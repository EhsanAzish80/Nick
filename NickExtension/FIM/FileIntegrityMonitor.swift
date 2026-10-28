// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import CryptoKit
import Foundation
import os

// MARK: - FileIntegrityMonitor

/// Monitors a set of security-critical paths for unauthorised changes.
///
/// **Lifecycle:**
/// 1. `buildBaseline()` — call once on first launch (or after an OS update).
///    Hashes every file in every monitored path and persists the results.
/// 2. `check(path:)` — call from the ES `NOTIFY_CLOSE` / `NOTIFY_WRITE` handler.
///    Returns an `IntegrityViolation` if the file's hash no longer matches
///    its baseline, or if the file is new / missing.
/// 3. `fullScan()` — triggered on-demand; walks all monitored paths.
///
/// Baselines are stored as JSON so they survive restarts.
/// All public methods are thread-safe — mutations are serialised via `NSLock`.
final class FileIntegrityMonitor {

    private struct BaselineStore: Codable {
        static let currentVersion = 2
        let version: Int
        let entries: [String: String]
    }

    // MARK: - Monitored Paths

    /// Default set of security-sensitive paths to track.
    static let systemMonitoredPaths: [String] = [
        "/Library/LaunchAgents",
        "/Library/LaunchDaemons",
        "/usr/lib/cron/tabs",
        "/usr/local/bin",
        "/private/etc/hosts",
        "/private/etc/sudoers",
        "/private/etc/pam.d",
        "/private/etc/sudoers.d",
        "/etc/zshrc",
        "/etc/zprofile",
        "/etc/zshenv",
        "/etc/bashrc",
        "/etc/profile",
    ]

    static func defaultMonitoredPaths(userHomeDirectories: [URL]) -> [String] {
        let userRelativePaths = [
            "Library/LaunchAgents",
            ".zshrc",
            ".zprofile",
            ".zshenv",
            ".bash_profile",
            ".bashrc",
            ".profile",
        ]
        return systemMonitoredPaths + userHomeDirectories.flatMap { home in
            userRelativePaths.map { home.appendingPathComponent($0).path }
        }
    }

    static func defaultDirectoryPaths(userHomeDirectories: [URL]) -> Set<String> {
        Set([
            "/Library/LaunchAgents",
            "/Library/LaunchDaemons",
            "/usr/lib/cron/tabs",
            "/usr/local/bin",
            "/private/etc/pam.d",
            "/private/etc/sudoers.d",
        ] + userHomeDirectories.map {
            $0.appendingPathComponent("Library/LaunchAgents", isDirectory: true).path
        })
    }

    // MARK: - Private

    private static let logger = Logger(
        subsystem: "com.ehsanazish.nick.NickExtension",
        category: "FIM"
    )

    /// path → SHA-256 hex digest
    private var baselines: [String: String] = [:]
    private var pendingViolations: [UUID: IntegrityViolation] = [:]
    private var recentViolationFingerprints: [String: Date] = [:]
    private static let eventCoalescingWindow: TimeInterval = 5

    private let baselinePath:   String
    private let pendingViolationsPath: String
    private let monitoredPaths: [String]
    private let monitoredDirectoryPaths: Set<String>
    private let lock = NSLock()

    var baselineCount: Int {
        lock.withLock { baselines.count }
    }

    // MARK: - Init

    init(
        baselinePath: String,
        pendingViolationsPath: String? = nil,
        monitoredPaths: [String]? = nil,
        userHomeDirectories: [URL] = UserHomeDirectoryResolver.humanHomeDirectories()
    ) {
        self.baselinePath = baselinePath
        self.pendingViolationsPath = pendingViolationsPath ?? baselinePath + ".pending"
        let configuredPaths = monitoredPaths
            ?? Self.defaultMonitoredPaths(userHomeDirectories: userHomeDirectories)
        let standardizedPaths = configuredPaths.map {
            URL(fileURLWithPath: $0).standardizedFileURL.path
        }
        let defaultDirectories = Self.defaultDirectoryPaths(userHomeDirectories: userHomeDirectories)
        let directoryFlags = standardizedPaths.map { path in
            defaultDirectories.contains(path) || Self.pathIsDirectory(path)
        }
        self.monitoredPaths = standardizedPaths.map {
            EndpointSecurityPath.canonical($0) ?? $0
        }
        self.monitoredDirectoryPaths = Set(zip(self.monitoredPaths, directoryFlags).compactMap {
            $0.1 ? $0.0 : nil
        })
        loadBaselines()
        loadPendingViolations()
    }

    // MARK: - Public API

    /// Hashes every file in every monitored path and persists the baselines.
    /// Call once on first launch; do not call on every restart (use saved data instead).
    @discardableResult
    func buildBaseline() -> Bool {
        guard lock.withLock({ pendingViolations.isEmpty }) else {
            Self.logger.warning("FIM baseline rebuild refused while violations await acknowledgement")
            return false
        }
        lock.lock()
        baselines.removeAll()
        lock.unlock()

        for path in monitoredPaths {
            let expanded = expand(path)
            if isDirectory(expanded) {
                baselineDirectory(expanded)
            } else if let hash = hashFile(expanded) {
                lock.lock()
                baselines[expanded] = hash
                lock.unlock()
            }
        }

        saveBaselines()
        Self.logger.info("FIM baseline built — \(self.baselines.count) file(s) tracked")
        return true
    }

    /// Checks a single path against the stored baseline.
    ///
    /// Called from the ES `NOTIFY_CLOSE` / `NOTIFY_WRITE` event handler
    /// for every file-write event. Non-monitored paths return `nil` quickly.
    ///
    /// When a violation is detected the baseline is updated so the same
    /// change is reported only once (not on every subsequent write).
    func check(path: String) -> IntegrityViolation? {
        let expanded = expand(path)
        guard isMonitored(expanded) else { return nil }

        lock.lock()
        let expected = baselines[expanded]
        lock.unlock()

        let actual = hashFile(expanded)

        if let expected {
            if actual == nil {
                // File deleted
                return recordPending(IntegrityViolation(
                    path: expanded, violationType: .deleted,
                    expectedHash: expected, actualHash: nil, timestamp: Date()
                ))
            } else if actual != expected {
                return recordPending(IntegrityViolation(
                    path: expanded, violationType: .modified,
                    expectedHash: expected, actualHash: actual, timestamp: Date()
                ))
            }
        } else if let actual {
            return recordPending(IntegrityViolation(
                path: expanded, violationType: .created,
                expectedHash: nil, actualHash: actual, timestamp: Date()
            ))
        }

        return nil
    }

    /// Persists event-time evidence for exact shell-profile files. Hash-only
    /// polling can miss a short-lived edit that is restored before the async
    /// worker reads it; an ES modified/write/rename event is itself durable
    /// evidence that the protected profile changed.
    func recordShellProfileEvent(
        path: String,
        violationType: IntegrityViolation.ViolationType = .modified,
        timestamp: Date = Date()
    ) -> IntegrityViolation? {
        let expanded = EndpointSecurityPath.canonical(expand(path)) ?? expand(path)
        let exact = isExactShellProfile(expanded)
        Self.logger.info(
            "recordShellProfileEvent path=\(expanded, privacy: .public) isExactShellProfile=\(exact)"
        )
        guard exact else { return nil }
        let expected = lock.withLock { baselines[expanded] }
        let violation = recordPending(IntegrityViolation(
            path: expanded,
            violationType: violationType,
            expectedHash: expected,
            actualHash: hashFile(expanded),
            timestamp: timestamp
        ))
        Self.logger.info(
            "recordShellProfileEvent persisted path=\(expanded, privacy: .public) inserted=\(violation != nil)"
        )
        return violation
    }

    func isExactShellProfile(_ path: String) -> Bool {
        let canonical = EndpointSecurityPath.canonical(expand(path)) ?? expand(path)
        return monitoredPaths.contains(canonical)
            && !monitoredDirectoryPaths.contains(canonical)
            && Self.shellProfileNames.contains(URL(fileURLWithPath: canonical).lastPathComponent.lowercased())
    }

    /// Exact target paths used by the dedicated inverted NOTIFY_WRITE client.
    /// Directory FIM remains driven by CLOSE/RENAME and is intentionally absent.
    var exactShellProfilePaths: [String] {
        monitoredPaths.filter { isExactShellProfile($0) }
    }

    func shouldCheck(_ path: String) -> Bool {
        isMonitored(expand(path))
    }

    /// Full integrity scan across all monitored paths.
    ///
    /// - Returns: All violations found. Empty array means clean.
    func fullScan() -> [IntegrityViolation] {
        var violations: [IntegrityViolation] = []

        // Check all baselined files
        lock.lock()
        let snapshot = baselines
        lock.unlock()

        for (path, _) in snapshot {
            if let v = check(path: path) { violations.append(v) }
        }

        // Scan directories for new (unbaselined) files
        for monPath in monitoredPaths {
            let expanded = expand(monPath)
            guard isDirectory(expanded),
                  let files = try? FileManager.default.contentsOfDirectory(atPath: expanded)
            else { continue }

            for file in files {
                let fullPath = (expanded as NSString).appendingPathComponent(file)
                lock.lock()
                let known = baselines[fullPath] != nil
                lock.unlock()

                guard !known, let hash = hashFile(fullPath) else { continue }
                if let violation = recordPending(IntegrityViolation(
                    path: fullPath, violationType: .created,
                    expectedHash: nil, actualHash: hash, timestamp: Date()
                )) { violations.append(violation) }
            }
        }

        Self.logger.info("FIM full scan complete — \(violations.count) violation(s)")
        return violations
    }

    var pendingViolationCount: Int {
        lock.withLock { pendingViolations.count }
    }

    func pendingViolationSnapshot() -> [IntegrityViolation] {
        lock.withLock { Array(pendingViolations.values) }
    }

    /// Accepts the current state only after the authenticated app explicitly
    /// acknowledges the exact pending violation.
    func acknowledgeViolation(id: UUID) -> Bool {
        guard let violation = lock.withLock({ pendingViolations[id] }) else { return false }
        let currentHash = hashFile(violation.path)
        guard FIMAcknowledgementPolicy.canAcknowledge(violation, currentHash: currentHash) else {
            return false
        }
        lock.withLock {
            switch violation.violationType {
            case .deleted:
                baselines.removeValue(forKey: violation.path)
            case .created, .modified:
                if let currentHash {
                    baselines[violation.path] = currentHash
                }
            }
            pendingViolations.removeValue(forKey: id)
        }
        saveBaselines()
        savePendingViolations()
        return true
    }

    // MARK: - Private Helpers

    private func isMonitored(_ path: String) -> Bool {
        FileIntegrityPathPolicy.isMonitored(
            path,
            configuredPaths: monitoredPaths.map(expand),
            directoryPaths: Set(monitoredDirectoryPaths.map(expand))
        )
    }

    private static let shellProfileNames: Set<String> = [
        ".zshrc", ".zprofile", ".zshenv", ".bash_profile", ".bashrc", ".profile",
        "zshrc", "zprofile", "zshenv", "bashrc", "profile",
    ]

    private func baselineDirectory(_ dirPath: String) {
        guard let files = try? FileManager.default.contentsOfDirectory(atPath: dirPath) else { return }
        for file in files {
            let full = (dirPath as NSString).appendingPathComponent(file)
            if let hash = hashFile(full) {
                lock.lock(); baselines[full] = hash; lock.unlock()
            }
        }
    }

    private func hashFile(_ path: String) -> String? {
        guard let data = FileManager.default.contents(atPath: path), !data.isEmpty else { return nil }
        return SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    private func isDirectory(_ path: String) -> Bool {
        Self.pathIsDirectory(path)
    }

    private static func pathIsDirectory(_ path: String) -> Bool {
        var isDir: ObjCBool = false
        return FileManager.default.fileExists(atPath: path, isDirectory: &isDir) && isDir.boolValue
    }

    private func expand(_ path: String) -> String {
        (path as NSString).expandingTildeInPath
    }

    private func saveBaselines() {
        lock.lock()
        let copy = baselines
        lock.unlock()
        let store = BaselineStore(version: BaselineStore.currentVersion, entries: copy)
        guard let data = try? JSONEncoder().encode(store) else { return }
        do {
            try data.write(to: URL(fileURLWithPath: baselinePath), options: .atomic)
            try FileManager.default.setAttributes(
                [.posixPermissions: 0o600],
                ofItemAtPath: baselinePath
            )
        } catch {
            Self.logger.error("Could not persist FIM baseline: \(error.localizedDescription, privacy: .public)")
        }
    }

    private func recordPending(_ violation: IntegrityViolation) -> IntegrityViolation? {
        let fingerprint = [
            violation.path,
            violation.violationType.rawValue,
            violation.actualHash ?? "missing",
        ].joined(separator: "|")
        let inserted = lock.withLock { () -> Bool in
            let now = violation.timestamp
            recentViolationFingerprints = recentViolationFingerprints.filter {
                now.timeIntervalSince($0.value) <= Self.eventCoalescingWindow
            }
            if let previous = recentViolationFingerprints[fingerprint],
               now.timeIntervalSince(previous) <= Self.eventCoalescingWindow {
                return false
            }
            recentViolationFingerprints[fingerprint] = now
            pendingViolations[violation.id] = violation
            return true
        }
        if inserted { savePendingViolations() }
        return inserted ? violation : nil
    }

    private func savePendingViolations() {
        let copy = lock.withLock { Array(pendingViolations.values) }
        guard let data = try? JSONEncoder().encode(copy) else { return }
        do {
            try data.write(to: URL(fileURLWithPath: pendingViolationsPath), options: .atomic)
            try FileManager.default.setAttributes(
                [.posixPermissions: 0o600],
                ofItemAtPath: pendingViolationsPath
            )
        } catch {
            Self.logger.error("Could not persist pending FIM evidence: \(error.localizedDescription, privacy: .public)")
        }
    }

    private func loadPendingViolations() {
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: pendingViolationsPath)),
              let loaded = try? JSONDecoder().decode([IntegrityViolation].self, from: data) else { return }
        lock.withLock {
            pendingViolations = Dictionary(uniqueKeysWithValues: loaded.map { ($0.id, $0) })
        }
    }

    private func loadBaselines() {
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: baselinePath)) else { return }

        if let store = try? JSONDecoder().decode(BaselineStore.self, from: data),
           store.version == BaselineStore.currentVersion {
            var loaded = store.entries.filter { isMonitored($0.key) }
            seedMissingConfiguredPaths(into: &loaded)
            lock.withLock { baselines = loaded }
            if loaded != store.entries { saveBaselines() }
            Self.logger.info("FIM baselines loaded — \(loaded.count) file(s)")
            return
        }

        guard let legacy = try? JSONDecoder().decode([String: String].self, from: data) else { return }
        var migrated = legacy
        let aliases = [
            "/etc/hosts": "/private/etc/hosts",
            "/etc/sudoers": "/private/etc/sudoers",
        ]
        for (oldPath, canonicalPath) in aliases {
            if migrated[canonicalPath] == nil, let oldHash = migrated[oldPath] {
                migrated[canonicalPath] = oldHash
            }
        }
        migrated = migrated.filter { isMonitored($0.key) }

        seedMissingConfiguredPaths(into: &migrated)

        lock.withLock { baselines = migrated }
        saveBaselines()
        Self.logger.info("FIM baseline migrated — \(migrated.count) file(s)")
    }

    /// Quietly seeds newly configured paths on every load. This keeps a future
    /// monitored-path addition from being reported as a newly created file on
    /// the first edit after an update.
    private func seedMissingConfiguredPaths(into entries: inout [String: String]) {
        for configuredPath in monitoredPaths {
            if monitoredDirectoryPaths.contains(configuredPath) {
                let hasCoverage = entries.keys.contains {
                    $0 == configuredPath || $0.hasPrefix(configuredPath + "/")
                }
                if !hasCoverage {
                    entries.merge(baselineEntries(in: configuredPath)) { existing, _ in existing }
                }
            } else if entries[configuredPath] == nil,
                      let hash = hashFile(configuredPath) {
                entries[configuredPath] = hash
            }
        }
    }

    private func baselineEntries(in directory: String) -> [String: String] {
        guard let files = try? FileManager.default.contentsOfDirectory(atPath: directory) else {
            return [:]
        }
        return files.reduce(into: [:]) { result, file in
            let fullPath = (directory as NSString).appendingPathComponent(file)
            if let hash = hashFile(fullPath) { result[fullPath] = hash }
        }
    }
}
