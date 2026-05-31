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

    // MARK: - Monitored Paths

    /// Default set of security-sensitive paths to track.
    static let defaultMonitoredPaths: [String] = [
        "/Library/LaunchAgents",
        "/Library/LaunchDaemons",
        "/usr/local/bin",
        "/etc/hosts",
        "/etc/sudoers",
        "/private/etc/pam.d",
        "/private/etc/sudoers",
        "~/Library/LaunchAgents",
    ]

    // MARK: - Private

    private static let logger = Logger(
        subsystem: "com.ehsanazish.nick.NickExtension",
        category: "FIM"
    )

    /// path → SHA-256 hex digest
    private var baselines: [String: String] = [:]

    private let baselinePath:   String
    private let monitoredPaths: [String]
    private let lock = NSLock()

    // MARK: - Init

    init(baselinePath: String, monitoredPaths: [String]? = nil) {
        self.baselinePath   = baselinePath
        self.monitoredPaths = monitoredPaths ?? Self.defaultMonitoredPaths
        loadBaselines()
    }

    // MARK: - Public API

    /// Hashes every file in every monitored path and persists the baselines.
    /// Call once on first launch; do not call on every restart (use saved data instead).
    func buildBaseline() {
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
                return IntegrityViolation(
                    path: expanded, violationType: .deleted,
                    expectedHash: expected, actualHash: nil, timestamp: Date()
                )
            } else if actual != expected {
                // File modified — update baseline so we don't re-report
                lock.lock(); baselines[expanded] = actual; lock.unlock()
                saveBaselines()
                return IntegrityViolation(
                    path: expanded, violationType: .modified,
                    expectedHash: expected, actualHash: actual, timestamp: Date()
                )
            }
        } else if let actual {
            // New file in a monitored directory — add to baseline
            lock.lock(); baselines[expanded] = actual; lock.unlock()
            saveBaselines()
            return IntegrityViolation(
                path: expanded, violationType: .created,
                expectedHash: nil, actualHash: actual, timestamp: Date()
            )
        }

        return nil
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
                lock.lock(); baselines[fullPath] = hash; lock.unlock()
                violations.append(IntegrityViolation(
                    path: fullPath, violationType: .created,
                    expectedHash: nil, actualHash: hash, timestamp: Date()
                ))
            }
        }

        if !violations.isEmpty { saveBaselines() }

        Self.logger.info("FIM full scan complete — \(violations.count) violation(s)")
        return violations
    }

    // MARK: - Private Helpers

    private func isMonitored(_ path: String) -> Bool {
        monitoredPaths.contains { path.hasPrefix(expand($0)) }
    }

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
        guard let data = try? JSONEncoder().encode(copy) else { return }
        try? data.write(to: URL(fileURLWithPath: baselinePath), options: .atomic)
    }

    private func loadBaselines() {
        guard let data   = try? Data(contentsOf: URL(fileURLWithPath: baselinePath)),
              let loaded = try? JSONDecoder().decode([String: String].self, from: data)
        else { return }
        lock.lock(); baselines = loaded; lock.unlock()
        Self.logger.info("FIM baselines loaded — \(loaded.count) file(s)")
    }
}
