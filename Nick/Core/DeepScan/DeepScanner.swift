// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation
import IOKit.ps
import Observation
import os

// MARK: - DeepScanner

/// Drives a full-system YARA + heuristic scan across standard executable locations.
///
/// All progress properties are `@MainActor`-isolated so `DeepScanView` can bind
/// to them directly. File enumeration and per-file scanning are dispatched off the
/// main actor; `@MainActor` is only held long enough to update state between files.
@Observable
@MainActor
final class DeepScanner {

    private nonisolated static let skippedExtensions: Set<String> = [
        "jpg", "jpeg", "png", "gif", "webp", "heic", "heif",
        "mp3", "mp4", "mov", "avi", "mkv", "wav", "flac", "aac",
        "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx",
        "zip", "tar", "gz", "dmg", "iso",
        "ttf", "otf", "woff", "woff2",
        "css", "svg", "json", "xml", "plist",
    ]

    private nonisolated static let scriptExtensions: Set<String> = [
        "sh", "py", "rb", "pl", "swift", "command", "tool",
    ]

    // MARK: - Progress State

    var progress:           Double       = 0.0
    var totalFiles:         Int          = 0
    var scannedFiles:       Int          = 0
    var currentFile:        String       = ""
    var elapsedTime:        TimeInterval = 0
    var estimatedRemaining: TimeInterval = 0
    var threatsFound:       Int          = 0
    var isScanning:         Bool         = false
    var isPaused:           Bool         = false
    var isCancelling:       Bool         = false
    var hasCompletedScan:   Bool         = false
    var results:            [YARAMatch]  = []
    var resultVerdicts:     [String: ThreatVerdict] = [:]

    // MARK: - Private

    private var scanTask: Task<Void, Never>?
    private var activeScanID: UUID?
    private var storedOnlyOnPower = false
    private var ignoredPaths: Set<String> = []
    /// Weak reference to the engine used to ingest YARA signals during a deep scan.
    /// Set by the caller (e.g. `ScannerDetailView`) before calling `start()`.
    weak var engine: SecurityEngine?

    private static let log = Logger(
        subsystem: "com.ehsanazish.nick",
        category: "DeepScanner"
    )

    // MARK: - Public API

    /// Starts the deep scan.
    ///
    /// - Parameters:
    ///   - onlyOnPower: Pause automatically when running on battery; resume on AC.
    ///   - scanFile: Async closure invoked for each file path. Errors are swallowed
    ///               per file — the overall scan always continues.
    func start(
        onlyOnPower: Bool,
        ignoredPaths: Set<String> = [],
        candidateFiles: [String]? = nil,
        scanFile: @escaping @Sendable (String) async throws -> [YARAMatch]
    ) {
        guard !isScanning, !isPaused, scanTask == nil else { return }
        let scanID = UUID()
        storedOnlyOnPower = onlyOnPower
        self.ignoredPaths = Set(ignoredPaths.map(Self.canonicalPath))
        activeScanID = scanID
        isScanning = true
        isCancelling = false
        hasCompletedScan = false
        scanTask = Task { [weak self] in
            await self?.performDeepScan(
                scanID: scanID,
                candidateFiles: candidateFiles,
                scanFile: scanFile
            )
        }
    }

    /// Requests cooperative cancellation. The scanner remains busy until the
    /// in-flight file operation returns, preventing a second overlapping scan.
    func cancel() {
        guard scanTask != nil else { return }
        isCancelling = true
        scanTask?.cancel()
    }

    /// Clears the last completed result set without replacing the scanner.
    /// The shared scanner is owned by `SecurityEngine`, so its identity must remain
    /// stable while users navigate between sidebar sections.
    func resetResults() {
        guard !isScanning, !isPaused else { return }
        progress = 0
        totalFiles = 0
        scannedFiles = 0
        currentFile = ""
        elapsedTime = 0
        estimatedRemaining = 0
        threatsFound = 0
        results = []
        resultVerdicts = [:]
        hasCompletedScan = false
    }

    // MARK: - Private Implementation

    private func performDeepScan(
        scanID: UUID,
        candidateFiles: [String]?,
        scanFile: @escaping @Sendable (String) async throws -> [YARAMatch]
    ) async {
        let startTime = Date()
        results       = []
        resultVerdicts = [:]
        threatsFound  = 0
        currentFile   = "Indexing files…"

        // Phase 1: enumerate executables on a background thread so the UI stays live.
        let files: [String]
        if let candidateFiles {
            files = Self.canonicalUniquePaths(candidateFiles)
        } else {
            files = await Task.detached(priority: .utility) {
                DeepScanner.enumerateExecutables()
            }.value
        }

        guard !Task.isCancelled else { return finishCancelledScan(scanID: scanID) }

        totalFiles = files.count
        Self.log.info("DeepScanner: \(files.count) files to scan")

        // Phase 2: scan each file, updating progress after each one.
        for (index, file) in files.enumerated() {
            guard !Task.isCancelled else { break }

            // Battery gate — pause if on battery and the user requested power-only.
            if storedOnlyOnPower && !Self.isOnPower() {
                isPaused = true
                while !Self.isOnPower() {
                    guard !Task.isCancelled else { break }
                    try? await Task.sleep(nanoseconds: 5_000_000_000)
                }
                isPaused = false
                guard !Task.isCancelled else { break }
            }

            // Show the file currently being inspected. Completed-file progress is
            // updated only after this operation returns.
            currentFile  = file

            // Per-file scan — YARAEngine.scanFile dispatches to a background thread
            // internally, so this await releases the main actor for the scan work.
            do {
                let matches = try await scanFile(file)
                guard !Task.isCancelled else { return finishCancelledScan(scanID: scanID) }
                if !matches.isEmpty {
                    let uniqueMatches = Self.uniqueMatches(matches)
                    results.append(contentsOf: uniqueMatches)
                    let classified = await Task.detached(priority: .utility) {
                        uniqueMatches.map { match in
                            (match, DeepScanner.classify(match: match))
                        }
                    }.value
                    guard !Task.isCancelled else { return finishCancelledScan(scanID: scanID) }
                    for (match, verdict) in classified {
                        resultVerdicts[Self.matchKey(for: match)] = verdict
                    }
                    let actionableMatches = classified.compactMap { pair -> YARAMatch? in
                        let (match, verdict) = pair
                        guard verdict == .threat || verdict == .suspicious else { return nil }
                        if self.ignoredPaths.contains(Self.canonicalPath(match.filePath)),
                           Self.canIgnore(match: match) {
                            return nil
                        }
                        return match
                    }
                    threatsFound += actionableMatches.count
                    // Ingest only actionable YARA matches (.threat / .suspicious) into the
                    // correlator. Safe verdicts (.applicationData, .developmentArtifact,
                    // .likelySafe) still appear in the Deep Scan results view for transparency
                    // but do not create alerts or fire notifications.
                    if let eng = engine {
                        var signals: [ThreatSignal] = []
                        for match in actionableMatches {
                            let severity = Self.signalSeverity(for: match)
                            signals.append(ThreatSignal(
                                source: .yara,
                                severity: severity,
                                title: "YARA match: \(match.ruleName)",
                                description: "\(match.metadata["description"] ?? match.ruleName) at \(match.filePath)",
                                context: ThreatSignalContext(
                                    fileInfo: FileInfo(
                                        path: match.filePath,
                                        sha256Hash: nil,
                                        entropy: nil,
                                        signingStatus: nil,
                                        sizeBytes: nil
                                    ),
                                    metadata: [
                                        "path": match.filePath,
                                        "rule": match.ruleName,
                                        "suppressible": Self.canIgnore(match: match) ? "true" : "false",
                                    ]
                                )
                            ))
                        }
                        if !signals.isEmpty {
                            await eng.correlator.ingest(signals)
                            let alerts = await eng.correlator.correlateNew()
                            for alert in alerts {
                                eng.addAlert(alert)
                                await NotificationManager.shared.send(for: alert)
                            }
                        }
                    }
                }
            } catch {
                // Skip unreadable, timed-out, or otherwise failing files silently.
            }

            guard !Task.isCancelled else { return finishCancelledScan(scanID: scanID) }
            let completed = index + 1
            let elapsed = Date().timeIntervalSince(startTime)
            scannedFiles = completed
            progress = files.isEmpty ? 0 : Double(completed) / Double(files.count)
            elapsedTime = elapsed
            if completed > 0 {
                let average = elapsed / Double(completed)
                estimatedRemaining = average * Double(files.count - completed)
            }

            // Yield cooperatively every 10 files to keep the main actor responsive.
            if index % 10 == 0 { await Task.yield() }
        }

        guard !Task.isCancelled else { return finishCancelledScan(scanID: scanID) }

        // Finalise only a scan that genuinely reached the end.
        progress     = 1.0
        scannedFiles = totalFiles
        isScanning   = false
        isPaused     = false
        isCancelling = false
        hasCompletedScan = true
        elapsedTime  = Date().timeIntervalSince(startTime)
        if activeScanID == scanID {
            scanTask = nil
            activeScanID = nil
        }
        engine?.recordDeepScan(fileCount: totalFiles)
        Self.log.info("DeepScanner: complete — \(self.threatsFound) actionable finding(s)")
    }

    private func finishCancelledScan(scanID: UUID) {
        guard activeScanID == scanID else { return }
        isScanning = false
        isPaused = false
        isCancelling = false
        hasCompletedScan = false
        scanTask = nil
        activeScanID = nil
    }

    // MARK: - File Enumeration

    /// Enumerates executables and scripts from the standard macOS scan paths.
    ///
    /// Media, document, archive, and font files are skipped to keep scan times
    /// reasonable. Marked `nonisolated` so it can run inside `Task.detached`.
    nonisolated private static func enumerateExecutables() -> [String] {
        var files: [String] = []
        let fm  = FileManager.default
        let log = Logger(subsystem: "com.ehsanazish.nick", category: "DeepScanner")

        let scanPaths: [String] = [
            "/Applications",
            "/usr/local/bin",
            "/usr/local/sbin",
            "/opt/homebrew/bin",
            "/opt/homebrew/sbin",
            "/Library/LaunchDaemons",
            "/Library/LaunchAgents",
            "/Library/Application Support",
            "/Library/Extensions",
            "/Library/PrivilegedHelperTools",
            NSHomeDirectory() + "/Library/LaunchAgents",
            NSHomeDirectory() + "/Library/Application Support",
            NSHomeDirectory() + "/Downloads",
            NSHomeDirectory() + "/Desktop",
            NSHomeDirectory() + "/Applications",
            "/tmp",
            "/var/tmp",
            "/private/tmp"
        ]

        for scanPath in scanPaths {
            guard fm.isReadableFile(atPath: scanPath) else {
                log.warning("DeepScan: no access to \(scanPath, privacy: .public)")
                continue
            }
            guard let enumerator = fm.enumerator(
                at: URL(fileURLWithPath: scanPath),
                includingPropertiesForKeys: [.isExecutableKey, .isRegularFileKey],
                // Descend into application bundles so their actual Mach-O binaries
                // are scanned; the bundle directory itself is not executable data.
                options: [.skipsHiddenFiles]
            ) else {
                log.warning("DeepScan: cannot enumerate \(scanPath, privacy: .public)")
                continue
            }

            var count = 0
            for case let url as URL in enumerator {
                guard let res = try? url.resourceValues(
                    forKeys: [.isExecutableKey, .isRegularFileKey]
                ), res.isRegularFile == true else { continue }
                if shouldScanFile(
                    path: url.path,
                    scanRoot: scanPath,
                    isExecutable: res.isExecutable == true
                ) {
                    files.append(url.path)
                    count += 1
                }
            }
            log.info("DeepScan: \(count) files from \(scanPath, privacy: .public)")
        }

        return canonicalUniquePaths(files)
    }

    /// Centralizes enumeration policy so launch-item property lists cannot be
    /// accidentally excluded when the general data-file skip list changes.
    nonisolated static func shouldScanFile(
        path: String,
        scanRoot: String,
        isExecutable: Bool
    ) -> Bool {
        let ext = URL(fileURLWithPath: path).pathExtension.lowercased()
        let isLaunchPropertyList = ext == "plist"
            && (scanRoot.hasSuffix("LaunchDaemons") || scanRoot.hasSuffix("LaunchAgents"))
        guard !skippedExtensions.contains(ext) || isLaunchPropertyList else { return false }
        return isExecutable || scriptExtensions.contains(ext) || isLaunchPropertyList || ext.isEmpty
    }

    // MARK: - Power Source

    // MARK: - Verdict Classification

    /// Classifies a YARA match using rule confidence, verified context, and code
    /// signing. Attacker-controlled directory names never downgrade concrete rules.
    nonisolated static func classify(
        match: YARAMatch,
        cellarRoots: [String] = ["/opt/homebrew/Cellar", "/usr/local/Cellar"]
    ) -> ThreatVerdict {
        let path = match.filePath.lowercased()

        // Concrete malware-family signatures remain actionable in every location.
        // A dropper controls its path, so location cannot override this evidence.
        if !behavioralRules.contains(match.ruleName) { return .threat }

        // Broad behavior rules intentionally match short command/API fragments. In a
        // source checkout, test fixture, package-manager cache, or documentation corpus,
        // those strings are evidence about source text rather than executed behavior.
        // Keep them in the completed report, but do not turn them into active threats.
        if isVerifiedDevelopmentContext(path) {
            return .developmentArtifact
        }

        // Homebrew wrapper scripts are unsigned by design. Only downgrade a broad
        // behavior rule when the resolved file belongs to a real Cellar keg with a
        // Homebrew receipt. A lookalike Downloads/Cellar path does not qualify, and
        // concrete signatures were already kept actionable above.
        if isVerifiedHomebrewArtifact(match.filePath, cellarRoots: cellarRoots) {
            return .likelySafe
        }

        // Behavior rules match source-code fragments as well as executable behavior.
        // Those fragments are common inside Chromium's opaque Service Worker cache,
        // where an entry is application runtime data rather than a user-openable file.
        // Keep the match in the report for transparency, but do not raise an active
        // alert. This deliberately excludes concrete malware-family signatures.
        let contextualCacheRules: Set<String> = [
            "nick_email_html_smuggling",
            "nick_email_office_macro_dropper",
            "macos_ptrace_antidebug",
            "macos_launch_constraints_bypass",
        ]
        if contextualCacheRules.contains(match.ruleName),
           isOpaqueApplicationCache(path) {
            return .applicationData
        }

        // Chrome extension packages are opaque updater data. A behavior string in a
        // cached CRX is useful forensic evidence but is not proof that the updater or
        // extension executed that behavior.
        if ["macos_ptrace_antidebug", "macos_launch_constraints_bypass"].contains(match.ruleName),
           path.contains("/google/googleupdater/crx_cache/") {
            return .applicationData
        }

        // Category B: Application runtime data — only trust if the parent .app is signed.
        // An attacker cannot gain trusted status by placing files under a path named after
        // a known application without the corresponding signed bundle.
        if isInsideSignedAppData(path: match.filePath) { return .applicationData }

        let signing = SignatureValidator.shared.evaluate(binaryPath: match.filePath)
        if case .signed = signing { return .likelySafe }

        return .suspicious
    }

    /// Maps YARA metadata to signal severity. Missing metadata defaults to Medium;
    /// bundled rules are separately validated to require an explicit value.
    nonisolated static func signalSeverity(for match: YARAMatch) -> SignalSeverity {
        switch match.metadata["severity"]?.trimmingCharacters(in: .whitespacesAndNewlines).uppercased() {
        case "INFO": return .info
        case "LOW": return .low
        case "MEDIUM": return .medium
        case "HIGH": return .high
        case "CRITICAL": return .critical
        default:
            return match.tags.contains(where: { $0.caseInsensitiveCompare("critical") == .orderedSame })
                ? .critical : .medium
        }
    }

    nonisolated static func matchKey(for match: YARAMatch) -> String {
        "\(match.ruleName)\u{0}\(canonicalPath(match.filePath))"
    }

    /// User ignores are available only for broad, non-critical behavioral matches.
    /// Concrete signatures remain visible and actionable on every scan.
    nonisolated static func canIgnore(match: YARAMatch) -> Bool {
        behavioralRules.contains(match.ruleName) && signalSeverity(for: match) < .critical
    }

    /// Removes duplicate rule/path pairs, which can otherwise occur when YARA returns
    /// duplicate callbacks or scan roots resolve to the same macOS volume location.
    nonisolated static func uniqueMatches(_ matches: [YARAMatch]) -> [YARAMatch] {
        var seen = Set<String>()
        return matches.filter { match in
            let path = canonicalPath(match.filePath)
            return seen.insert("\(match.ruleName)\u{0}\(path)").inserted
        }
    }

    /// Canonicalizes and de-duplicates scan candidates (notably `/tmp` and
    /// `/private/tmp`) while preserving deterministic discovery order.
    nonisolated static func canonicalUniquePaths(_ paths: [String]) -> [String] {
        var seen = Set<String>()
        var result: [String] = []
        for path in paths {
            let canonical = canonicalPath(path)
            if seen.insert(canonical).inserted { result.append(canonical) }
        }
        return result
    }

    /// `resolvingSymlinksInPath()` does not reliably resolve `/tmp`, `/var`, or
    /// `/etc` when the final path component does not exist yet. Normalize the
    /// standard macOS aliases explicitly so overlapping roots and YARA callbacks
    /// cannot produce duplicate findings.
    nonisolated static func canonicalPath(_ path: String) -> String {
        let resolved = URL(fileURLWithPath: path)
            .resolvingSymlinksInPath().standardizedFileURL.path
        for alias in ["/tmp", "/var", "/etc"] where resolved == alias || resolved.hasPrefix(alias + "/") {
            return "/private" + resolved
        }
        return resolved
    }

    private nonisolated static let behavioralRules: Set<String> = [
        "macos_backup_deletion", "macos_browser_credential_theft",
        "macos_browser_extension_inject", "macos_dns_hijack",
        "macos_dylib_injection", "macos_icloud_token_theft",
        "macos_keychain_access", "macos_launch_constraints_bypass",
        "macos_launchagent_install", "macos_mass_file_rename",
        "macos_network_proxy_intercept", "macos_ptrace_antidebug",
        "macos_ransom_note", "macos_reverse_shell", "macos_screenshot_capture",
        "macos_shadow_copy_delete", "nick_email_applescript_dropper",
        "nick_email_html_smuggling", "nick_email_office_macro_dropper",
        "nick_email_powershell_encoded_dropper", "nick_email_shell_dropper",
    ]

    nonisolated static func isVerifiedDevelopmentContext(_ path: String) -> Bool {
        let fm = FileManager.default
        var candidate = URL(fileURLWithPath: path).deletingLastPathComponent()
        for _ in 0..<12 {
            let markers = [".git", "Package.swift", ".swiftpm", "project.pbxproj"]
            if markers.contains(where: {
                fm.fileExists(atPath: candidate.appendingPathComponent($0).path)
            }) {
                return true
            }
            let parent = candidate.deletingLastPathComponent()
            if parent.path == candidate.path { break }
            candidate = parent
        }
        return false
    }

    nonisolated static func isVerifiedHomebrewArtifact(
        _ path: String,
        cellarRoots: [String] = ["/opt/homebrew/Cellar", "/usr/local/Cellar"]
    ) -> Bool {
        let fm = FileManager.default
        let resolved = canonicalPath(path)
        for rawRoot in cellarRoots {
            let root = canonicalPath(rawRoot)
            guard resolved.hasPrefix(root + "/") else { continue }
            let relative = resolved.dropFirst(root.count + 1)
            let components = relative.split(separator: "/")
            guard components.count >= 3 else { continue }
            let keg = URL(fileURLWithPath: root, isDirectory: true)
                .appendingPathComponent(String(components[0]), isDirectory: true)
                .appendingPathComponent(String(components[1]), isDirectory: true)
            if fm.fileExists(atPath: keg.appendingPathComponent("INSTALL_RECEIPT.json").path) {
                return true
            }
            let formulaReceipt = keg.appendingPathComponent(".brew", isDirectory: true)
                .appendingPathComponent("\(components[0]).rb").path
            if fm.fileExists(atPath: formulaReceipt) { return true }
        }
        return false
    }

    nonisolated private static func isOpaqueApplicationCache(_ path: String) -> Bool {
        let markers = [
            "/service worker/cachestorage/", "/service worker/scriptcache/",
            "/code cache/", "/gpucache/", "/google/googleupdater/crx_cache/",
        ]
        return markers.contains(where: path.contains)
    }

    /// Returns true only for an exact conventional container relationship to an
    /// installed signed app. Similarly named Application Support and cache folders
    /// are user-writable and deliberately do not establish ownership.
    nonisolated static func isInsideSignedAppData(path: String) -> Bool {
        let identifierMarkers = ["/Group Containers/", "/Containers/"]
        for marker in identifierMarkers {
            guard let range = path.range(of: marker, options: .caseInsensitive) else { continue }
            let containerID = path[range.upperBound...]
                .split(separator: "/").first.map(String.init)?.lowercased() ?? ""
            guard !containerID.isEmpty else { continue }
            for appURL in installedApplicationURLs() {
                guard let bundleID = Bundle(url: appURL)?.bundleIdentifier?.lowercased(),
                      containerIdentifier(containerID, matchesBundleIdentifier: bundleID),
                      signedAppExists(atPath: appURL.path) else { continue }
                return true
            }
        }

        return false
    }

    nonisolated static func containerIdentifier(
        _ containerID: String,
        matchesBundleIdentifier bundleID: String
    ) -> Bool {
        let container = containerID.lowercased()
        let bundle = bundleID.lowercased()
        guard !container.isEmpty, !bundle.isEmpty else { return false }
        return container == bundle
            || container == "\(bundle).data"
            || container == "group.\(bundle).shared"
    }

    nonisolated private static func signedAppExists(atPath path: String) -> Bool {
        guard FileManager.default.fileExists(atPath: path) else { return false }
        if case .signed = SignatureValidator.shared.evaluate(binaryPath: path) { return true }
        return false
    }

    nonisolated private static func installedApplicationURLs() -> [URL] {
        let roots = [
            URL(fileURLWithPath: "/Applications", isDirectory: true),
            URL(fileURLWithPath: "/System/Applications", isDirectory: true),
            URL(fileURLWithPath: NSHomeDirectory() + "/Applications", isDirectory: true),
        ]
        let fm = FileManager.default
        return roots.flatMap { root in
            (try? fm.contentsOfDirectory(
                at: root,
                includingPropertiesForKeys: nil,
                options: [.skipsHiddenFiles]
            ))?.filter { $0.pathExtension.caseInsensitiveCompare("app") == .orderedSame } ?? []
        }
    }

    /// Returns the canonical app bundle paths to search for a given app name.
    nonisolated static func appBundleSearchDirectories(for appName: String) -> [String] {
        [
            "/Applications/\(appName).app",
            "/Applications/\(appName) Desktop.app",
            "/System/Applications/\(appName).app",
            NSHomeDirectory() + "/Applications/\(appName).app",
        ]
    }

    // MARK: - Power Source

    /// Returns `true` when the Mac is on AC power (or has no battery, e.g. Mac mini).
    nonisolated static func isOnPower() -> Bool {
        guard let snapshot = IOPSCopyPowerSourcesInfo()?.takeRetainedValue() else { return true }
        guard let sources = IOPSCopyPowerSourcesList(snapshot)?.takeRetainedValue() as? [CFTypeRef],
              let first = sources.first else {
            return true  // No battery — desktop Mac, treat as on power.
        }
        guard let desc = IOPSGetPowerSourceDescription(snapshot, first)?
                .takeUnretainedValue() as? [String: Any],
              let state = desc[kIOPSPowerSourceStateKey] as? String else {
            return true
        }
        return state == kIOPSACPowerValue
    }
}
