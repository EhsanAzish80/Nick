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
        "sh", "py", "rb", "pl", "swift", "command", "tool", "scpt", "applescript",
    ]

    /// Directory names whose contents are never executable payloads and are
    /// expensive to walk (packed VCS objects).
    private nonisolated static let prunedDirectoryNames: Set<String> = [".git", ".svn", ".hg"]

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
    /// `true` while locations are still being walked. Scanning runs at the
    /// same time, so `totalFiles` is only final once this turns `false`.
    var isIndexing:         Bool         = false
    /// Candidate files found so far (grows while `isIndexing`).
    var discoveredFiles:    Int          = 0
    /// The location currently being walked, for progress text.
    var indexingLocation:   String       = ""

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
        progress = 0
        totalFiles = 0
        scannedFiles = 0
        discoveredFiles = 0
        indexingLocation = ""
        isIndexing = true
        currentFile = "Indexing files…"
        elapsedTime = 0
        estimatedRemaining = 0
        threatsFound = 0
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

        // Phase 1 and 2 overlap. Walking /Applications and both Application
        // Support folders takes minutes on a full Mac; waiting for the whole
        // walk before scanning left the UI on "Indexing files…" and then the
        // scan itself finished in seconds. Candidates now stream to the
        // workers as they are found.
        let queue = CandidateQueue()
        let enumeration: Task<Void, Never>
        if let candidateFiles {
            for path in Self.canonicalUniquePaths(candidateFiles) {
                queue.push(Candidate(path: path, needsContentCheck: false))
            }
            queue.finish()
            enumeration = Task {}
        } else {
            enumeration = Task.detached(priority: .utility) {
                DeepScanner.enumerateCandidates(into: queue)
            }
        }

        // Classification (signature checks, path context) and content
        // sniffing run in the workers; the main actor only merges results and
        // publishes progress, at most a few times per second.
        let workerCount = Self.workerCount()
        var completed = 0
        var lastPublish = Date.distantPast

        await withTaskGroup(of: FileOutcome.self) { group in
            var inFlight = 0
            var exhausted = false

            while true {
                // Keep every worker busy while candidates are available.
                fill: while !exhausted, inFlight < workerCount, !Task.isCancelled {
                    switch queue.pop() {
                    case .item(let candidate):
                        group.addTask { await Self.scan(candidate, with: scanFile) }
                        inFlight += 1
                    case .finished:
                        exhausted = true
                    case .empty:
                        break fill
                    }
                }

                if Task.isCancelled {
                    group.cancelAll()
                    enumeration.cancel()
                }
                if inFlight == 0 {
                    if exhausted || Task.isCancelled { break }
                    // Only the walker is running: report what it has found.
                    publishProgress(queue: queue, completed: completed, startTime: startTime)
                    try? await Task.sleep(for: .milliseconds(50))
                    continue
                }

                guard let outcome = await group.next() else { break }
                inFlight -= 1
                guard !Task.isCancelled else { continue }
                completed += 1
                await merge(outcome)

                let now = Date()
                if now.timeIntervalSince(lastPublish) >= 0.2 {
                    lastPublish = now
                    currentFile = outcome.path
                    publishProgress(queue: queue, completed: completed, startTime: startTime)
                    // A busy task group can keep returning already-completed work
                    // without suspending. Yield so SwiftUI renders this update.
                    await Task.yield()
                }

                // Battery gate — hold new work while on battery if requested.
                if storedOnlyOnPower && !Self.isOnPower() {
                    isPaused = true
                    while !Self.isOnPower(), !Task.isCancelled {
                        try? await Task.sleep(nanoseconds: 5_000_000_000)
                    }
                    isPaused = false
                }
            }
        }
        enumeration.cancel()
        isIndexing = false

        guard !Task.isCancelled else { return finishCancelledScan(scanID: scanID) }

        totalFiles = queue.snapshot().discovered
        Self.log.info("DeepScanner: \(self.totalFiles) files scanned")

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

    /// Result of scanning and classifying one file in a worker task.
    private struct FileOutcome: Sendable {
        let path: String
        let classified: [(YARAMatch, ThreatVerdict)]
    }

    nonisolated private static func workerCount() -> Int {
        let cores = ProcessInfo.processInfo.activeProcessorCount
        let base = ProcessInfo.processInfo.isLowPowerModeEnabled ? 2 : cores - 1
        return max(2, min(base, YARAEngine.maximumConcurrentScans / 2))
    }

    nonisolated private static func scan(
        _ candidate: Candidate,
        with scanFile: @escaping @Sendable (String) async throws -> [YARAMatch]
    ) async -> FileOutcome {
        let file = candidate.path
        // Extensionless files are sniffed here, in parallel, rather than
        // during the walk: reading a header for every cache blob serially was
        // most of the indexing time.
        if candidate.needsContentCheck,
           !ScanCandidatePolicy.isExecutableContent(ScanCandidatePolicy.kind(atPath: file)) {
            return FileOutcome(path: file, classified: [])
        }
        guard let matches = try? await scanFile(file), !matches.isEmpty else {
            return FileOutcome(path: file, classified: [])
        }
        let unique = uniqueMatches(matches)
        return FileOutcome(path: file, classified: unique.map { ($0, classify(match: $0)) })
    }

    /// Records one file's findings and forwards actionable ones to the correlator.
    private func merge(_ outcome: FileOutcome) async {
        guard !outcome.classified.isEmpty else { return }
        results.append(contentsOf: outcome.classified.map { $0.0 })
        for (match, verdict) in outcome.classified {
            resultVerdicts[Self.matchKey(for: match)] = verdict
        }
        let actionableMatches = outcome.classified.compactMap { pair -> YARAMatch? in
            let (match, verdict) = pair
            guard verdict == .threat || verdict == .suspicious else { return nil }
            if ignoredPaths.contains(Self.canonicalPath(match.filePath)), Self.canIgnore(match: match) {
                return nil
            }
            return match
        }
        threatsFound += actionableMatches.count
        // Ingest only actionable YARA matches (.threat / .suspicious) into the
        // correlator. Safe verdicts (.applicationData, .developmentArtifact,
        // .likelySafe) still appear in the Deep Scan results view for
        // transparency but do not create alerts or fire notifications.
        guard let eng = engine, !actionableMatches.isEmpty else { return }
        let signals = actionableMatches.map { match in
            ThreatSignal(
                source: .yara,
                severity: Self.signalSeverity(for: match),
                title: "YARA match: \(match.ruleName)",
                description: "\(match.metadata["description"] ?? match.ruleName) at \(match.filePath)"
                    + (match.metadata["author"].map { " (rule author: \($0))" } ?? ""),
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
                        "yaraRules": match.ruleName,
                        // Third-party rule licenses (DRL 1.1) require the
                        // author to be retained in messages based on matches.
                        "yaraAuthors": match.metadata["author"] ?? "",
                        "suppressible": Self.canIgnore(match: match) ? "true" : "false",
                    ]
                )
            )
        }
        let alerts = await eng.correlator.ingestAndCorrelateNew(signals)
        for alert in alerts {
            eng.addAlert(alert)
            await NotificationManager.shared.send(for: alert)
        }
    }

    /// Publishes scan progress. While locations are still being walked the
    /// total is unknown, so the percentage is withheld (`progress` stays 0 and
    /// the view shows an indeterminate state with the running counts).
    private func publishProgress(queue: CandidateQueue, completed: Int, startTime: Date) {
        let state = queue.snapshot()
        let elapsed = Date().timeIntervalSince(startTime)
        discoveredFiles = state.discovered
        indexingLocation = state.location
        isIndexing = !state.finished
        scannedFiles = completed
        elapsedTime = elapsed
        if state.finished {
            totalFiles = state.discovered
            progress = state.discovered == 0 ? 0 : Double(completed) / Double(state.discovered)
            estimatedRemaining = completed == 0
                ? 0
                : elapsed / Double(completed) * Double(max(0, state.discovered - completed))
        } else {
            estimatedRemaining = 0
        }
    }

    private func finishCancelledScan(scanID: UUID) {
        isIndexing = false
        guard activeScanID == scanID else { return }
        isScanning = false
        isPaused = false
        isCancelling = false
        hasCompletedScan = false
        scanTask = nil
        activeScanID = nil
    }

    // MARK: - File Enumeration

    /// A file to scan. `needsContentCheck` marks extensionless files whose
    /// header decides whether they are scanned at all.
    struct Candidate: Sendable, Equatable {
        let path: String
        let needsContentCheck: Bool
    }

    /// What the walk decided about one file.
    enum CandidateDecision: Equatable {
        case scan
        case checkContent
        case skip
    }

    nonisolated static var standardScanRoots: [String] {
        [
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
            // Common stealer, loader, and persistence staging locations.
            NSHomeDirectory() + "/Library/Application Scripts",
            NSHomeDirectory() + "/Library/Scripts",
            NSHomeDirectory() + "/.local",
            NSHomeDirectory() + "/.config",
            "/Library/Scripts",
            "/Users/Shared",
            "/tmp",
            "/var/tmp",
            "/private/tmp"
        ]
    }

    /// Walks the standard macOS scan paths and streams candidates into
    /// `queue`. Media, document, archive, and font files are skipped.
    /// Runs inside `Task.detached`; stops early when that task is cancelled.
    nonisolated static func enumerateCandidates(into queue: CandidateQueue) {
        defer { queue.finish() }
        let fm  = FileManager.default
        let log = Logger(subsystem: "com.ehsanazish.nick", category: "DeepScanner")
        var walkedRoots = Set<String>()

        for scanPath in standardScanRoots {
            guard !Task.isCancelled else { return }
            // /tmp and /private/tmp are the same directory; walk it once.
            let root = canonicalPath(scanPath)
            guard walkedRoots.insert(root).inserted else { continue }
            guard fm.isReadableFile(atPath: root) else {
                log.warning("DeepScan: no access to \(scanPath, privacy: .public)")
                continue
            }
            queue.setLocation(scanPath)
            // Hidden files are included: dot-prefixed staging directories and
            // payloads are a hallmark of macOS stealers. Bundles are descended
            // so their actual Mach-O binaries are scanned.
            guard let enumerator = fm.enumerator(
                at: URL(fileURLWithPath: root),
                includingPropertiesForKeys: [.isExecutableKey, .isRegularFileKey, .isDirectoryKey],
                options: []
            ) else {
                log.warning("DeepScan: cannot enumerate \(scanPath, privacy: .public)")
                continue
            }

            var count = 0
            for case let url as URL in enumerator {
                if count % 256 == 0, Task.isCancelled { return }
                guard let res = try? url.resourceValues(
                    forKeys: [.isExecutableKey, .isRegularFileKey, .isDirectoryKey]
                ) else { continue }
                if res.isDirectory == true {
                    if prunedDirectoryNames.contains(url.lastPathComponent) {
                        enumerator.skipDescendants()
                    }
                    continue
                }
                guard res.isRegularFile == true else { continue }
                switch candidateDecision(
                    path: url.path,
                    scanRoot: scanPath,
                    isExecutable: res.isExecutable == true
                ) {
                case .scan:
                    queue.push(Candidate(path: url.path, needsContentCheck: false))
                    count += 1
                case .checkContent:
                    queue.push(Candidate(path: url.path, needsContentCheck: true))
                    count += 1
                case .skip:
                    break
                }
            }
            log.info("DeepScan: \(count) candidates from \(scanPath, privacy: .public)")
        }
    }

    /// Decides a file's fate from metadata alone (no I/O).
    nonisolated static func candidateDecision(
        path: String,
        scanRoot: String,
        isExecutable: Bool
    ) -> CandidateDecision {
        let ext = URL(fileURLWithPath: path).pathExtension.lowercased()
        let isLaunchPropertyList = ext == "plist"
            && (scanRoot.hasSuffix("LaunchDaemons") || scanRoot.hasSuffix("LaunchAgents"))
        guard !skippedExtensions.contains(ext) || isLaunchPropertyList else { return .skip }
        if isExecutable || scriptExtensions.contains(ext) || isLaunchPropertyList { return .scan }
        // Extensionless files are mostly opaque application caches. Only scan
        // the ones whose content can actually run (extensionless Mach-O and
        // scripts are a common dropper pattern).
        return ext.isEmpty ? .checkContent : .skip
    }

    /// Centralizes enumeration policy so launch-item property lists cannot be
    /// accidentally excluded when the general data-file skip list changes.
    nonisolated static func shouldScanFile(
        path: String,
        scanRoot: String,
        isExecutable: Bool,
        contentKind: (String) -> ScanCandidatePolicy.Kind = ScanCandidatePolicy.kind(atPath:)
    ) -> Bool {
        switch candidateDecision(path: path, scanRoot: scanRoot, isExecutable: isExecutable) {
        case .scan: return true
        case .skip: return false
        case .checkContent: return ScanCandidatePolicy.isExecutableContent(contentKind(path))
        }
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

        // Email attachment heuristics are intentionally built from common script
        // fragments. Those fragments are only meaningful when the file is a format
        // that can actually carry the behavior described by the rule. For example,
        // a bundled JavaScript application may contain the words `AutoOpen`,
        // `powershell`, and `XMLHTTP` in unrelated modules; that does not make the
        // JavaScript file an Office macro. Preserve the match in the completed report,
        // but never turn a context-incompatible match into an active alert.
        if !isEmailRuleApplicable(match.ruleName, to: match.filePath) {
            return .applicationData
        }

        // Concrete malware-family signatures remain actionable in every location.
        // A dropper controls its path, so location cannot override this evidence.
        if YARAVerdictPolicy.ruleClass(ruleName: match.ruleName, metadata: match.metadata) == .signature {
            return .threat
        }

        // Build outputs can live outside the source repository, especially under
        // DerivedData and SwiftPM scratch directories. Strong layout markers give
        // context to broad behavior rules without trusting arbitrary temp files.
        if isRecognizedDevelopmentArtifactPath(path) {
            return .developmentArtifact
        }

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

    /// Validates the file-format context for bundled Email Guard heuristics.
    /// Non-email rules always apply. This is deliberately based on capability rather
    /// than app identity, so a renamed malicious attachment cannot gain trust merely
    /// by being placed inside a known application's directory.
    nonisolated static func isEmailRuleApplicable(_ ruleName: String, to path: String) -> Bool {
        let ext = URL(fileURLWithPath: path).pathExtension.lowercased()

        switch ruleName {
        case "nick_email_office_macro_dropper":
            return [
                "doc", "dot", "xls", "xlt", "ppt", "pot", "pps",
                "docm", "dotm", "xlsm", "xltm", "xlam", "pptm", "potm", "ppsm", "sldm",
            ].contains(ext)
        case "nick_email_html_smuggling":
            return ["html", "htm", "xhtml", "svg", "mht", "mhtml"].contains(ext)
        case "nick_email_powershell_encoded_dropper":
            return ["ps1", "psm1", "bat", "cmd"].contains(ext)
        case "nick_email_applescript_dropper":
            return ["applescript", "scpt", "scptd", "sh", "command"].contains(ext)
        case "nick_email_shell_dropper":
            return ["sh", "bash", "zsh", "command", "tool"].contains(ext)
        default:
            return true
        }
    }

    /// Maps YARA metadata to signal severity. Missing metadata defaults to Medium;
    /// bundled rules are separately validated to require an explicit value.
    nonisolated static func signalSeverity(for match: YARAMatch) -> SignalSeverity {
        switch YARAVerdictPolicy.severity(metadata: match.metadata, tags: match.tags) {
        case .info: return .info
        case .low: return .low
        case .medium: return .medium
        case .high: return .high
        case .critical: return .critical
        }
    }

    nonisolated static func matchKey(for match: YARAMatch) -> String {
        "\(match.ruleName)\u{0}\(canonicalPath(match.filePath))"
    }

    /// User ignores are available only for broad, non-critical behavioral matches.
    /// Concrete signatures remain visible and actionable on every scan.
    nonisolated static func canIgnore(match: YARAMatch) -> Bool {
        YARAVerdictPolicy.canIgnore(ruleName: match.ruleName, metadata: match.metadata, tags: match.tags)
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

    /// Staging and persistence locations. A development downgrade is never
    /// applied here: a payload chooses its own directory names, and no real
    /// build tree lives in these places.
    nonisolated static func isDevelopmentDowngradeForbidden(_ path: String) -> Bool {
        let lower = canonicalPath(path).lowercased()
        let forbidden = [
            "/library/launchagents/", "/library/launchdaemons/",
            "/library/privilegedhelpertools/", "/library/application support/",
            "/library/application scripts/", "/users/shared/", "/downloads/",
        ]
        return forbidden.contains(where: lower.contains)
    }

    /// A match is development context only inside a real repository root that
    /// sits strictly below the user's home directory. The walk stops at the
    /// home directory so a dotfiles repository in `~` cannot turn all of
    /// Downloads, Desktop, and Application Support into "source code".
    nonisolated static func isVerifiedDevelopmentContext(
        _ path: String,
        homeDirectory: String = NSHomeDirectory()
    ) -> Bool {
        let canonical = canonicalPath(path)
        guard !isDevelopmentDowngradeForbidden(canonical) else { return false }
        let home = canonicalPath(homeDirectory)
        let boundaries: Set<String> = [
            "/", "/Users", "/Volumes", "/private", "/private/tmp", "/private/var",
            "/private/var/tmp", "/private/var/folders", home,
        ]
        var candidate = URL(fileURLWithPath: canonical).deletingLastPathComponent()
        for _ in 0..<12 {
            if boundaries.contains(candidate.path) { break }
            if isRepositoryRoot(candidate) { return true }
            let parent = candidate.deletingLastPathComponent()
            if parent.path == candidate.path { break }
            candidate = parent
        }
        return false
    }

    /// Structured evidence of a working copy or package root — never a bare
    /// directory name.
    nonisolated static func isRepositoryRoot(_ directory: URL) -> Bool {
        let fm = FileManager.default
        let git = directory.appendingPathComponent(".git")
        var isDirectory: ObjCBool = false
        if fm.fileExists(atPath: git.path, isDirectory: &isDirectory) {
            if isDirectory.boolValue {
                if fm.fileExists(atPath: git.appendingPathComponent("HEAD").path) { return true }
            } else if let handle = FileHandle(forReadingAtPath: git.path),
                      let head = try? handle.read(upToCount: 8) {
                try? handle.close()
                // Worktrees and submodules use a `.git` file pointing at the real directory.
                if head.starts(with: Data("gitdir:".utf8)) { return true }
            }
        }
        if fm.fileExists(atPath: directory.appendingPathComponent("Package.swift").path) { return true }
        if let children = try? fm.contentsOfDirectory(atPath: directory.path) {
            return children.contains { name in
                name.hasSuffix(".xcodeproj")
                    && fm.fileExists(atPath: directory.appendingPathComponent(name)
                        .appendingPathComponent("project.pbxproj").path)
            }
        }
        return false
    }

    nonisolated static func isRecognizedDevelopmentArtifactPath(_ path: String) -> Bool {
        let canonical = canonicalPath(path)
        let lower = canonical.lowercased()
        guard !isDevelopmentDowngradeForbidden(canonical) else { return false }
        if isVerifiedSwiftPMWorkspaceArtifact(canonical) { return true }

        // Xcode's and SwiftPM's default per-user locations.
        if lower.contains("/library/developer/xcode/deriveddata/")
            || lower.contains("/library/caches/org.swift.swiftpm/") {
            return true
        }

        let layoutMarkers = [
            "/deriveddata/", "/sourcepackages/", "/checkouts/", "/.build/",
            "/build/products/", ".dsym/contents/resources/dwarf/",
        ]
        guard layoutMarkers.contains(where: lower.contains) else { return false }
        // Anywhere else — notably temporary directories — a build-layout name
        // is attacker-choosable. Require the metadata Xcode writes into a
        // derived-data root, or a verified repository.
        return hasXcodeDerivedDataRoot(canonical) || isVerifiedDevelopmentContext(canonical)
    }

    /// Xcode writes `info.plist` with a `WorkspacePath` key into every
    /// derived-data root, including custom `-derivedDataPath` locations.
    nonisolated static func hasXcodeDerivedDataRoot(_ path: String) -> Bool {
        var candidate = URL(fileURLWithPath: path).deletingLastPathComponent()
        for _ in 0..<16 {
            let plist = candidate.appendingPathComponent("info.plist").path
            if let info = NSDictionary(contentsOfFile: plist),
               info["WorkspacePath"] is String {
                return true
            }
            let parent = candidate.deletingLastPathComponent()
            if parent.path == candidate.path { break }
            candidate = parent
        }
        return false
    }

    /// Recognizes SwiftPM's alternate scratch layouts using persisted workspace
    /// metadata instead of trusting a directory name alone. Package artifact caches
    /// and `--scratch-path .../out` products do not necessarily include `.build`,
    /// `SourcePackages`, or another marker handled above.
    nonisolated static func isVerifiedSwiftPMWorkspaceArtifact(_ path: String) -> Bool {
        let resolved = URL(fileURLWithPath: canonicalPath(path)).standardizedFileURL
        var candidate = resolved.deletingLastPathComponent()
        for _ in 0..<20 {
            let state = candidate.appendingPathComponent("workspace-state.json").path
            if FileManager.default.isReadableFile(atPath: state) {
                let root = candidate.path.lowercased()
                let item = resolved.path.lowercased()
                guard item.hasPrefix(root + "/") else { return false }
                let relative = String(item.dropFirst(root.count + 1))
                return relative.hasPrefix("artifacts/")
                    || relative.hasPrefix("checkouts/")
                    || relative.hasPrefix("repositories/")
                    || relative.hasPrefix("out/products/")
                    || relative.hasPrefix("plugins/cache/")
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
            let signedBundles = signedInstalledBundleIdentifiers()
            if candidateBundleIdentifiers(forContainer: containerID).contains(where: signedBundles.contains) {
                return true
            }
        }

        return false
    }

    /// The bundle identifiers a container name can belong to under the
    /// conventions accepted by `containerIdentifier(_:matchesBundleIdentifier:)`.
    nonisolated static func candidateBundleIdentifiers(forContainer containerID: String) -> [String] {
        let container = containerID.lowercased()
        var candidates = [container]
        if container.hasSuffix(".data") { candidates.append(String(container.dropLast(5))) }
        if container.hasPrefix("group."), container.hasSuffix(".shared") {
            candidates.append(String(container.dropFirst(6).dropLast(7)))
        }
        return candidates.filter { !$0.isEmpty }
    }

    private nonisolated static let signedBundleCache = OSAllocatedUnfairLock<(builtAt: Date, identifiers: Set<String>)>(
        initialState: (.distantPast, [])
    )

    /// Lower-cased bundle identifiers of installed, validly signed apps.
    /// Built once per scan window instead of enumerating and signature-checking
    /// every installed app for each finding.
    nonisolated static func signedInstalledBundleIdentifiers() -> Set<String> {
        let cached = signedBundleCache.withLock { $0 }
        if Date().timeIntervalSince(cached.builtAt) < 300 { return cached.identifiers }
        var identifiers = Set<String>()
        for appURL in installedApplicationURLs() {
            guard let bundleID = Bundle(url: appURL)?.bundleIdentifier?.lowercased(),
                  signedAppExists(atPath: appURL.path) else { continue }
            identifiers.insert(bundleID)
        }
        // Freeze the locally-built set before passing it into the lock closure.
        // Swift 6 otherwise treats the mutable local as a concurrently captured
        // variable, even though mutation has finished at this point.
        let resolvedIdentifiers = identifiers
        signedBundleCache.withLock { $0 = (Date(), resolvedIdentifiers) }
        return resolvedIdentifiers
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

// MARK: - CandidateQueue

/// Hand-off between the file-system walk (a detached task) and the scan
/// workers (driven from the main actor). Lock-protected so neither side
/// depends on the other's isolation.
final class CandidateQueue: Sendable {

    enum Pop: Sendable {
        case item(DeepScanner.Candidate)
        case empty
        case finished
    }

    struct Snapshot: Sendable {
        let discovered: Int
        let location: String
        let finished: Bool
    }

    private struct State: Sendable {
        var items: [DeepScanner.Candidate] = []
        var head = 0
        var discovered = 0
        var location = ""
        var finished = false
    }

    private let state = OSAllocatedUnfairLock(initialState: State())

    func push(_ candidate: DeepScanner.Candidate) {
        state.withLock {
            $0.items.append(candidate)
            $0.discovered += 1
        }
    }

    func setLocation(_ location: String) {
        state.withLock { $0.location = location }
    }

    func finish() {
        state.withLock { $0.finished = true }
    }

    func pop() -> Pop {
        state.withLock { state -> Pop in
            if state.head < state.items.count {
                let candidate = state.items[state.head]
                state.head += 1
                // Release consumed storage now and then.
                if state.head > 4_096, state.head * 2 > state.items.count {
                    state.items.removeFirst(state.head)
                    state.head = 0
                }
                return .item(candidate)
            }
            return state.finished ? .finished : .empty
        }
    }

    func snapshot() -> Snapshot {
        state.withLock { Snapshot(discovered: $0.discovered, location: $0.location, finished: $0.finished) }
    }
}
