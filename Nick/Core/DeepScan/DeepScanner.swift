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
    var results:            [YARAMatch]  = []

    // MARK: - Private

    private var scanTask: Task<Void, Never>?
    private var storedOnlyOnPower = false
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
        scanFile: @escaping @Sendable (String) async throws -> [YARAMatch]
    ) {
        guard !isScanning else { return }
        storedOnlyOnPower = onlyOnPower
        scanTask = Task { [weak self] in
            await self?.performDeepScan(scanFile: scanFile)
        }
    }

    /// Cancels an in-progress scan immediately.
    func cancel() {
        scanTask?.cancel()
        scanTask   = nil
        isScanning = false
        isPaused   = false
    }

    // MARK: - Private Implementation

    private func performDeepScan(
        scanFile: @escaping @Sendable (String) async throws -> [YARAMatch]
    ) async {
        let startTime = Date()
        isScanning    = true
        results       = []
        threatsFound  = 0
        currentFile   = "Indexing files…"

        // Phase 1: enumerate executables on a background thread so the UI stays live.
        let files: [String] = await Task.detached(priority: .utility) {
            DeepScanner.enumerateExecutables()
        }.value

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

            // Update progress state on the main actor (we're already here).
            let elapsed = Date().timeIntervalSince(startTime)
            scannedFiles = index
            progress     = files.isEmpty ? 0 : Double(index) / Double(files.count)
            currentFile  = file
            elapsedTime  = elapsed

            // Recalculate the time estimate every 100 files.
            if index > 0 && index % 100 == 0 {
                let avgPerFile = elapsed / Double(index)
                estimatedRemaining = avgPerFile * Double(files.count - index)
            }

            // Per-file scan — YARAEngine.scanFile dispatches to a background thread
            // internally, so this await releases the main actor for the scan work.
            do {
                let matches = try await scanFile(file)
                if !matches.isEmpty {
                    results.append(contentsOf: matches)
                    threatsFound += matches.count
                    // Ingest only actionable YARA matches (.threat / .suspicious) into the
                    // correlator. Safe verdicts (.applicationData, .developmentArtifact,
                    // .likelySafe) still appear in the Deep Scan results view for transparency
                    // but do not create alerts or fire notifications.
                    if let eng = engine {
                        var signals: [ThreatSignal] = []
                        for match in matches {
                            let verdict = await Task.detached(priority: .utility) {
                                DeepScanner.classify(match: match)
                            }.value
                            guard verdict == .threat || verdict == .suspicious else { continue }
                            let severity: SignalSeverity = match.tags.contains("critical") ? .critical : .high
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
                                    metadata: ["path": match.filePath, "rule": match.ruleName]
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

            // Yield cooperatively every 10 files to keep the main actor responsive.
            if index % 10 == 0 { await Task.yield() }
        }

        // Finalise.
        progress     = 1.0
        scannedFiles = totalFiles
        isScanning   = false
        isPaused     = false
        elapsedTime  = Date().timeIntervalSince(startTime)
        Self.log.info("DeepScanner: complete — \(self.threatsFound) threat(s) found")
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

        let skipExtensions: Set<String> = [
            "jpg", "jpeg", "png", "gif", "webp", "heic", "heif",
            "mp3", "mp4", "mov", "avi", "mkv", "wav", "flac", "aac",
            "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx",
            "zip", "tar", "gz", "dmg", "iso",
            "ttf", "otf", "woff", "woff2",
            "css", "svg", "json", "xml", "plist"
        ]

        let scriptExtensions: Set<String> = [
            "sh", "py", "rb", "pl", "swift", "command", "tool"
        ]

        for scanPath in scanPaths {
            guard fm.isReadableFile(atPath: scanPath) else {
                log.warning("DeepScan: no access to \(scanPath, privacy: .public)")
                continue
            }
            guard let enumerator = fm.enumerator(
                at: URL(fileURLWithPath: scanPath),
                includingPropertiesForKeys: [.isExecutableKey, .isRegularFileKey],
                options: [.skipsHiddenFiles, .skipsPackageDescendants]
            ) else {
                log.warning("DeepScan: cannot enumerate \(scanPath, privacy: .public)")
                continue
            }

            var count = 0
            for case let url as URL in enumerator {
                let ext = url.pathExtension.lowercased()
                guard !skipExtensions.contains(ext) else { continue }
                guard let res = try? url.resourceValues(
                    forKeys: [.isExecutableKey, .isRegularFileKey]
                ), res.isRegularFile == true else { continue }

                if res.isExecutable == true
                    || scriptExtensions.contains(ext)
                    || ext.isEmpty
                {
                    files.append(url.path)
                    count += 1
                }
            }
            log.info("DeepScan: \(count) files from \(scanPath, privacy: .public)")
        }

        return files
    }

    // MARK: - Power Source

    // MARK: - Verdict Classification

    /// Classifies a YARA match into a `ThreatVerdict` using path heuristics and
    /// code-signature verification. Marked `nonisolated` so it can run inside
    /// `Task.detached` without holding the main actor.
    nonisolated static func classify(match: YARAMatch) -> ThreatVerdict {
        let path = match.filePath.lowercased()

        // Category A: Build / dev artifacts — path check is safe (build system output).
        let buildArtifacts = ["deriveddata", "workspacestorage", ".git/", "node_modules",
                              "__pycache__", ".build/", "/build/products/", "nickperformanceaudit"]
        if buildArtifacts.contains(where: { path.contains($0) }) { return .developmentArtifact }

        // Category B: Application runtime data — only trust if the parent .app is signed.
        // An attacker cannot gain trusted status by placing files under a path named after
        // a known application without the corresponding signed bundle.
        if isInsideSignedAppData(path: match.filePath) { return .applicationData }

        let signing = SignatureValidator.shared.evaluate(binaryPath: match.filePath)
        if case .signed = signing { return .likelySafe }

        return .suspicious
    }

    /// Returns `true` when `path` is inside the data container of a signed `.app` bundle.
    ///
    /// Extracts the app name from paths containing `/Application Support/`, `/Caches/`, or
    /// `/WebKit/`, locates a matching `.app` in standard install directories, and verifies
    /// it carries a valid Developer ID signature.
    nonisolated static func isInsideSignedAppData(path: String) -> Bool {
        let markers = ["/Application Support/", "/Caches/", "/WebKit/"]
        guard markers.contains(where: { path.range(of: $0, options: .caseInsensitive) != nil }) else {
            return false
        }
        for marker in markers {
            guard let range = path.range(of: marker, options: .caseInsensitive) else { continue }
            let afterMarker = String(path[range.upperBound...])
            let appName = afterMarker.components(separatedBy: "/").first ?? ""
            guard !appName.isEmpty else { continue }
            let fm = FileManager.default
            for candidate in appBundleSearchDirectories(for: appName) {
                guard fm.fileExists(atPath: candidate) else { continue }
                let status = SignatureValidator.shared.evaluate(binaryPath: candidate)
                if case .signed = status { return true }
            }
        }
        return false
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
