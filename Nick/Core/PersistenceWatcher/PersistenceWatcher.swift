// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation
import Observation
import os

// MARK: - PersistenceWatcherError

/// Errors thrown by `PersistenceWatcher`.
enum PersistenceWatcherError: LocalizedError {

    /// A required directory could not be read (permissions, not found, etc.).
    case directoryUnreadable(path: String, underlying: Error)

    var errorDescription: String? {
        switch self {
        case .directoryUnreadable(let path, let err):
            return "Cannot enumerate persistence directory \(path): \(err.localizedDescription)"
        }
    }
}

// MARK: - PersistenceWatcher

/// Enumerates all macOS persistence mechanisms and produces `PersistenceItem` snapshots.
///
/// Phase 1 is snapshot-only: `start()` performs a one-shot enumeration of every
/// known persistence location and stores the results. FSEvents-based real-time
/// monitoring is added in Phase 2.
///
/// Persistence items with unsigned or missing executables are converted to
/// `ThreatSignal` events that the `ThreatCorrelator` can act on.
@Observable
@MainActor
final class PersistenceWatcher: MonitorProtocol {

    // MARK: - MonitorProtocol

    let monitorType: MonitorType = .persistence
    private(set) var isRunning = false

    // MARK: - Published State

    /// All persistence items found during the last snapshot.
    private(set) var items: [PersistenceItem] = []

    // MARK: - Private

    private var pendingSignals: [ThreatSignal] = []
    private let parser = PlistParser()

    private static let logger = Logger(
        subsystem: "com.ehsanazish.nick",
        category: "PersistenceWatcher"
    )

    /// Known directories to scan, with associated metadata.
    private static let scanLocations: [(path: String, type: PersistenceType, scope: PersistenceScope)] = [
        ("/Library/LaunchDaemons",              .launchDaemon, .system),
        ("/Library/LaunchAgents",               .launchAgent,  .system),
        (NSString("~/Library/LaunchAgents").expandingTildeInPath, .launchAgent, .user),
        ("/Library/StartupItems",               .startupItem,  .system),
        ("/etc/periodic/daily",                 .periodicScript, .system),
        ("/etc/periodic/weekly",                .periodicScript, .system),
        ("/etc/periodic/monthly",               .periodicScript, .system),
        ("/Library/SystemExtensions",           .systemExtension, .system)
    ]

    // MARK: - MonitorProtocol

    /// Performs a full snapshot scan of all persistence locations.
    func start() async throws {
        guard !isRunning else { return }
        isRunning = true
        defer { isRunning = false }
        let found = try await snapshot()
        items = found
        pendingSignals = found.compactMap { makeSignal(from: $0) }
        Self.logger.info("Persistence snapshot: \(found.count) items, \(self.pendingSignals.count) signals")
    }

    func stop() async {
        isRunning = false
    }

    func latestSignals() async -> [ThreatSignal] {
        let signals = pendingSignals
        pendingSignals = []
        return signals
    }

    // MARK: - Public API

    /// Scans all known persistence locations and returns the complete item list.
    ///
    /// - Returns: All `PersistenceItem` values found across all monitored paths.
    /// - Throws: `PersistenceWatcherError` if a directory cannot be read.
    func snapshot() async throws -> [PersistenceItem] {
        var all: [PersistenceItem] = []
        for location in Self.scanLocations {
            let found = await scanDirectory(
                at: location.path,
                type: location.type,
                scope: location.scope
            )
            all.append(contentsOf: found)
        }
        all.append(contentsOf: await scanCrontabs())
        all.append(contentsOf: await scanLoginItems())
        return all
    }

    // MARK: - Private Scanning

    private func scanDirectory(
        at path: String,
        type: PersistenceType,
        scope: PersistenceScope
    ) async -> [PersistenceItem] {
        guard FileManager.default.fileExists(atPath: path) else { return [] }

        let urls: [URL]
        do {
            urls = try FileManager.default.contentsOfDirectory(
                at: URL(fileURLWithPath: path),
                includingPropertiesForKeys: [.contentModificationDateKey, .isRegularFileKey],
                options: [.skipsHiddenFiles]
            )
        } catch {
            Self.logger.error("Cannot read directory \(path): \(error.localizedDescription)")
            return []
        }

        var items: [PersistenceItem] = []
        for url in urls {
            if let item = await makeItem(from: url, type: type, scope: scope) {
                items.append(item)
            }
        }
        return items
    }

    private func makeItem(
        from url: URL,
        type: PersistenceType,
        scope: PersistenceScope
    ) async -> PersistenceItem? {
        let path = url.path
        let attrs = try? FileManager.default.attributesOfItem(atPath: path)
        let modDate = attrs?[.modificationDate] as? Date

        // For LaunchAgent/Daemon plists, parse the plist for rich metadata
        if url.pathExtension == "plist",
           type == .launchAgent || type == .launchDaemon {
            return await makeLaunchItem(from: url, plistType: type, scope: scope, modDate: modDate)
        }

        // For other items (scripts, system extensions), use filename as name
        return PersistenceItem(
            id: UUID(),
            type: type,
            name: url.lastPathComponent,
            path: path,
            executablePath: type == .periodicScript ? path : nil,
            isEnabled: true,
            signingStatus: nil,
            scope: scope,
            lastModified: modDate
        )
    }

    private func makeLaunchItem(
        from url: URL,
        plistType: PersistenceType,
        scope: PersistenceScope,
        modDate: Date?
    ) async -> PersistenceItem? {
        guard let plist = try? parser.parse(at: url.path) else {
            // Malformed plist — still record it, it's suspicious
            return PersistenceItem(
                id: UUID(),
                type: plistType,
                name: url.lastPathComponent,
                path: url.path,
                executablePath: nil,
                isEnabled: false,
                signingStatus: nil,
                scope: scope,
                lastModified: modDate
            )
        }

        let execPath = plist.programPath
        // SignatureValidator calls SecStaticCodeCheckValidity which blocks the calling
        // thread. Run it off @MainActor so the UI stays responsive.
        let signingStatus: SigningStatus? = await {
            guard let path = execPath else { return nil }
            guard FileManager.default.fileExists(atPath: path) else { return .unknown }
            return await Task.detached(priority: .userInitiated) {
                SignatureValidator.shared.evaluate(binaryPath: path)
            }.value
        }()

        let isEnabled = plist.runAtLoad || plist.keepAlive || plist.startInterval != nil

        return PersistenceItem(
            id: UUID(),
            type: plistType,
            name: plist.label.isEmpty ? url.lastPathComponent : plist.label,
            path: url.path,
            executablePath: execPath,
            isEnabled: isEnabled,
            signingStatus: signingStatus,
            scope: scope,
            lastModified: modDate
        )
    }

    /// Returns Login Items registered with System Events.
    ///
    /// Requires Automation → System Events TCC permission.
    /// Returns an empty array silently when access is denied so the rest of the
    /// persistence scan continues unaffected.
    private func scanLoginItems() async -> [PersistenceItem] {
        // Each line: "<name>\t<posix path>"  — tab-delimited to avoid comma ambiguity.
        let script = """
            tell application "System Events"
                set output to ""
                repeat with li in every login item
                    set output to output & (name of li) & tab & (path of li) & linefeed
                end repeat
                return output
            end tell
            """
        guard let raw = try? await runAppleScript(script), !raw.isEmpty else { return [] }

        var items: [PersistenceItem] = []
        for line in raw.components(separatedBy: "\n") {
            let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmed.isEmpty else { continue }
            let parts = trimmed.components(separatedBy: "\t")
            let name     = parts.first ?? trimmed
            let itemPath = parts.count > 1 ? parts[1] : ""
            let execPath = itemPath.isEmpty ? nil : itemPath
            let signingStatus: SigningStatus? = await {
                guard let path = execPath else { return nil }
                guard FileManager.default.fileExists(atPath: path) else { return .unknown }
                return await Task.detached(priority: .userInitiated) {
                    SignatureValidator.shared.evaluate(binaryPath: path)
                }.value
            }()
            items.append(PersistenceItem(
                id: UUID(),
                type: .loginItem,
                name: name,
                path: itemPath.isEmpty ? "Login Items" : itemPath,
                executablePath: execPath,
                isEnabled: true,
                signingStatus: signingStatus,
                scope: .user,
                lastModified: nil
            ))
        }
        Self.logger.info("Login Items scan: found \(items.count) item(s)")
        return items
    }

    /// Runs a hardcoded AppleScript string out-of-process and returns stdout.
    ///
    /// - Parameter script: A hardcoded AppleScript literal — never pass user input here.
    /// - Returns: Trimmed stdout, or throws if the process cannot be launched.
    private func runAppleScript(_ script: String) async throws -> String {
        try await withCheckedThrowingContinuation { continuation in
            let process = Process()
            process.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
            process.arguments = ["-e", script]
            let outputPipe = Pipe()
            let errorPipe  = Pipe()
            process.standardOutput = outputPipe
            process.standardError  = errorPipe
            process.terminationHandler = { _ in
                let data   = outputPipe.fileHandleForReading.readDataToEndOfFile()
                let output = String(data: data, encoding: .utf8) ?? ""
                continuation.resume(returning: output.trimmingCharacters(in: .whitespacesAndNewlines))
            }
            do {
                try process.run()
            } catch {
                continuation.resume(throwing: error)
            }
        }
    }

    private func scanCrontabs() async -> [PersistenceItem] {
        var items: [PersistenceItem] = []
        let etcCrontab = "/etc/crontab"
        if FileManager.default.fileExists(atPath: etcCrontab) {
            items.append(PersistenceItem(
                id: UUID(),
                type: .cronJob,
                name: "crontab (system)",
                path: etcCrontab,
                executablePath: nil,
                isEnabled: true,
                signingStatus: nil,
                scope: .system,
                lastModified: (try? FileManager.default.attributesOfItem(atPath: etcCrontab))?[.modificationDate] as? Date
            ))
        }
        return items
    }

    // MARK: - Signal Generation

    private func makeSignal(from item: PersistenceItem) -> ThreatSignal? {
        // Unsigned executable in a launch agent/daemon → high severity
        if item.signingStatus?.isSuspicious == true,
           item.type == .launchAgent || item.type == .launchDaemon {
            return ThreatSignal(
                source: .persistence,
                severity: .high,
                title: "Unsigned launch \(item.type == .launchDaemon ? "daemon" : "agent")",
                description: "'\(item.name)' at \(item.path) points to an unsigned executable at \(item.executablePath ?? "unknown").",
                context: ThreatSignalContext(metadata: ["path": item.path, "executable": item.executablePath ?? "", "reason": item.type == .launchDaemon ? "unsigned_launch_daemon" : "unsigned_launch_agent"])
            )
        }

        // Launch item pointing to a nonexistent executable → medium severity
        if let execPath = item.executablePath,
           !FileManager.default.fileExists(atPath: execPath),
           item.type == .launchAgent || item.type == .launchDaemon {
            return ThreatSignal(
                source: .persistence,
                severity: .medium,
                title: "Launch item with missing executable",
                description: "'\(item.name)' references executable at \(execPath) which does not exist.",
                context: ThreatSignalContext(metadata: [
                    "path": item.path,
                    "executable": execPath,
                    "reason": "persist_executable_missing"
                ])
            )
        }

        return nil
    }
}
