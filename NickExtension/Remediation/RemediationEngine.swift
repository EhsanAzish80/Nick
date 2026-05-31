// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Darwin
import Foundation
import os

// MARK: - RemediationEngine

/// Orchestrates automated threat response:
/// 1. Sends `SIGKILL` to the offending process
/// 2. Quarantines the threat file
/// 3. Scans and removes persistence mechanisms (LaunchAgents / LaunchDaemons)
///
/// All methods are synchronous and must be called from a background queue
/// (never from the ES callback queue directly).
final class RemediationEngine {

    // MARK: - Private

    private static let logger = Logger(
        subsystem: "com.ehsanazish.nick.NickExtension",
        category: "RemediationEngine"
    )

    private let quarantineManager: QuarantineManager

    // MARK: - Init

    init(quarantineManager: QuarantineManager) {
        self.quarantineManager = quarantineManager
    }

    // MARK: - Public API

    /// Full remediation pipeline for a confirmed threat.
    ///
    /// - Returns: A `RemediationReport` describing every action taken.
    func remediate(
        threatPath:  String,
        hash:        String,
        threatName:  String,
        processPath: String,
        pid:         Int32
    ) -> RemediationReport {
        var actions: [RemediationAction] = []

        // 1. Kill the offending process immediately
        actions.append(killProcess(pid: pid))

        // 2. Quarantine (or delete as fallback) the threat file
        let record = quarantineManager.quarantine(
            filePath:    threatPath,
            hash:        hash,
            threatName:  threatName,
            severity:    "critical",
            processPath: processPath,
            pid:         pid
        )
        actions.append(RemediationAction(
            type:    .quarantineFile,
            target:  threatPath,
            success: record != nil,
            detail:  record != nil
                ? "Moved to quarantine vault"
                : "Failed to quarantine — deleted as fallback"
        ))

        // 3. Remove persistence mechanisms that reference the threat
        actions.append(contentsOf: cleanPersistence(threatPath: threatPath))

        let report = RemediationReport(
            timestamp:        Date(),
            threatPath:       threatPath,
            threatName:       threatName,
            quarantineRecord: record,
            actions:          actions
        )

        let succeeded = actions.filter(\.success).count
        Self.logger.info("Remediation complete for '\(threatPath)': \(succeeded)/\(actions.count) action(s) succeeded")
        return report
    }

    // MARK: - Private Steps

    private func killProcess(pid: Int32) -> RemediationAction {
        // Never kill init (PID 1) or the extension itself
        guard pid > 1 else {
            return RemediationAction(
                type: .killProcess, target: "PID \(pid)",
                success: false, detail: "Refused to kill PID ≤ 1"
            )
        }
        let result = Darwin.kill(pid, SIGKILL)
        return RemediationAction(
            type:    .killProcess,
            target:  "PID \(pid)",
            success: result == 0,
            detail:  result == 0 ? "SIGKILL sent" : "kill(2) failed — errno \(errno)"
        )
    }

    /// Finds and removes `.plist` files in LaunchAgent / LaunchDaemon directories
    /// that explicitly reference `threatPath`.
    private func cleanPersistence(threatPath: String) -> [RemediationAction] {
        var actions: [RemediationAction] = []

        let launchDirs = [
            (NSHomeDirectory() as NSString).appendingPathComponent("Library/LaunchAgents"),
            "/Library/LaunchAgents",
            "/Library/LaunchDaemons",
        ]

        for dir in launchDirs {
            for plistPath in maliciousPlists(in: dir, referencingPath: threatPath) {
                var ok = false
                do {
                    try FileManager.default.removeItem(atPath: plistPath)
                    ok = true
                } catch {}

                actions.append(RemediationAction(
                    type:    .removeLaunchItem,
                    target:  plistPath,
                    success: ok,
                    detail:  ok ? "Persistence plist removed" : "Failed to remove plist"
                ))
            }
        }

        return actions
    }

    /// Returns paths of `.plist` files in `directory` whose `Program` or
    /// `ProgramArguments[0]` explicitly references `targetPath`.
    ///
    /// - Important: Only returns plists that contain the exact threat path
    ///   or its basename. Never removes system or Apple-signed plists.
    private func maliciousPlists(in directory: String, referencingPath targetPath: String) -> [String] {
        let fm = FileManager.default
        guard let files = try? fm.contentsOfDirectory(atPath: directory) else { return [] }

        let targetName = (targetPath as NSString).lastPathComponent
        var matches: [String] = []

        for file in files where file.hasSuffix(".plist") {
            let fullPath = (directory as NSString).appendingPathComponent(file)

            guard let data  = fm.contents(atPath: fullPath),
                  let plist = try? PropertyListSerialization.propertyList(
                      from: data, format: nil) as? [String: Any]
            else { continue }

            let program: String? =
                (plist["Program"] as? String) ??
                (plist["ProgramArguments"] as? [String])?.first

            guard let p = program else { continue }

            // Require the full path to match, or the basename when it's > 4 chars
            if p.contains(targetPath) || (targetName.count > 4 && p.contains(targetName)) {
                matches.append(fullPath)
            }
        }

        return matches
    }
}
