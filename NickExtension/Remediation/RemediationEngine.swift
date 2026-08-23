// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import CryptoKit
import Darwin
import Foundation
import os

// MARK: - RemediationEngine

/// Orchestrates automated threat response:
/// 1. Sends `SIGKILL` to the offending process
/// 2. Quarantines the threat file
/// 3. Quarantines persistence mechanisms (LaunchAgents / LaunchDaemons)
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
        pid:         Int32,
        terminateProcess: Bool = true
    ) -> RemediationReport {
        var actions: [RemediationAction] = []

        // 1. Kill the offending process immediately
        if terminateProcess {
            actions.append(killProcess(pid: pid))
        }

        // 2. Quarantine the threat file. Never delete as a fallback: a failed
        // quarantine must remain recoverable and visible to the user.
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
                : "Failed to quarantine — file was not deleted"
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

    /// Finds and quarantines `.plist` files in LaunchAgent / LaunchDaemon directories
    /// that explicitly reference `threatPath`.
    private func cleanPersistence(threatPath: String) -> [RemediationAction] {
        var actions: [RemediationAction] = []

        var launchDirs: Set<String> = [
            "/Library/LaunchAgents",
            "/Library/LaunchDaemons",
        ]
        let components = URL(fileURLWithPath: threatPath).standardizedFileURL.pathComponents
        if components.count > 2, components[1] == "Users" {
            launchDirs.insert("/Users/\(components[2])/Library/LaunchAgents")
        }

        for dir in launchDirs {
            for plistPath in maliciousPlists(in: dir, referencingPath: threatPath) {
                guard let hash = sha256(of: plistPath) else {
                    actions.append(RemediationAction(
                        type: .removeLaunchItem, target: plistPath,
                        success: false, detail: "Could not hash persistence item; left unchanged"
                    ))
                    continue
                }
                let record = quarantineManager.quarantine(
                    filePath: plistPath,
                    hash: hash,
                    threatName: "Persistence linked to quarantined threat",
                    severity: "high",
                    processPath: threatPath,
                    pid: 0
                )
                actions.append(RemediationAction(
                    type: .removeLaunchItem,
                    target: plistPath,
                    success: record != nil,
                    detail: record != nil
                        ? "Persistence plist moved to quarantine"
                        : "Failed to quarantine plist; left unchanged"
                ))
            }
        }

        return actions
    }

    /// Returns paths of `.plist` files in `directory` whose `Program` or
    /// `ProgramArguments[0]` explicitly references `targetPath`.
    ///
    /// - Important: Only returns non-Apple plists that contain the exact,
    ///   standardized absolute threat path. Matching plists are quarantined, never deleted.
    private func maliciousPlists(in directory: String, referencingPath targetPath: String) -> [String] {
        let fm = FileManager.default
        guard let files = try? fm.contentsOfDirectory(atPath: directory) else { return [] }

        let normalizedTarget = URL(fileURLWithPath: targetPath).standardizedFileURL.path
        var matches: [String] = []

        for file in files where file.hasSuffix(".plist") && !file.hasPrefix("com.apple.") {
            let fullPath = (directory as NSString).appendingPathComponent(file)

            guard let data  = fm.contents(atPath: fullPath),
                  let plist = try? PropertyListSerialization.propertyList(
                      from: data, format: nil) as? [String: Any]
            else { continue }

            let candidates = ([plist["Program"] as? String].compactMap { value in value })
                + (plist["ProgramArguments"] as? [String] ?? [])
            let hasExactReference = candidates.contains { candidate in
                guard candidate.hasPrefix("/") else { return false }
                return URL(fileURLWithPath: candidate).standardizedFileURL.path == normalizedTarget
            }
            if hasExactReference { matches.append(fullPath) }
        }

        return matches
    }

    private func sha256(of path: String) -> String? {
        guard let data = FileManager.default.contents(atPath: path) else { return nil }
        return SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }
}
