// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import CryptoKit
import Darwin
import Foundation
import Security
import os

/// Validates a third-party actor against Apple's Developer ID Application
/// anchor off the Endpoint Security authorization path. Results are cached by
/// cdhash, never by a caller-supplied Team ID.
final class DeveloperIDTrustValidator: @unchecked Sendable {
    static let shared = DeveloperIDTrustValidator()
    private let lock = NSLock()
    private var cache: [Data: Bool] = [:]
    private var appleImageCache: [Data: Bool] = [:]
    private var distributionCache: [Data: Bool] = [:]
    private var preparedOwningApps = Set<Data>()
    private var owningApps: [Data: CredentialAccessPolicy.ValidatedIdentity] = [:]

    func needsOwningAppPreparation(cdhash: Data) -> Bool {
        lock.withLock { !preparedOwningApps.contains(cdhash) }
    }

    func cachedOwningApp(cdhash: Data) -> CredentialAccessPolicy.ValidatedIdentity? {
        lock.withLock { owningApps[cdhash] }
    }

    /// Bind a validated helper image to a containing app signed by the same
    /// distribution team. No filesystem or certificate work occurs on AUTH.
    func prepareOwningApp(path: String, actorHash: Data, actorTeam: String?) {
        lock.withLock { _ = preparedOwningApps.insert(actorHash) }
        guard let actorTeam, !actorTeam.isEmpty, cachedValidation(cdhash: actorHash) == true,
              let range = path.range(of: ".app/") else { return }
        let appPath = String(path[..<range.lowerBound]) + ".app"
        guard isValidatedDistribution(path: appPath) else { return }
        var code: SecStaticCode?
        var information: CFDictionary?
        guard SecStaticCodeCreateWithPath(URL(fileURLWithPath: appPath) as CFURL, [], &code) == errSecSuccess,
              let code,
              SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &information) == errSecSuccess,
              let info = information as? [String: Any],
              info[kSecCodeInfoTeamIdentifier as String] as? String == actorTeam,
              let identifier = info[kSecCodeInfoIdentifier as String] as? String else { return }
        let identity = CredentialAccessPolicy.ValidatedIdentity(bundleID: identifier, teamID: actorTeam,
            signingValidated: true, isApplePlatform: false)
        lock.withLock { owningApps[actorHash] = identity }
    }

    func cachedValidation(cdhash: Data) -> Bool? {
        lock.withLock { distributionCache[cdhash] }
    }

    /// Own-store authorization also accepts Apple's Mac App Store distribution
    /// certificate, not merely Developer ID. Kernel IDs are compared separately.
    func isValidatedDistribution(path: String) -> Bool {
        var code: SecStaticCode?
        var information: CFDictionary?
        guard SecStaticCodeCreateWithPath(URL(fileURLWithPath: path) as CFURL, [], &code) == errSecSuccess,
              let code,
              SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &information) == errSecSuccess,
              let info = information as? [String: Any],
              let hash = info[kSecCodeInfoUnique as String] as? Data else { return false }
        if let cached = cachedValidation(cdhash: hash) { return cached }
        var requirement: SecRequirement?
        let text = "anchor apple generic and (certificate leaf[field.1.2.840.113635.100.6.1.13] exists or certificate leaf[field.1.2.840.113635.100.6.1.9] exists)"
        guard SecRequirementCreateWithString(text as CFString, [], &requirement) == errSecSuccess,
              let requirement else { return false }
        let flags = UInt32(kSecCSDoNotValidateResources) | (UInt32(1) << 30) | (UInt32(1) << 31)
        let valid = SecStaticCodeCheckValidity(code, SecCSFlags(rawValue: flags), requirement) == errSecSuccess
        lock.withLock { distributionCache[hash] = valid }
        return valid
    }

    /// Verify an exited parent's exact captured image, without querying a PID
    /// that may have exited or been reused by the time queued work runs.
    func isAppleImage(path: String, expectedHash: Data) -> Bool {
        if let cached = lock.withLock({ appleImageCache[expectedHash] }) { return cached }
        var code: SecStaticCode?
        var information: CFDictionary?
        var requirement: SecRequirement?
        guard SecStaticCodeCreateWithPath(URL(fileURLWithPath: path) as CFURL, [], &code) == errSecSuccess,
              let code,
              SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &information) == errSecSuccess,
              let info = information as? [String: Any],
              info[kSecCodeInfoUnique as String] as? Data == expectedHash,
              SecRequirementCreateWithString("anchor apple" as CFString, [], &requirement) == errSecSuccess,
              let requirement else { return false }
        let valid = SecStaticCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSDoNotValidateResources), requirement) == errSecSuccess
        lock.withLock { appleImageCache[expectedHash] = valid }
        return valid
    }

    func isValidated(path: String) -> Bool {
        var code: SecStaticCode?
        guard SecStaticCodeCreateWithPath(URL(fileURLWithPath: path) as CFURL, [], &code) == errSecSuccess,
              let code else { return false }
        var info: CFDictionary?
        guard SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess,
              let dict = info as? [String: Any],
              let cdhash = dict[kSecCodeInfoUnique as String] as? Data else { return false }
        if let cached = lock.withLock({ cache[cdhash] }) { return cached }

        var requirement: SecRequirement?
        let text = "anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.13] exists"
        guard SecRequirementCreateWithString(text as CFString, [], &requirement) == errSecSuccess,
              let requirement else { return false }
        // Security exposes these CSCommon flags to C but not Swift in every SDK.
        // Values are stable API constants: revocation 1<<30, expiration 1<<31.
        let enforceRevocation = UInt32(1) << 30
        let considerExpiration = UInt32(1) << 31
        let rawFlags = UInt32(kSecCSDoNotValidateResources)
            | enforceRevocation
            | considerExpiration
        let valid = SecStaticCodeCheckValidity(code, SecCSFlags(rawValue: rawFlags), requirement) == errSecSuccess
        lock.withLock { cache[cdhash] = valid }
        return valid
    }
}

// MARK: - RemediationEngine

/// Orchestrates automated threat response:
/// 1. Sends `SIGKILL` to the offending process
/// 2. Quarantines the threat file
/// 3. Quarantines persistence mechanisms (LaunchAgents / LaunchDaemons)
///
/// All methods are synchronous and must be called from a background queue
/// (never from the ES callback queue directly).
final class RemediationEngine {
    private static let programArgumentsKey = decode(
        "UHJvZ3JhbUFyZ3VtZW50cw=="
    )

    private static func decode(_ base64: String) -> String {
        guard let data = Data(base64Encoded: base64),
              let value = String(data: data, encoding: .utf8)
        else { preconditionFailure("Invalid encoded policy literal") }
        return value
    }

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
        processIdentity: ProcessInstanceIdentity? = nil,
        terminateProcess: Bool = true
    ) -> RemediationReport {
        var actions: [RemediationAction] = []

        // 1. Kill the offending process immediately
        if terminateProcess {
            actions.append(killProcess(pid: pid, expectedIdentity: processIdentity))
        }

        // 2. Quarantine the threat file. Never delete as a fallback: a failed
        // quarantine must remain recoverable and visible to the user.
        let quarantineResult = quarantineManager.quarantine(
            filePath:    threatPath,
            hash:        hash,
            threatName:  threatName,
            severity:    "critical",
            processPath: processPath,
            pid:         pid
        )
        let record: QuarantineRecord?
        let quarantineFailure: QuarantineFailure?
        switch quarantineResult {
        case .success(let value):
            record = value
            quarantineFailure = nil
        case .failure(let failure):
            record = nil
            quarantineFailure = failure
        }
        actions.append(RemediationAction(
            type:    .quarantineFile,
            target:  threatPath,
            success: record != nil,
            detail:  record != nil
                ? "Moved to quarantine vault"
                : (quarantineFailure?.statusLine ?? "Failed to quarantine — file was not deleted"),
            quarantineFailure: quarantineFailure
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

    private func killProcess(pid: Int32, expectedIdentity: ProcessInstanceIdentity?) -> RemediationAction {
        // Never kill init (PID 1) or the extension itself
        guard pid > 1 else {
            return RemediationAction(
                type: .killProcess, target: "PID \(pid)",
                success: false, detail: "Refused to kill PID ≤ 1"
            )
        }
        guard RansomwareTerminationPolicy.maySignalKill(
            expected: expectedIdentity,
            current: ProcessInstanceIdentity.capture(pid: pid)
        ) else {
            return RemediationAction(
                type: .killProcess, target: "PID \(pid)",
                success: false, detail: "Process identity changed; refused to signal reused PID"
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
                let result = quarantineManager.quarantine(
                    filePath: plistPath,
                    hash: hash,
                    threatName: "Persistence linked to quarantined threat",
                    severity: "high",
                    processPath: threatPath,
                    pid: 0
                )
                let succeeded: Bool
                let failure: QuarantineFailure?
                switch result {
                case .success: succeeded = true; failure = nil
                case .failure(let value): succeeded = false; failure = value
                }
                actions.append(RemediationAction(
                    type: .removeLaunchItem,
                    target: plistPath,
                    success: succeeded,
                    detail: succeeded
                        ? "Persistence plist moved to quarantine"
                        : "Failed to quarantine plist; left unchanged",
                    quarantineFailure: failure
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
                + (plist[Self.programArgumentsKey] as? [String] ?? [])
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
