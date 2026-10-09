// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation
import Security
import SystemConfiguration
import os

/// Validates a live Endpoint Security actor from its kernel audit token.
/// Endpoint Security's Team ID and signing ID fields select an allow-listed
/// requirement but never establish trust themselves. Results are cached by the
/// kernel cdhash plus identifier after one dynamic Apple-chain validation.
final class TamperActorValidator: @unchecked Sendable {
    static let shared = TamperActorValidator()

    private struct CacheKey: Hashable {
        let cdhash: Data
        let signingID: String
    }

    private let lock = NSLock()
    private var cache: [CacheKey: Bool] = [:]

    func validatesNickActor(auditToken: audit_token_t, identity: TamperActorIdentity) -> Bool {
        guard identity.teamID == TamperProtectionPolicy.nickTeamID,
              let signingID = identity.signingID,
              TamperProtectionPolicy.nickMaintenanceSigningIDs.contains(signingID)
        else { return false }

        var token = auditToken
        let tokenData = Data(bytes: &token, count: MemoryLayout<audit_token_t>.size)
        let attributes = [kSecGuestAttributeAudit: tokenData] as CFDictionary
        var code: SecCode?
        guard SecCodeCopyGuestWithAttributes(nil, attributes, [], &code) == errSecSuccess,
              let code,
              let cdhash = Self.cdhash(for: code)
        else { return false }

        let key = CacheKey(cdhash: cdhash, signingID: signingID)
        if let cached = lock.withLock({ cache[key] }) { return cached }

        let requirementText = "anchor apple generic and certificate leaf[subject.OU] = \""
            + TamperProtectionPolicy.nickTeamID
            + "\" and identifier \""
            + signingID
            + "\""
        var requirement: SecRequirement?
        guard SecRequirementCreateWithString(requirementText as CFString, [], &requirement) == errSecSuccess,
              let requirement
        else { return false }

        let valid = SecCodeCheckValidity(code, [], requirement) == errSecSuccess
        lock.withLock { cache[key] = valid }
        return valid
    }

    private static func cdhash(for code: SecCode) -> Data? {
        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess,
              let staticCode else { return nil }
        var info: CFDictionary?
        guard SecCodeCopySigningInformation(
            staticCode,
            SecCSFlags(rawValue: kSecCSSigningInformation),
            &info
        ) == errSecSuccess,
              let dictionary = info as? [String: Any]
        else { return nil }
        return dictionary[kSecCodeInfoUnique as String] as? Data
    }
}

enum TamperConsoleUserResolver {
    static func current() -> TamperConsoleUser? {
        var uid: uid_t = 0
        var gid: gid_t = 0
        guard let name = SCDynamicStoreCopyConsoleUser(nil, &uid, &gid) as String?,
              name != "loginwindow",
              let record = getpwuid(uid),
              let home = record.pointee.pw_dir
        else { return nil }
        return TamperConsoleUser(uid: uid, homeDirectory: String(cString: home))
    }
}

// MARK: - TamperProtection

/// Enforces deletion and replacement protection for Nick's own files.
///
/// Maintenance is allowed only for an identity-bearing Nick/Sparkle process,
/// Apple's package installer, or the narrow Finder move-to-Trash uninstall
/// flow. Every other actor is denied and reported.
///
/// Additionally `handleExecEvent(execPath:pid:)` watches for attempts to run
/// `systemextensionsctl` (the command-line tool used to uninstall system
/// extensions) and raises a warning.
final class TamperProtection: @unchecked Sendable {

    // MARK: - Types

    enum Disposition: Sendable, Equatable {
        case blocked
        case maintenance
        case documentedUninstall
    }

    enum TamperAttempt: Sendable {
        /// Attempt to delete a protected file/directory.
        case deleteProtectedPath(
            path: String, actorPID: Int32, actorPath: String,
            identity: TamperActorIdentity, disposition: Disposition
        )
        /// Attempt to rename/replace a protected file/directory.
        case renameProtectedPath(
            path: String, actorPID: Int32, actorPath: String,
            identity: TamperActorIdentity, disposition: Disposition
        )
        /// `systemextensionsctl` was executed.
        case systemExtensionsCtlExec(pid: Int32, isSensitive: Bool)
    }

    // MARK: - Configuration

    /// Paths whose deletion or replacement Nick observes.
    ///
    /// Populated at init from the running process's own bundle path and a set of
    /// well-known installation locations.
    private let protectedPaths: [String]

    var onTamperAttempt: ((TamperAttempt) -> Void)?

    private static let logger = Logger(
        subsystem: "com.ehsanazish.nick",
        category: "TamperProtection"
    )

    // MARK: - Init

    init(additionalPaths: [String] = []) {
        var paths: [String] = [
            // Protect Nick itself. Never protect the broad
            // /Library/SystemExtensions prefix because it also contains
            // extensions owned by unrelated applications.
            "/Applications/Nick.app",
        ]

        // Do not protect Nick's mutable Application Support directory here.
        // Health, event, database and incident-store updates use atomic
        // renames. Treating those expected writes as tampering makes the
        // persisted tamper event trigger itself recursively. Root ownership
        // and per-file permissions protect that state until identity-aware
        // self-protection is implemented.

        // Also protect the running extension bundle itself (resolves symlinks)
        let bundlePath = Bundle.main.bundlePath
        if !bundlePath.isEmpty && !paths.contains(bundlePath) {
            paths.append(bundlePath)
        }

        paths.append(contentsOf: additionalPaths)
        self.protectedPaths = paths

    }

    // MARK: - Public API

    func protects(path: String) -> Bool {
        isProtected(path: path)
    }

    func shouldBlockUnlink(
        targetPath: String,
        identity: TamperActorIdentity,
        nickIdentityValidated: Bool
    ) -> Bool {
        isProtected(path: targetPath) && !TamperProtectionPolicy.isTrustedMaintenanceActor(
            identity,
            nickIdentityValidated: nickIdentityValidated
        )
    }

    func shouldBlockRename(
        sourcePath: String,
        destinationPath: String,
        identity: TamperActorIdentity,
        nickIdentityValidated: Bool,
        consoleUser: TamperConsoleUser?
    ) -> Bool {
        guard isProtected(path: sourcePath) || isProtected(path: destinationPath) else { return false }
        if TamperProtectionPolicy.isTrustedMaintenanceActor(
            identity,
            nickIdentityValidated: nickIdentityValidated
        ) { return false }
        return !TamperProtectionPolicy.isDocumentedFinderUninstall(
            sourcePath: sourcePath,
            destinationPath: destinationPath,
            identity: identity,
            consoleUser: consoleUser
        )
    }

    func shouldBlockWrite(
        targetPath: String,
        identity: TamperActorIdentity,
        nickIdentityValidated: Bool
    ) -> Bool {
        isProtected(path: targetPath) && !TamperProtectionPolicy.isTrustedMaintenanceActor(
            identity,
            nickIdentityValidated: nickIdentityValidated
        )
    }

    /// Notifies the protection module of an AUTH_UNLINK attempt for logging.
    func handleUnlinkEvent(
        targetPath: String,
        actorPath: String,
        actorPid: Int32,
        identity: TamperActorIdentity,
        blocked: Bool
    ) {
        guard isProtected(path: targetPath) else { return }
        onTamperAttempt?(.deleteProtectedPath(
            path: targetPath,
            actorPID: actorPid,
            actorPath: actorPath,
            identity: identity,
            disposition: blocked ? .blocked : .maintenance
        ))
    }

    /// Notifies the protection module of an AUTH_RENAME attempt for logging.
    func handleRenameEvent(
        srcPath: String,
        destinationPath: String,
        actorPath: String,
        actorPid: Int32,
        identity: TamperActorIdentity,
        blocked: Bool,
        consoleUser: TamperConsoleUser?
    ) {
        let observedPath: String
        if isProtected(path: srcPath) {
            observedPath = srcPath
        } else if isProtected(path: destinationPath) {
            observedPath = destinationPath
        } else {
            return
        }
        let disposition: Disposition
        if blocked {
            disposition = .blocked
        } else if TamperProtectionPolicy.isDocumentedFinderUninstall(
            sourcePath: srcPath,
            destinationPath: destinationPath,
            identity: identity,
            consoleUser: consoleUser
        ) {
            disposition = .documentedUninstall
        } else {
            disposition = .maintenance
        }
        onTamperAttempt?(.renameProtectedPath(
            path: observedPath,
            actorPID: actorPid,
            actorPath: actorPath,
            identity: identity,
            disposition: disposition
        ))
    }

    func handleWriteEvent(
        targetPath: String,
        actorPath: String,
        actorPid: Int32,
        identity: TamperActorIdentity,
        blocked: Bool
    ) {
        guard isProtected(path: targetPath) else { return }
        onTamperAttempt?(.renameProtectedPath(
            path: targetPath,
            actorPID: actorPid,
            actorPath: actorPath,
            identity: identity,
            disposition: blocked ? .blocked : .maintenance
        ))
    }

    /// Call from `AUTH_EXEC` / `NOTIFY_EXEC` handler.
    ///
    /// Flags attempts to run `systemextensionsctl` (uninstall vector).
    func handleExecEvent(execPath: String, pid: Int32, args: [String] = []) {
        guard execPath.hasSuffix("systemextensionsctl") else { return }
        let commands = Set(args.dropFirst().map { $0.lowercased() })
        let isSensitive = !commands.isDisjoint(with: ["uninstall", "reset"])
        Self.logger.info("TamperProtection: system extension management observed pid=\(pid)")
        onTamperAttempt?(.systemExtensionsCtlExec(pid: pid, isSensitive: isSensitive))
    }

    // MARK: - Private

    private func isProtected(path: String) -> Bool {
        let standardized = URL(fileURLWithPath: path).standardizedFileURL.path
        return protectedPaths.contains { protected in
            let root = URL(fileURLWithPath: protected).standardizedFileURL.path
            return standardized == root || standardized.hasPrefix(root + "/")
        }
    }

}
