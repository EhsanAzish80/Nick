// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation
import os

// MARK: - TamperProtection

/// Phase 6.4 — Protects Nick's own files from deletion or replacement.
///
/// `EventHandler` calls `shouldBlock(targetPath:actorPath:actorPid:)` from
/// `AUTH_UNLINK` and `AUTH_RENAME` handlers. If the target is one of Nick's
/// protected paths and the actor is **not** a trusted system process or Nick
/// itself, the method returns `true` and the event is denied.
///
/// Additionally `handleExecEvent(execPath:pid:)` watches for attempts to run
/// `systemextensionsctl` (the command-line tool used to uninstall system
/// extensions) and raises a warning.
final class TamperProtection: @unchecked Sendable {

    // MARK: - Types

    enum TamperAttempt: Sendable {
        /// Attempt to delete a protected file/directory.
        case deleteProtectedPath(path: String, actorPID: Int32, actorPath: String)
        /// Attempt to rename/replace a protected file/directory.
        case renameProtectedPath(path: String, actorPID: Int32, actorPath: String)
        /// `systemextensionsctl` was executed.
        case systemExtensionsCtlExec(pid: Int32, args: String)
    }

    // MARK: - Configuration

    /// Paths that Nick will block deletions / renames on.
    ///
    /// Populated at init from the running process's own bundle path and a set of
    /// well-known installation locations.
    private let protectedPaths: [String]

    /// Actor paths allowed via exact match (Apple system update tooling).
    private let trustedActorExact: Set<String> = [
        "/usr/sbin/installer",
        "/System/Library/PrivateFrameworks/PackageKit.framework/Versions/A/XPCServices/package_script_service.xpc/Contents/MacOS/package_script_service",
        "/System/Library/CoreServices/Software Update.app/Contents/MacOS/Software Update",
    ]

    /// Actor path *prefixes* allowed — Nick's own processes use this so that
    /// in-app updates and the helper can touch Nick's files without being blocked.
    private let trustedActorPrefixes: [String]

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
            "/Library/Application Support/com.ehsanazish.nick",
        ]

        // Also protect the running extension bundle itself (resolves symlinks)
        let bundlePath = Bundle.main.bundlePath
        if !bundlePath.isEmpty && !paths.contains(bundlePath) {
            paths.append(bundlePath)
        }

        paths.append(contentsOf: additionalPaths)
        self.protectedPaths = paths

        // Build trusted-actor prefixes: any executable *inside* Nick.app is
        // allowed to modify protected paths (in-app updater, helper, etc.).
        // We include both the canonical install location and the running bundle
        // so development builds work correctly too.
        var prefixes: [String] = ["/Applications/Nick.app/"]
        if !bundlePath.isEmpty {
            // Resolve symlinks so staging/sandbox paths are also covered.
            let resolved = (bundlePath as NSString)
                .standardizingPath
                .appending("/")
            if !prefixes.contains(resolved) {
                prefixes.append(resolved)
            }
        }
        self.trustedActorPrefixes = prefixes
    }

    // MARK: - Public API

    /// Returns `true` when the AUTH_UNLINK / AUTH_RENAME event should be **denied**.
    ///
    /// - Parameters:
    ///   - targetPath: The file or directory being deleted/renamed.
    ///   - actorPath:  Executable path of the process making the request.
    ///   - actorPid:   PID of the actor process.
    func shouldBlock(targetPath: String, actorPath: String, actorPid: Int32) -> Bool {
        guard isProtected(path: targetPath) else { return false }
        guard !isTrusted(actorPath: actorPath) else { return false }

        Self.logger.warning(
            "TamperProtection: blocked modification of '\(targetPath)' by pid=\(actorPid) (\(actorPath))"
        )
        return true
    }

    /// Notifies the protection module of an AUTH_UNLINK attempt for logging.
    func handleUnlinkEvent(targetPath: String, actorPath: String, actorPid: Int32) {
        guard isProtected(path: targetPath), !isTrusted(actorPath: actorPath) else { return }
        onTamperAttempt?(.deleteProtectedPath(path: targetPath, actorPID: actorPid, actorPath: actorPath))
    }

    /// Notifies the protection module of an AUTH_RENAME attempt for logging.
    func handleRenameEvent(srcPath: String, actorPath: String, actorPid: Int32) {
        guard isProtected(path: srcPath), !isTrusted(actorPath: actorPath) else { return }
        onTamperAttempt?(.renameProtectedPath(path: srcPath, actorPID: actorPid, actorPath: actorPath))
    }

    /// Call from `AUTH_EXEC` / `NOTIFY_EXEC` handler.
    ///
    /// Flags attempts to run `systemextensionsctl` (uninstall vector).
    func handleExecEvent(execPath: String, pid: Int32, args: String = "") {
        guard execPath.hasSuffix("systemextensionsctl") else { return }
        Self.logger.warning("TamperProtection: systemextensionsctl exec detected pid=\(pid)")
        onTamperAttempt?(.systemExtensionsCtlExec(pid: pid, args: args))
    }

    // MARK: - Private

    private func isProtected(path: String) -> Bool {
        let standardized = URL(fileURLWithPath: path).standardizedFileURL.path
        return protectedPaths.contains { protected in
            let root = URL(fileURLWithPath: protected).standardizedFileURL.path
            return standardized == root || standardized.hasPrefix(root + "/")
        }
    }

    /// Returns `true` when `actorPath` belongs to a trusted process.
    ///
    /// Two checks, in order:
    /// 1. **Prefix match** — any executable inside Nick.app itself is trusted
    ///    (covers the in-app updater, helper daemon, and development builds).
    /// 2. **Exact match** — well-known Apple system installers.
    private func isTrusted(actorPath: String) -> Bool {
        if trustedActorPrefixes.contains(where: { actorPath.hasPrefix($0) }) { return true }
        return trustedActorExact.contains(actorPath)
    }
}
