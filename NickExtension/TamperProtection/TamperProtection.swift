// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation
import os

// MARK: - TamperProtection

/// Observes attempts to delete or replace Nick's own files.
///
/// Phase 3 is deliberately observe-only: AUTH handlers always allow the
/// operation and this component emits evidence. Identity-based enforcement,
/// identity-based enforcement and verified update/uninstall flows remain
/// Phase 6 work.
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
            "/Library/Application Support/com.ehsanazish.nick",
        ]

        // Also protect the running extension bundle itself (resolves symlinks)
        let bundlePath = Bundle.main.bundlePath
        if !bundlePath.isEmpty && !paths.contains(bundlePath) {
            paths.append(bundlePath)
        }

        paths.append(contentsOf: additionalPaths)
        self.protectedPaths = paths

    }

    // MARK: - Public API

    /// Phase 3 never denies an AUTH_UNLINK / AUTH_RENAME event.
    ///
    /// - Parameters:
    ///   - targetPath: The file or directory being deleted/renamed.
    ///   - actorPath:  Executable path of the process making the request.
    ///   - actorPid:   PID of the actor process.
    func shouldBlock(targetPath _: String, actorPath _: String, actorPid _: Int32) -> Bool {
        false
    }

    /// Notifies the protection module of an AUTH_UNLINK attempt for logging.
    func handleUnlinkEvent(targetPath: String, actorPath: String, actorPid: Int32) {
        guard isProtected(path: targetPath) else { return }
        onTamperAttempt?(.deleteProtectedPath(path: targetPath, actorPID: actorPid, actorPath: actorPath))
    }

    /// Notifies the protection module of an AUTH_RENAME attempt for logging.
    func handleRenameEvent(
        srcPath: String,
        destinationPath: String,
        actorPath: String,
        actorPid: Int32
    ) {
        let observedPath: String
        if isProtected(path: srcPath) {
            observedPath = srcPath
        } else if isProtected(path: destinationPath) {
            observedPath = destinationPath
        } else {
            return
        }
        onTamperAttempt?(.renameProtectedPath(path: observedPath, actorPID: actorPid, actorPath: actorPath))
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
