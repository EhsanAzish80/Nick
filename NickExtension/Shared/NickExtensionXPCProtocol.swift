// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation

// MARK: - NickExtensionXPCProtocol (Container App → Extension)

/// XPC protocol exposed **by the extension** to the container app.
///
/// The container app calls these methods to query status or request actions
/// from the System Extension. All reply blocks execute on the caller's queue.
///
/// This protocol is compiled into **both** targets. Add both targets to this
/// file's "Target Membership" in Xcode.
@objc public protocol NickExtensionXPCProtocol {

    /// Returns whether the ES client is initialised and actively subscribed.
    func getStatus(reply: @escaping (Bool) -> Void)

    /// Requests an on-demand scan of the file at `path`.
    /// - Parameters:
    ///   - path: Absolute path to the file or directory to scan.
    ///   - reply: `(success, errorDescription)` — `errorDescription` is `nil` on success.
    func requestScan(path: String, reply: @escaping (Bool, String?) -> Void)
}

// MARK: - NickAppXPCProtocol (Extension → Container App)

/// XPC protocol exposed **by the container app** to the extension.
///
/// The extension calls these methods to push events and status updates to the
/// container app without the app having to poll.
///
/// This protocol is compiled into **both** targets. Add both targets to this
/// file's "Target Membership" in Xcode.
@objc public protocol NickAppXPCProtocol {

    /// Called by the extension for every ES event it observes.
    /// - Parameter eventData: JSON-encoded `ESEvent`.
    func reportEvent(_ eventData: Data)

    /// Called by the extension when it detects a confirmed threat.
    /// - Parameter threatData: JSON-encoded payload (Phase 2+).
    func reportThreat(_ threatData: Data)

    /// Called by the extension after completing the remediation pipeline for a threat.
    /// - Parameter reportData: JSON-encoded `RemediationReport`.
    func reportRemediationAction(_ reportData: Data)

    /// Called by the extension when a File Integrity Monitor violation is detected.
    /// - Parameter violationData: JSON-encoded `IntegrityViolation`.
    func reportIntegrityViolation(_ violationData: Data)

    /// Called by the extension when its running state changes.
    /// - Parameter isActive: `true` if the ES client is running.
    func reportStatusChange(_ isActive: Bool)
}
