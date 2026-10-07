// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation

/// Durable envelope for security findings produced by the system extension.
/// The payload remains the original JSON representation so older records can
/// be migrated without coupling the privileged store to app-only models.
public struct PersistedExtensionFinding: Codable, Sendable, Identifiable {
    public enum Kind: String, Codable, Sendable {
        case endpointEvent
        case threat
        case remediation
        case integrityViolation
        case privacyAlert
        case usbThreat
    }

    public let id: UUID
    public let kind: Kind
    public let timestamp: Date
    public let payload: Data

    public init(id: UUID = UUID(), kind: Kind, timestamp: Date = Date(), payload: Data) {
        self.id = id
        self.kind = kind
        self.timestamp = timestamp
        self.payload = payload
    }
}

/// Opaque, versioned transport for the app's incident/evidence state. The
/// extension owns the file and revision; the app owns the payload schema.
public struct PrivilegedIncidentStoreRecord: Codable, Sendable, Equatable {
    public static let currentSchemaVersion = 1

    public let schemaVersion: Int
    public let revision: UInt64
    public let payload: Data

    public init(
        schemaVersion: Int = Self.currentSchemaVersion,
        revision: UInt64,
        payload: Data
    ) {
        self.schemaVersion = schemaVersion
        self.revision = revision
        self.payload = payload
    }
}

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

    /// Returns the root-published health snapshot. The app never reads the
    /// privileged health file directly.
    func getExtensionHealth(reply: @escaping (Data) -> Void)

    /// Re-scans and moves a confirmed threat into Nick's protected vault.
    /// The encoded record lets the app update Quarantine immediately.
    func requestQuarantineFile(
        path: String,
        expectedThreatName: String,
        reply: @escaping (Bool, String?, Data?) -> Void
    )

    /// Clears a stale cached denial and permits the next authorization for the
    /// selected file. This is deliberately one-shot.
    func requestAllowFileOnce(path: String, reply: @escaping (Bool) -> Void)

    /// Promotes a reviewed heuristic finding to an explicit user block.
    func requestBlockReviewedFile(path: String, reply: @escaping (Bool) -> Void)

    /// Returns a bounded JSON array of important events recorded while the
    /// container app was closed.
    func getPersistedEvents(reply: @escaping (Data) -> Void)

    /// Returns the root-owned incident/evidence snapshot. An empty Data value
    /// means no privileged store has been created yet.
    func getIncidentStore(reply: @escaping (Data) -> Void)

    /// Creates the privileged store only when none exists. Repeating the call
    /// returns the existing record without overwriting it.
    func migrateIncidentStore(_ payload: Data, reply: @escaping (Bool, Data) -> Void)

    /// Replaces the privileged snapshot if the caller's revision is current.
    /// The reply always includes the authoritative record when available.
    func replaceIncidentStore(
        _ payload: Data,
        expectedRevision: UInt64,
        reply: @escaping (Bool, Data) -> Void
    )

    /// Authenticates a UI verdict before the app records actor `.user`.
    func authoriseIncidentVerdict(
        incidentID: String,
        action: String,
        reply: @escaping (Bool) -> Void
    )

    /// Instructs the extension to rebuild the FIM baseline from the current
    /// state of monitored paths. Used by the "Rebuild Baseline" button in
    /// `IntegrityView`.
    func requestRebuildFIMBaseline(reply: @escaping (Bool) -> Void)

    /// Accepts one durable FIM violation and advances its baseline only when
    /// the current file still matches the reviewed evidence.
    func acknowledgeFIMViolation(id: String, reply: @escaping (Bool) -> Void)

    /// Instructs the extension to deploy ransomware canary files into the
    /// user's common directories (Desktop, Documents, Downloads, Pictures).
    /// Useful when the user manually enables the Ransomware Shield from Smart Scan.
    func requestDeployCanaries(reply: @escaping (Bool) -> Void)

    func requestRestoreQuarantinedFile(id: String, reply: @escaping (Bool) -> Void)

    func requestDeleteQuarantinedFile(id: String, reply: @escaping (Bool) -> Void)
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

    /// Called by the extension when a TCC privacy permission is granted or
    /// revoked for a sensitive service (Phase 5+).
    /// - Parameter alertData: JSON-encoded `PrivacyAlert`.
    func reportPrivacyAlert(_ alertData: Data)

    /// Called by the extension when a threat is found on an external/removable
    /// volume during a background USB scan (Phase 5+).
    /// - Parameter threatData: JSON-encoded `USBThreat`.
    func reportUSBThreat(_ threatData: Data)
}
