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

enum IncidentVerdictValidationPolicy {
    private static let allowedActions: Set<String> = [
        "reviewed", "hidden", "dismissed", "resolved", "allowedOnce", "alwaysAllowed"
    ]

    static func accepts(
        incidentID: String,
        action: String,
        existingIncidentIDs: Set<String>,
        hasProtectionAuthorization: Bool
    ) -> Bool {
        guard UUID(uuidString: incidentID) != nil,
              allowedActions.contains(action),
              existingIncidentIDs.contains(incidentID) else { return false }
        let protectionReducingActions: Set<String> = ["dismissed", "allowedOnce", "alwaysAllowed"]
        return !protectionReducingActions.contains(action) || hasProtectionAuthorization
    }
}

enum ProtectionAuthorizationRightPolicy {
    static func isExpected(_ dictionary: [String: Any]) -> Bool {
        let value = dictionary["rule"]
        let rules = (value as? [String]) ?? (value as? String).map { [$0] } ?? []
        return dictionary["class"] as? String == "rule"
            && rules == ["authenticate-session-owner-or-admin"]
            && (dictionary["timeout"] as? NSNumber)?.intValue == 120
            && (dictionary["shared"] as? NSNumber)?.boolValue == false
    }
}

enum IncidentStoreWritePolicy {
    static func requiresAuthorization(previousPayload: Data, proposedPayload: Data) -> Bool {
        guard let old = try? JSONSerialization.jsonObject(with: previousPayload) as? [String: Any],
              let new = try? JSONSerialization.jsonObject(with: proposedPayload) as? [String: Any] else {
            return true
        }
        let oldIncidents = (old["incidents"] as? [[String: Any]]) ?? []
        let newIncidents = (new["incidents"] as? [[String: Any]]) ?? []
        let oldByID = Dictionary(uniqueKeysWithValues: oldIncidents.compactMap { incident -> (String, [String: Any])? in
            guard let id = incident["id"] as? String else { return nil }
            return (id, incident)
        })
        func protectedActions(_ incident: [String: Any]) -> Set<String> {
            let reducing: Set<String> = ["dismissed", "allowedOnce", "alwaysAllowed"]
            let actions = (incident["actions"] as? [[String: Any]]) ?? []
            return Set(actions.compactMap { $0["action"] as? String }).intersection(reducing)
        }
        for incident in newIncidents {
            guard let id = incident["id"] as? String else { return true }
            guard let previous = oldByID[id] else {
                if incident["state"] as? String == "allowed"
                    || incident["permanentlyDismissed"] as? Bool == true
                    || !protectedActions(incident).isEmpty {
                    return true
                }
                continue
            }
            if incident["state"] as? String == "allowed",
               previous["state"] as? String != "allowed" { return true }
            if incident["permanentlyDismissed"] as? Bool == true,
               previous["permanentlyDismissed"] as? Bool != true { return true }
            if !protectedActions(incident).isSubset(of: protectedActions(previous)) { return true }
        }
        func tombstoneKeys(_ object: [String: Any]) -> Set<String> {
            let values = (object["dismissalTombstones"] as? [[String: Any]]) ?? []
            return Set(values.compactMap { value in
                guard let incidentKey = value["incidentKey"] as? String else { return nil }
                return incidentKey + "|" + (value["alertDeduplicationKey"] as? String ?? "")
            })
        }
        return !tombstoneKeys(new).isSubset(of: tombstoneKeys(old))
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
    func requestAllowFileOnce(
        path: String,
        authorizationExternalForm: Data?,
        reply: @escaping (Bool) -> Void
    )

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
        authorizationExternalForm: Data?,
        reply: @escaping (Bool, Data) -> Void
    )

    /// Root-owned security preferences. The payload schema belongs to the app;
    /// the extension authenticates the caller and owns persistence/revisions.
    func getSecuritySettings(reply: @escaping (Data) -> Void)
    func migrateSecuritySettings(_ payload: Data, reply: @escaping (Bool, Data) -> Void)
    func replaceSecuritySettings(
        _ payload: Data,
        expectedRevision: UInt64,
        authorizationExternalForm: Data?,
        reply: @escaping (Bool, Data) -> Void
    )

    /// Validates that a verdict targets an incident in the privileged store.
    /// Security-reducing verdicts additionally require a user-authorized right.
    func validateIncidentVerdictTarget(
        incidentID: String,
        action: String,
        authorizationExternalForm: Data?,
        reply: @escaping (Bool) -> Void
    )

    /// Instructs the extension to rebuild the FIM baseline from the current
    /// state of monitored paths. Used by the "Rebuild Baseline" button in
    /// `IntegrityView`.
    func requestRebuildFIMBaseline(reply: @escaping (Bool) -> Void)

    /// Returns the authoritative root-owned set of pending integrity changes.
    /// This rehydrates the UI after either side of the XPC connection restarts.
    func getPendingFIMViolations(reply: @escaping (Data) -> Void)

    /// Accepts one durable FIM violation and advances its baseline only when
    /// the current file still matches the reviewed evidence.
    func acknowledgeFIMViolation(
        id: String,
        authorizationExternalForm: Data?,
        reply: @escaping (Bool) -> Void
    )

    /// Instructs the extension to deploy ransomware canary files into the
    /// user's common directories (Desktop, Documents, Downloads, Pictures).
    /// Useful when the user manually enables the Ransomware Shield from Smart Scan.
    func requestDeployCanaries(reply: @escaping (Bool) -> Void)

    func requestRestoreQuarantinedFile(
        id: String,
        authorizationExternalForm: Data?,
        reply: @escaping (Bool) -> Void
    )

    func requestDeleteQuarantinedFile(id: String, reply: @escaping (Bool) -> Void)

#if DEBUG
    /// Test hook: verifies that a form which was never granted Nick's right is refused.
    func debugValidateProtectionAuthorization(
        authorizationExternalForm: Data,
        reply: @escaping (Bool) -> Void
    )
#endif
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
