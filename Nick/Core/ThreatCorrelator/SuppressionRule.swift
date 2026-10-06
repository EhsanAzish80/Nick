// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation

// MARK: - SuppressionType

/// The dimension along which a suppression rule matches an alert.
enum SuppressionType: String, Codable, CaseIterable {
    /// Suppress all alerts whose contributing signals originate from this process name.
    case processName
    /// Suppress behavioral alerts from one signed executable identity.
    /// The stored value is `teamID|signingIdentifier`.
    case signedProcess
    /// Suppress all alerts whose contributing signals reference this file path prefix.
    case path
    /// Suppress all alerts whose correlation rule name (alert title) matches this value.
    case ruleName

    var displayName: String {
        switch self {
        case .processName: return "Process Name"
        case .signedProcess: return "Signed App"
        case .path:        return "Path"
        case .ruleName:    return "Rule Name"
        }
    }
}

// MARK: - SuppressionRule

/// A user-defined rule that prevents specific alerts from being raised.
///
/// Suppression rules are evaluated in `ThreatCorrelator` before an alert is
/// emitted. Any alert that matches at least one active rule is silently discarded
/// and a suppression event is logged via the alert pipeline (`emitAlert`).
struct SuppressionRule: Codable, Identifiable, Equatable {
    let id: UUID
    var type: SuppressionType
    /// The value to match against (case-insensitive substring match).
    var value: String
    /// Optional human-readable note explaining why this rule was added.
    var note: String
    let createdAt: Date
    /// Optional exact behavior context learned when the user approved an alert.
    /// A signed app performing a different action must still be reviewed.
    var behaviorContext: String?
    /// Learned approvals expire so long-running or newly compromised software
    /// cannot retain a permanent blind spot.
    var expiresAt: Date?

    init(
        id: UUID = UUID(),
        type: SuppressionType,
        value: String,
        note: String = "",
        createdAt: Date = Date(),
        behaviorContext: String? = nil,
        expiresAt: Date? = nil
    ) {
        self.id = id
        self.type = type
        self.value = value
        self.note = note
        self.createdAt = createdAt
        self.behaviorContext = behaviorContext
        self.expiresAt = expiresAt
    }

    var isActive: Bool {
        expiresAt.map { $0 > Date() } ?? true
    }

    static func contextFingerprint(for alert: ThreatAlert) -> String {
        let signalContexts = alert.contributingSignals.map { signal in
            let reason = signal.metadata["reason"] ?? signal.title
            return "\(signal.source.rawValue):\(reason.lowercased())"
        }.sorted()
        return ([alert.title.lowercased()] + signalContexts).joined(separator: "|")
    }
}

extension SuppressionRule {
    struct MigrationResult {
        let rules: [SuppressionRule]
        let notices: [String]
        let changed: Bool
    }

    /// Converts the pre-5.0 `teamID|executablePath` representation to the
    /// stable `teamID|signingIdentifier` representation. An unresolved legacy
    /// suppression is dropped fail-closed and surfaced for review.
    static func migrateLegacySignedProcessRules(
        _ rules: [SuppressionRule],
        signingStatus: (String) -> SigningStatus
    ) -> MigrationResult {
        var migrated: [SuppressionRule] = []
        var notices: [String] = []
        var changed = false

        for var rule in rules {
            guard rule.type == .signedProcess else {
                migrated.append(rule)
                continue
            }
            let components = rule.value.split(
                separator: "|", maxSplits: 1, omittingEmptySubsequences: false
            )
            guard components.count == 2 else {
                migrated.append(rule)
                continue
            }
            let teamID = String(components[0]).trimmingCharacters(in: .whitespaces)
            let legacyPath = String(components[1]).trimmingCharacters(in: .whitespaces)
            guard legacyPath.hasPrefix("/") else {
                migrated.append(rule)
                continue
            }

            guard let identity = SigningIdentity(status: signingStatus(legacyPath)),
                  identity.teamID.caseInsensitiveCompare(teamID) == .orderedSame else {
                notices.append("Removed the old signed-app suppression for \(legacyPath) because its signing identity could not be verified.")
                changed = true
                continue
            }
            rule.value = "\(identity.teamID)|\(identity.signingID)"
            migrated.append(rule)
            changed = true
        }
        return MigrationResult(rules: migrated, notices: notices, changed: changed)
    }
}
