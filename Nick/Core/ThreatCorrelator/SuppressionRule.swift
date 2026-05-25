// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation

// MARK: - SuppressionType

/// The dimension along which a suppression rule matches an alert.
enum SuppressionType: String, Codable, CaseIterable {
    /// Suppress all alerts whose contributing signals originate from this process name.
    case processName
    /// Suppress all alerts whose contributing signals reference this file path prefix.
    case path
    /// Suppress all alerts whose correlation rule name (alert title) matches this value.
    case ruleName

    var displayName: String {
        switch self {
        case .processName: return "Process Name"
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

    init(id: UUID = UUID(), type: SuppressionType, value: String, note: String = "", createdAt: Date = Date()) {
        self.id = id
        self.type = type
        self.value = value
        self.note = note
        self.createdAt = createdAt
    }
}
