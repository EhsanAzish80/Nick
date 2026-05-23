// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation

// MARK: - FirewallAllowlistIssue

/// The specific problem found with a firewall-allowed app.
enum FirewallAllowlistIssue: Sendable, Equatable {

    /// The path in the firewall rule no longer exists on disk.
    case notInstalled

    /// The path exists but has no valid code signature.
    case unsigned

    /// The path is outside the standard macOS app locations.
    case nonStandardLocation

    /// Short description shown in the audit sub-section.
    var description: String {
        switch self {
        case .notInstalled:        return "app not found on disk"
        case .unsigned:            return "unsigned binary"
        case .nonStandardLocation: return "non-standard location"
        }
    }
}

// MARK: - FirewallAllowlistEntry

/// One entry parsed from `socketfilterfw --listapps`.
struct FirewallAllowlistEntry: Sendable, Identifiable, Equatable {

    /// The full path as it appears in the firewall database.
    let path: String

    /// Short app or binary name derived from the path.
    let displayName: String

    /// The problem found, or `nil` if the entry is clean.
    let issue: FirewallAllowlistIssue?

    var id: String { path }
    var hasIssue: Bool { issue != nil }
}

// MARK: - FirewallAllowlistResult

/// Aggregated result of checking every entry in the firewall allowlist.
struct FirewallAllowlistResult: Sendable {

    /// All parsed entries in path-sorted order.
    let entries: [FirewallAllowlistEntry]

    /// Entries that have at least one issue.
    var flagged: [FirewallAllowlistEntry] { entries.filter(\.hasIssue) }

    /// Entries with no issues.
    var clean: [FirewallAllowlistEntry] { entries.filter { !$0.hasIssue } }
}
