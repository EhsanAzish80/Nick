// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation

// MARK: - SystemCheckType

/// Identifies each individual security configuration check performed by `SystemAuditor`.
enum SystemCheckType: String, Codable, Sendable, CaseIterable {

    /// System Integrity Protection — verified via `csrutil status`.
    case sip = "sip"

    /// FileVault full-disk encryption — verified via `fdesetup status`.
    case fileVault = "fileVault"

    /// Gatekeeper app notarisation enforcement — verified via `spctl --status`.
    case gatekeeper = "gatekeeper"

    /// Application Firewall global state — verified via `socketfilterfw`.
    case firewall = "firewall"

    /// Firewall stealth mode (drops unsolicited ICMP/TCP) — verified via `socketfilterfw`.
    case firewallStealth = "firewallStealth"

    /// XProtect definition freshness — compared against a 30-day threshold.
    case xprotect = "xprotect"

    /// Automatic security update checks — verified via `defaults read`.
    case automaticUpdates = "automaticUpdates"

    /// Remote Login (SSH) service state — verified via `systemsetup`.
    case remoteLogin = "remoteLogin"

    // MARK: - Display Helpers

    /// Human-readable label for the check.
    var displayName: String {
        switch self {
        case .sip:              return "System Integrity Protection"
        case .fileVault:        return "FileVault Encryption"
        case .gatekeeper:       return "Gatekeeper"
        case .firewall:         return "Application Firewall"
        case .firewallStealth:  return "Firewall Stealth Mode"
        case .xprotect:         return "XProtect Definitions"
        case .automaticUpdates: return "Automatic Updates"
        case .remoteLogin:      return "Remote Login (SSH)"
        }
    }

    /// Whether a `.fail` on this check should produce a `.critical` signal.
    var isCritical: Bool {
        switch self {
        case .sip, .fileVault, .gatekeeper: return true
        default: return false
        }
    }
}

// MARK: - CheckStatus

/// Outcome of a single `SystemAuditor` check.
enum CheckStatus: String, Codable, Sendable, CaseIterable {

    /// The check passed — the expected security state is in place.
    case pass = "pass"

    /// The check failed — the security control is missing or disabled.
    case fail = "fail"

    /// The check reveals a non-ideal but non-critical configuration.
    case warning = "warning"

    /// The check could not be completed (permissions, tool unavailable, etc.).
    case unknown = "unknown"

    // MARK: - Helpers

    /// SF Symbol name for this status.
    var systemImage: String {
        switch self {
        case .pass:    return "checkmark.circle.fill"
        case .fail:    return "xmark.circle.fill"
        case .warning: return "exclamationmark.triangle.fill"
        case .unknown: return "questionmark.circle"
        }
    }

    /// Maps this status to the appropriate signal severity.
    func severity(for checkType: SystemCheckType) -> SignalSeverity {
        switch self {
        case .pass:    return .info
        case .unknown: return .low
        case .warning: return .medium
        case .fail:    return checkType.isCritical ? .critical : .high
        }
    }
}

// MARK: - SystemCheckResult

/// The result of one security configuration check performed by `SystemAuditor`.
///
/// Immutable value type that captures both the outcome of the check and
/// enough context for the UI and `ThreatCorrelator` to act on it.
/// `recommendation` is populated whenever `status` is `.fail` or `.warning`.
struct SystemCheckResult: Sendable, Codable, Identifiable, Equatable {

    // MARK: - Properties

    /// Stable identifier for this result within a scan session.
    let id: UUID

    /// Which check produced this result.
    let check: SystemCheckType

    /// Outcome of the check.
    let status: CheckStatus

    /// The value actually observed (e.g. "disabled", "FileVault is Off").
    let currentValue: String

    /// The value expected for a secure configuration.
    let expectedValue: String

    /// Human-readable explanation of what was checked and what was found.
    let description: String

    /// Actionable remediation steps shown when `status` is `.fail` or `.warning`.
    let recommendation: String?

    // MARK: - Convenience

    /// Derives the `SignalSeverity` implied by this result.
    var impliedSeverity: SignalSeverity {
        status.severity(for: check)
    }
}
