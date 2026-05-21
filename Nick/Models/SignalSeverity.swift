// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation

// MARK: - SignalSeverity

/// Ordered severity classification for threat signals emitted by Nick monitors.
///
/// Severity drives notification urgency, UI presentation colour, and
/// `ThreatCorrelator` scoring weights. Use `.info` for baseline observations
/// that require no user action, and `.critical` only for immediately
/// actionable threats (SIP disabled, active reverse shell, etc.).
///
/// - Note: Conforms to `Comparable` — `SignalSeverity.info < .critical`
///         always evaluates to `true`.
enum SignalSeverity: Int, Codable, Sendable, Comparable, CaseIterable {

    // MARK: - Cases

    /// Informational baseline observation; no action required.
    case info = 0

    /// Low-probability or low-impact finding; logged but not alerted.
    case low = 1

    /// Suspicious activity requiring investigation.
    case medium = 2

    /// High-confidence threat indicator requiring prompt user attention.
    case high = 3

    /// Confirmed or near-certain active threat requiring immediate action.
    case critical = 4

    // MARK: - Comparable

    static func < (lhs: SignalSeverity, rhs: SignalSeverity) -> Bool {
        lhs.rawValue < rhs.rawValue
    }

    // MARK: - Display Helpers

    /// Human-readable label suitable for UI presentation.
    var displayName: String {
        switch self {
        case .info:     return "Info"
        case .low:      return "Low"
        case .medium:   return "Medium"
        case .high:     return "High"
        case .critical: return "Critical"
        }
    }

    /// SF Symbol name representing this severity level.
    var systemImage: String {
        switch self {
        case .info:     return "info.circle"
        case .low:      return "exclamationmark.circle"
        case .medium:   return "exclamationmark.triangle"
        case .high:     return "exclamationmark.triangle.fill"
        case .critical: return "xmark.shield.fill"
        }
    }
}
