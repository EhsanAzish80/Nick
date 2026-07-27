// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation

// MARK: - UserFacingAlert

/// A consumer-friendly wrapper around a `ThreatAlert`.
///
/// Phase 4 detection engines produce highly technical output — process IDs,
/// file paths, entropy values, behavioral score breakdowns. `UserFacingAlert`
/// translates that output into plain language that a non-technical Mac user
/// can understand and act on immediately.
///
/// **Two-tier display contract:**
/// - **Simple mode** (default): show `headline` and `explanation` only.
///   No PIDs, no paths, no scores — just what happened and what to do.
/// - **Technical mode** (opt-in via Settings): surface `technicalDetail`
///   inline so power users see the full correlated signal context.
///
/// Build from a `ThreatAlert` using `UserFacingAlertBuilder.build(from:)`.
struct UserFacingAlert: Identifiable, Sendable {

    // MARK: - Properties

    /// Stable identifier — copied from the source `ThreatAlert.id`.
    let id: UUID

    /// Short, plain-English headline. Maximum one sentence.
    /// **Must not contain** process paths, file paths, PIDs, IP addresses,
    /// or SHA-256 hashes — those belong in `technicalDetail`.
    let headline: String

    /// 2–3 sentence plain-English explanation.
    /// Answers: what happened / why it matters / what Nick did.
    let explanation: String

    /// A short confidence-aware assessment, such as "Likely safe" or
    /// "Needs your review". This is intentionally different from detector
    /// severity: it tells a person what Nick actually knows.
    let assessment: String

    /// One concrete next step. This must never be a generic "investigate"
    /// instruction or imply that Nick blocked something when it only observed it.
    let recommendedAction: String

    /// Consumer-facing severity classification.
    let severity: AlertSeverity

    /// Ordered list of actions the user can take.
    let actions: [AlertAction]

    /// The full `ThreatAlert` — visible only in technical mode or when the
    /// user explicitly taps "Show Details".
    let technicalDetail: ThreatAlert

    /// When the alert was raised.
    let timestamp: Date

    // MARK: - Severity

    enum AlertSeverity: String, Sendable {
        /// No immediate threat — informational or resolved.
        case safe
        /// Suspicious activity worth reviewing; may not be harmful.
        case warning
        /// Active or confirmed threat requiring immediate action.
        case critical
    }

    // MARK: - Actions

    enum AlertAction: String, Sendable, Identifiable {
        case keepBlocked
        case allowOnce
        case quarantine
        case showDetails
        case dismiss

        var id: String { rawValue }

        var label: String {
            switch self {
            case .keepBlocked:  return "Keep Blocked"
            case .allowOnce:    return "Allow Once"
            case .quarantine:   return "Quarantine"
            case .showDetails:  return "Show Details"
            case .dismiss:      return "Dismiss"
            }
        }

        var systemImage: String {
            switch self {
            case .keepBlocked:  return "shield.fill"
            case .allowOnce:    return "checkmark.circle"
            case .quarantine:   return "lock.fill"
            case .showDetails:  return "info.circle"
            case .dismiss:      return "xmark"
            }
        }

        var isDestructive: Bool { self == .allowOnce }
    }
}
