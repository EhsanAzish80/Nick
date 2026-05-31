// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation

// MARK: - SystemHealthScore

/// Phase 6.3 — Composite security health score for the dashboard.
///
/// `calculate(...)` is a pure function: given current security state it
/// returns a deterministic score and letter grade with a human-readable summary.
///
/// The score is intentionally *conservative* — every penalty is additive and
/// capped at reasonable maximums so a single misconfiguration cannot push the
/// score to zero.
struct SystemHealthScore: Sendable {

    // MARK: - Grade

    enum Grade: String, Sendable {
        case a = "A"
        case b = "B"
        case c = "C"
        case d = "D"
        case f = "F"

        init(score: Int) {
            switch score {
            case 90...100: self = .a
            case 70...89:  self = .b
            case 50...69:  self = .c
            case 30...49:  self = .d
            default:       self = .f
            }
        }

        /// SF Symbol name representing the grade.
        var symbolName: String {
            switch self {
            case .a: "checkmark.shield.fill"
            case .b: "shield.fill"
            case .c: "exclamationmark.shield.fill"
            case .d: "xmark.shield.fill"
            case .f: "xmark.shield.fill"
            }
        }

        var color: String {
            switch self {
            case .a: "green"
            case .b: "blue"
            case .c: "yellow"
            case .d: "orange"
            case .f: "red"
            }
        }
    }

    // MARK: - Properties

    /// 0–100.
    let score: Int
    let grade: Grade
    /// One-sentence human-readable summary.
    let summary: String
    /// Individual score components for the detail view.
    let breakdown: [Component]

    struct Component: Sendable {
        let name: String
        let rawScore: Int
        let maxScore: Int
        let description: String
    }

    // MARK: - Factory

    /// Calculates a health score from current security state.
    ///
    /// - Parameters:
    ///   - extensionActive:     Whether the NickExtension is actively running.
    ///   - signatureAgeDays:    Days since the last signature update (0 = today).
    ///   - threatsBlocked24h:   Threats blocked in the last 24 hours.
    ///   - quarantineCount:     Files currently in quarantine.
    ///   - fimViolations:       Open file-integrity violations.
    ///   - networkBlocksCount:  Network connections blocked by the filter.
    ///   - privacyAlerts:       Open privacy-permission alerts.
    static func calculate(
        extensionActive: Bool,
        signatureAgeDays: Int,
        threatsBlocked24h: Int,
        quarantineCount: Int,
        fimViolations: Int,
        networkBlocksCount: Int,
        privacyAlerts: Int
    ) -> SystemHealthScore {

        // ── Component 1: Extension active (30 points) ──────────────────────
        let extPoints = extensionActive ? 30 : 0
        let extDesc   = extensionActive
            ? "Real-time protection is active"
            : "Extension is not running — real-time protection is disabled"

        // ── Component 2: Signature freshness (20 points) ───────────────────
        let sigPoints: Int
        let sigDesc: String
        switch signatureAgeDays {
        case 0:
            sigPoints = 20
            sigDesc   = "Signatures are up to date (updated today)"
        case 1...3:
            sigPoints = 15
            sigDesc   = "Signatures are recent (\(signatureAgeDays) days old)"
        case 4...7:
            sigPoints = 10
            sigDesc   = "Signatures are slightly out of date (\(signatureAgeDays) days old)"
        default:
            sigPoints = 0
            sigDesc   = "Signatures are stale (\(signatureAgeDays) days old) — update recommended"
        }

        // ── Component 3: No active threats (25 points) ─────────────────────
        let threatPenalty = min(threatsBlocked24h * 5, 25)
        let threatPoints  = 25 - threatPenalty
        let threatDesc    = threatsBlocked24h == 0
            ? "No threats detected in the last 24 hours"
            : "\(threatsBlocked24h) threat(s) blocked in the last 24 hours"

        // ── Component 4: File integrity (15 points) ────────────────────────
        let fimPenalty = min(fimViolations * 5, 15)
        let fimPoints  = 15 - fimPenalty
        let fimDesc    = fimViolations == 0
            ? "No file integrity violations"
            : "\(fimViolations) active file integrity violation(s)"

        // ── Component 5: Privacy cleanliness (10 points) ──────────────────
        let privacyPenalty = min(privacyAlerts * 3, 10)
        let privacyPoints  = 10 - privacyPenalty
        let privacyDesc    = privacyAlerts == 0
            ? "No open privacy alerts"
            : "\(privacyAlerts) open privacy alert(s)"

        let total = extPoints + sigPoints + threatPoints + fimPoints + privacyPoints
        let clamped = max(0, min(100, total))
        let grade = Grade(score: clamped)

        let summary: String
        switch grade {
        case .a: summary = "Your Mac is fully protected"
        case .b: summary = "Protection is good with minor issues"
        case .c: summary = "Some security issues need attention"
        case .d: summary = "Significant security risks detected"
        case .f: summary = "Critical: real-time protection is disabled"
        }

        let breakdown = [
            Component(name: "Real-Time Protection", rawScore: extPoints,     maxScore: 30, description: extDesc),
            Component(name: "Signature Freshness",  rawScore: sigPoints,     maxScore: 20, description: sigDesc),
            Component(name: "Recent Threats",       rawScore: threatPoints,  maxScore: 25, description: threatDesc),
            Component(name: "File Integrity",       rawScore: fimPoints,     maxScore: 15, description: fimDesc),
            Component(name: "Privacy",              rawScore: privacyPoints, maxScore: 10, description: privacyDesc),
        ]

        return SystemHealthScore(score: clamped, grade: grade, summary: summary, breakdown: breakdown)
    }
}
