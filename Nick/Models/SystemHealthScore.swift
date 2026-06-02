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
    ///   - threatsBlocked24h:   Threats blocked in the last 24 hours.
    ///   - quarantineCount:     Files currently in quarantine.
    ///   - fimViolations:       Open file-integrity violations.
    ///   - networkBlocksCount:  Network connections blocked by the filter.
    ///   - privacyAlerts:       Open privacy-permission alerts.
    static func calculate(
        extensionActive: Bool,
        threatsBlocked24h: Int,
        quarantineCount: Int,
        fimViolations: Int,
        networkBlocksCount: Int,
        privacyAlerts: Int
    ) -> SystemHealthScore {

        // ── Component 1: Extension active (37 points) ──────────────────────
        let extPoints = extensionActive ? 37 : 0
        let extDesc   = extensionActive
            ? "Real-time protection is active"
            : "Extension is not running — real-time protection is disabled"

        // ── Component 2: No active threats (31 points) ─────────────────────
        let threatPenalty = min(threatsBlocked24h * 6, 31)
        let threatPoints  = 31 - threatPenalty
        let threatDesc    = threatsBlocked24h == 0
            ? "No threats detected in the last 24 hours"
            : "\(threatsBlocked24h) threat(s) blocked in the last 24 hours"

        // ── Component 3: File integrity (19 points) ────────────────────────
        let fimPenalty = min(fimViolations * 6, 19)
        let fimPoints  = 19 - fimPenalty
        let fimDesc    = fimViolations == 0
            ? "No file integrity violations"
            : "\(fimViolations) active file integrity violation(s)"

        // ── Component 4: Privacy cleanliness (13 points) ──────────────────
        let privacyPenalty = min(privacyAlerts * 4, 13)
        let privacyPoints  = 13 - privacyPenalty
        let privacyDesc    = privacyAlerts == 0
            ? "No open privacy alerts"
            : "\(privacyAlerts) open privacy alert(s)"

        let total = extPoints + threatPoints + fimPoints + privacyPoints
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
            Component(name: "Real-Time Protection", rawScore: extPoints,     maxScore: 37, description: extDesc),
            Component(name: "Recent Threats",       rawScore: threatPoints,  maxScore: 31, description: threatDesc),
            Component(name: "File Integrity",       rawScore: fimPoints,     maxScore: 19, description: fimDesc),
            Component(name: "Privacy",              rawScore: privacyPoints, maxScore: 13, description: privacyDesc),
        ]

        return SystemHealthScore(score: clamped, grade: grade, summary: summary, breakdown: breakdown)
    }
}
