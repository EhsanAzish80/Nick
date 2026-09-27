// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation

/// Plain-language copy for the Simple alert sheet. It fills the gaps
/// `UserFacingAlertBuilder` leaves (what Nick actually did, the reassurance
/// line, the status word, the one-line technical summary) without changing
/// how alerts are built or scored.
struct SimpleAlertCopy: Equatable {

    enum Status: String, Equatable {
        case blocked = "Blocked"
        case threat = "Threat"
        case warning = "Warning"
        case info = "Info"
    }

    enum Tone: Equatable { case danger, warning, safe }

    let title: String
    let subline: String
    let status: Status
    let tone: Tone
    let whatHappened: String
    let whatNickDid: String
    let whatToDo: String
    /// "rule · confidence · signer", shown collapsed under Technical details.
    let technicalSummary: String

    static func make(
        alert: ThreatAlert,
        user: UserFacingAlert,
        isQuarantined: Bool,
        fileStillPresent: Bool,
        now: Date = Date()
    ) -> SimpleAlertCopy {
        let when = HomeFormatting.dayAndTime(alert.lastSeen, now: now)

        let status: Status
        let tone: Tone
        let title: String
        let reassurance: String
        switch (isQuarantined, user.severity) {
        case (true, _):
            status = .blocked; tone = .danger
            title = "Nick stopped a harmful app"
            reassurance = "It can’t run from Quarantine"
        case (false, .critical):
            status = .threat; tone = .danger
            title = user.headline
            reassurance = fileStillPresent ? "Take a look now" : "It’s no longer on your Mac"
        case (false, .warning):
            status = .warning; tone = .warning
            title = user.headline
            reassurance = "Probably fine, but worth a look"
        case (false, .safe):
            status = .info; tone = .safe
            title = user.headline
            reassurance = "No action needed"
        }

        let didText: String
        if isQuarantined {
            didText = "Moved it to Quarantine, where it can’t open or change anything. Nothing was deleted."
        } else if !fileStillPresent, alert.detectedFilePath != nil {
            didText = "Noticed it and kept watching. The file has since been removed."
        } else {
            switch user.severity {
            case .critical: didText = "Flagged it and kept watching. Nothing was deleted, so you decide what happens next."
            case .warning:  didText = "Made a note of it and kept watching."
            case .safe:     didText = "Checked it and found nothing to act on."
            }
        }

        let todo: String
        if isQuarantined {
            todo = "Nothing right now. If you don’t recognise the app, delete it."
        } else if !user.recommendedAction.isEmpty {
            todo = user.recommendedAction
        } else {
            todo = user.severity == .critical
                ? "If you didn’t install this, move it to the Trash."
                : "Nothing, unless this surprises you."
        }

        return SimpleAlertCopy(
            title: title,
            subline: "\(when) · \(reassurance)",
            status: status,
            tone: tone,
            whatHappened: user.explanation.isEmpty ? user.headline : user.explanation,
            whatNickDid: didText,
            whatToDo: todo,
            technicalSummary: technicalSummary(for: alert)
        )
    }

    static func technicalSummary(for alert: ThreatAlert) -> String {
        let rule = alert.contributingSignals.lazy
            .compactMap { $0.metadata["rule"] ?? $0.metadata["yaraRules"] }
            .first { !$0.isEmpty } ?? alert.title
        let confidence = "\(Int((alert.score * 100).rounded()))%"
        let signer: String
        switch alert.contributingSignals.lazy.compactMap(\.processInfo).first?.signingStatus {
        case .signed(let teamID)?: signer = teamID == "APPLE_PLATFORM" ? "Apple" : "Team \(teamID)"
        case .adHoc?:              signer = "ad-hoc"
        case .unsigned?:           signer = "unsigned"
        case .invalid?:            signer = "invalid signature"
        default:                   signer = "signer unknown"
        }
        return [rule, confidence, signer].joined(separator: " · ")
    }
}
