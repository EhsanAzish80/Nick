// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation

/// One presentation model for Nick's top-level protection state.
///
/// Views must not infer "blocked" from severity: only recorded remediation
/// outcomes may use that word. Review-only and observed activity are excluded
/// by the caller before this value is calculated.
struct ProtectionStatus: Equatable, Sendable {
    enum State: String, Equatable, Sendable {
        case protected = "Protected"
        case attentionNeeded = "Attention needed"
        case threatBlocked = "Threat blocked"
        case remediationNeeded = "Remediation needed"
        case sensorProblem = "Sensor problem"
    }

    let state: State
    let count: Int

    static func evaluate(
        actionableAlerts: [ThreatAlert],
        incidents: [SecurityIncident],
        auditIssueCount: Int,
        sensorRunning: Bool
    ) -> ProtectionStatus {
        let count = actionableAlerts.count + max(0, auditIssueCount)
        guard sensorRunning else {
            return ProtectionStatus(state: .sensorProblem, count: count)
        }

        let relevant = incidents.filter { incident in
            actionableAlerts.contains { $0.id == incident.alert.id }
        }
        if relevant.contains(where: { incident in
            incident.actions.contains { $0.action == .quarantineFailed }
                || incident.alert.contributingSignals.contains {
                    $0.metadata["remediationStatus"] == "quarantine-failed"
                }
        }) {
            return ProtectionStatus(state: .remediationNeeded, count: max(1, count))
        }
        if relevant.contains(where: { incident in
            incident.actions.contains { $0.action == .quarantined }
                || incident.alert.contributingSignals.contains {
                    $0.metadata["tamperDisposition"] == "blocked"
                }
        }) {
            return ProtectionStatus(state: .threatBlocked, count: max(1, count))
        }
        if count > 0 {
            return ProtectionStatus(state: .attentionNeeded, count: count)
        }
        return ProtectionStatus(state: .protected, count: 0)
    }
}

/// The only user-facing presentation of a top-level protection status.
///
/// This type deliberately depends on `ProtectionStatus` alone. Individual
/// screens may add contextual detail below it, but they must not reinterpret
/// the state, invent a count, or select their own severity treatment.
struct ProtectionStatusPresentation: Equatable, Sendable {
    enum Tone: Equatable, Sendable {
        case protected
        case attention
        case critical
        case unavailable
    }

    let state: ProtectionStatus.State
    let headlineText: String
    let countText: String?
    let tone: Tone
    let systemImage: String

    init(status: ProtectionStatus, locale: Locale = .current) {
        state = status.state
        let count = DisplayNumber.count(max(0, status.count), locale: locale)
        switch status.state {
        case .protected:
            headlineText = "Protected"
            countText = nil
            tone = .protected
            systemImage = "checkmark.shield.fill"
        case .attentionNeeded:
            headlineText = "Attention needed"
            countText = "\(count) items need review"
            tone = .attention
            systemImage = "exclamationmark.shield.fill"
        case .threatBlocked:
            headlineText = "Threat blocked"
            countText = "\(count) items"
            tone = .critical
            systemImage = "hand.raised.fill"
        case .remediationNeeded:
            headlineText = "Remediation needed"
            countText = "\(count) items"
            tone = .critical
            systemImage = "exclamationmark.triangle.fill"
        case .sensorProblem:
            headlineText = "Protection component unavailable"
            countText = nil
            tone = .unavailable
            systemImage = "exclamationmark.triangle.fill"
        }
    }

    var displayText: String {
        guard let countText else { return headlineText }
        return "\(headlineText) · \(countText)"
    }
}

/// Small, named adapters keep all five status surfaces testable without
/// allowing any of them to add local headline/count logic.
protocol ProtectionStatusPresenting: Sendable {
    var presentation: ProtectionStatusPresentation { get }
}

struct SimpleHomeProtectionStatusModel: ProtectionStatusPresenting {
    let presentation: ProtectionStatusPresentation
    init(status: ProtectionStatus) { presentation = .init(status: status) }
}

struct SimpleActivityProtectionStatusModel: ProtectionStatusPresenting {
    let presentation: ProtectionStatusPresentation
    init(status: ProtectionStatus) { presentation = .init(status: status) }
}

struct AdvancedOverviewProtectionStatusModel: ProtectionStatusPresenting {
    let presentation: ProtectionStatusPresentation
    init(status: ProtectionStatus) { presentation = .init(status: status) }
}

struct SmartScanProtectionStatusModel: ProtectionStatusPresenting {
    let presentation: ProtectionStatusPresentation
    init(status: ProtectionStatus) { presentation = .init(status: status) }
}

struct SystemAuditProtectionStatusModel: ProtectionStatusPresenting {
    let presentation: ProtectionStatusPresentation
    init(status: ProtectionStatus) { presentation = .init(status: status) }
}

enum DisplayNumber {
    static func identifier<T: BinaryInteger>(_ value: T) -> String { String(value) }

    static func count(_ value: Int, locale: Locale = .current) -> String {
        value.formatted(.number.locale(locale))
    }
}
