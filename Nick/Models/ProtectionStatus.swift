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

enum DisplayNumber {
    static func identifier<T: BinaryInteger>(_ value: T) -> String { String(value) }

    static func count(_ value: Int, locale: Locale = .current) -> String {
        value.formatted(.number.locale(locale))
    }
}
