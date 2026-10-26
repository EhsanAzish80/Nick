// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation

struct StrictBlockingConfiguration: Codable, Equatable, Sendable {
    var strictModeEnabled: Bool
    var blockingKillSwitch: Bool

    static let safeDefault = Self(strictModeEnabled: false, blockingKillSwitch: false)
}

/// One thread-safe enforcement policy shared by file scanning and every
/// Endpoint Security AUTH handler. Signed intelligence decides eligibility;
/// user settings decide whether eligible rules may enforce.
final class StrictBlockingPolicy: @unchecked Sendable {
    private let lock = NSLock()
    private var configuration: StrictBlockingConfiguration
    private var signedHighConfidenceRules: Set<String>

    init(
        configuration: StrictBlockingConfiguration = .safeDefault,
        signedRules: [ThreatIntelligenceBundlePayload.Rule] = []
    ) {
        self.configuration = configuration
        self.signedHighConfidenceRules = Self.blockableRuleIDs(signedRules)
    }

    var currentConfiguration: StrictBlockingConfiguration {
        lock.withLock { configuration }
    }

    var allowsAnyBlocking: Bool {
        lock.withLock { !configuration.blockingKillSwitch }
    }

    func allowsRule(_ identifier: String) -> Bool {
        lock.withLock {
            configuration.strictModeEnabled
                && !configuration.blockingKillSwitch
                && signedHighConfidenceRules.contains(identifier)
        }
    }

    func update(settingsRecord: Data) {
        let decoded = Self.configuration(fromSettingsRecord: settingsRecord)
        lock.withLock { configuration = decoded }
    }

    func update(signedRules: [ThreatIntelligenceBundlePayload.Rule]) {
        let ruleIDs = Self.blockableRuleIDs(signedRules)
        lock.withLock { signedHighConfidenceRules = ruleIDs }
    }

    static func configuration(fromSettingsRecord data: Data) -> StrictBlockingConfiguration {
        guard let record = try? JSONDecoder().decode(PrivilegedIncidentStoreRecord.self, from: data),
              let object = try? JSONSerialization.jsonObject(with: record.payload) as? [String: Any]
        else { return .safeDefault }
        return StrictBlockingConfiguration(
            strictModeEnabled: object["strictModeEnabled"] as? Bool ?? false,
            blockingKillSwitch: object["blockingKillSwitch"] as? Bool ?? false
        )
    }

    private static func blockableRuleIDs(
        _ rules: [ThreatIntelligenceBundlePayload.Rule]
    ) -> Set<String> {
        Set(rules.compactMap { rule in
            guard rule.blockable, rule.confidence == .high else { return nil }
            return rule.identifier
        })
    }
}
