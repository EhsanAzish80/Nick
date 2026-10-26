// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import XCTest
@testable import Nick

final class StrictBlockingPolicyTests: XCTestCase {
    private let signedHigh = ThreatIntelligenceBundlePayload.Rule(
        identifier: "signed.high",
        confidence: .high,
        blockable: true
    )
    private let signedReview = ThreatIntelligenceBundlePayload.Rule(
        identifier: "signed.review",
        confidence: .review,
        blockable: false
    )

    func test_strictModeIsOffByDefault() {
        let policy = StrictBlockingPolicy(signedRules: [signedHigh])
        XCTAssertFalse(policy.allowsRule("signed.high"))
        XCTAssertTrue(policy.allowsAnyBlocking, "Existing exact-hash protection stays active")
    }

    func test_onlySignedHighConfidenceBlockableRuleCanEnforce() {
        let policy = StrictBlockingPolicy(
            configuration: .init(strictModeEnabled: true, blockingKillSwitch: false),
            signedRules: [signedHigh, signedReview]
        )
        XCTAssertTrue(policy.allowsRule("signed.high"))
        XCTAssertFalse(policy.allowsRule("signed.review"))
        XCTAssertFalse(policy.allowsRule("unsigned.high"))
    }

    func test_killSwitchDisablesExactAndRuleBlocking() {
        let policy = StrictBlockingPolicy(
            configuration: .init(strictModeEnabled: true, blockingKillSwitch: true),
            signedRules: [signedHigh]
        )
        XCTAssertFalse(policy.allowsAnyBlocking)
        XCTAssertFalse(policy.allowsRule("signed.high"))
    }

    func test_settingsRecordDefaultsSafelyAndUpdatesAtomically() throws {
        let policy = StrictBlockingPolicy(signedRules: [signedHigh])
        policy.update(settingsRecord: Data("not-json".utf8))
        XCTAssertEqual(policy.currentConfiguration, .safeDefault)

        let payload = try JSONSerialization.data(withJSONObject: [
            "strictModeEnabled": true,
            "blockingKillSwitch": false
        ])
        let record = try JSONEncoder().encode(
            PrivilegedIncidentStoreRecord(revision: 3, payload: payload)
        )
        policy.update(settingsRecord: record)
        XCTAssertTrue(policy.allowsRule("signed.high"))
    }
}
