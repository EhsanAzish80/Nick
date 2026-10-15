import XCTest
@testable import Nick

final class ProtectionStatusTests: XCTestCase {
    func test_sameInputsProduceSameStatusAndCountForEveryConsumer() {
        let alert = makeAlert(metadata: ["reason": "review_only"])
        let expected = ProtectionStatus.evaluate(
            actionableAlerts: [alert], incidents: [], auditIssueCount: 2, sensorRunning: true
        )
        let fiveViews = (0..<5).map { _ in
            ProtectionStatus.evaluate(
                actionableAlerts: [alert], incidents: [], auditIssueCount: 2, sensorRunning: true
            )
        }
        XCTAssertEqual(Set(fiveViews.map(\.state)), [expected.state])
        XCTAssertEqual(Set(fiveViews.map(\.count)), [3])
        XCTAssertEqual(expected.state, .attentionNeeded)
    }

    func test_observedOrReviewOnlyDoesNotClaimBlocked() {
        let alert = makeAlert(metadata: ["reason": "capture_device_active"])
        let status = ProtectionStatus.evaluate(
            actionableAlerts: [alert], incidents: [], auditIssueCount: 0, sensorRunning: true
        )
        XCTAssertEqual(status.state, .attentionNeeded)
    }

    func test_identifierAndLocaleCountFormatting() {
        XCTAssertEqual(DisplayNumber.identifier(50344), "50344")
        XCTAssertEqual(DisplayNumber.count(1308, locale: Locale(identifier: "en_US")), "1,308")
        XCTAssertEqual(DisplayNumber.count(1308, locale: Locale(identifier: "tr_TR")), "1.308")
    }

    func test_sensorProblemDoesNotInventAnIncidentCount() {
        let status = ProtectionStatus.evaluate(
            actionableAlerts: [], incidents: [], auditIssueCount: 0, sensorRunning: false
        )
        XCTAssertEqual(status.state, .sensorProblem)
        XCTAssertEqual(status.count, 0)
    }

    private func makeAlert(metadata: [String: String]) -> ThreatAlert {
        let signal = ThreatSignal(
            source: .process,
            severity: .medium,
            title: "Review activity",
            description: "Review activity",
            context: ThreatSignalContext(metadata: metadata)
        )
        return ThreatAlert(
            score: 0.5,
            content: AlertContent(
                title: "Review activity",
                description: "Review activity",
                severity: .medium,
                recommendedAction: "Review"
            ),
            contributingSignals: [signal]
        )
    }
}
