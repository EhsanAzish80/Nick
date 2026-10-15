import XCTest
@testable import Nick

final class ProtectionStatusTests: XCTestCase {
    func test_everyViewModelProducesIdenticalPresentationForEveryState() {
        let cases: [(ProtectionStatus.State, Int, String, String?)] = [
            (.protected, 0, "Protected", nil),
            (.attentionNeeded, 2, "Attention needed", "2 items need review"),
            (.threatBlocked, 2, "Threat blocked", "2 items"),
            (.remediationNeeded, 2, "Remediation needed", "2 items"),
            (.sensorProblem, 0, "Protection component unavailable", nil),
        ]

        for (state, count, headline, countText) in cases {
            let status = ProtectionStatus(state: state, count: count)
            let models: [any ProtectionStatusPresenting] = [
                SimpleHomeProtectionStatusModel(status: status),
                SimpleActivityProtectionStatusModel(status: status),
                AdvancedOverviewProtectionStatusModel(status: status),
                SmartScanProtectionStatusModel(status: status),
                SystemAuditProtectionStatusModel(status: status),
            ]
            let presentations = models.map(\.presentation)

            XCTAssertTrue(
                presentations.dropFirst().allSatisfy { $0 == presentations[0] },
                "Mismatch for \(state)"
            )
            XCTAssertEqual(presentations[0].headlineText, headline)
            XCTAssertEqual(presentations[0].countText, countText)
        }
    }

    func test_appTargetDoesNotContainFoundAThreatCopy() throws {
        let testsURL = URL(fileURLWithPath: #filePath)
        let projectRoot = testsURL
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let appRoot = projectRoot.appendingPathComponent("Nick", isDirectory: true)
        let enumerator = FileManager.default.enumerator(
            at: appRoot,
            includingPropertiesForKeys: [.isRegularFileKey],
            options: [.skipsHiddenFiles]
        )
        var matches: [String] = []
        while let url = enumerator?.nextObject() as? URL {
            guard ["swift", "strings", "plist"].contains(url.pathExtension.lowercased()),
                  let contents = try? String(contentsOf: url, encoding: .utf8),
                  contents.localizedCaseInsensitiveContains("found a threat")
            else { continue }
            matches.append(url.path)
        }
        XCTAssertTrue(matches.isEmpty, "Legacy copy remains in: \(matches)")
    }

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
