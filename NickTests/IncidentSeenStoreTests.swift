import XCTest
@testable import Nick

final class IncidentSeenStoreTests: XCTestCase {
    func test_seenBadgeIsIndependentFromReviewStatusAndReopensOnNewOccurrence() throws {
        let suite = "IncidentSeenStoreTests.\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }
        let seen = IncidentSeenStore(defaults: defaults)
        let alert = makeAlert().withOccurrenceCount(1)
        var incident = SecurityIncident(
            key: "curl_pipe_shell|/bin/zsh",
            alert: alert,
            evidence: [],
            state: .new
        )

        XCTAssertEqual(seen.unseenCount(in: [incident]), 1)
        XCTAssertEqual(headline(for: incident), "Remediation needed · 1 item")

        seen.markSeen(id: alert.id, occurrenceCount: 1)
        XCTAssertEqual(seen.unseenCount(in: [incident]), 0)
        XCTAssertEqual(headline(for: incident), "Remediation needed · 1 item")

        incident.state = .reviewed
        XCTAssertEqual(headline(for: incident), "Protected")

        incident.state = .new
        incident.alert = incident.alert.withOccurrenceCount(2)
        XCTAssertEqual(seen.unseenCount(in: [incident]), 1)
        XCTAssertEqual(headline(for: incident), "Remediation needed · 1 item")
    }

    func test_seenOccurrencePersistsPerUser() throws {
        let suite = "IncidentSeenStoreTests.\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }
        let alert = makeAlert().withOccurrenceCount(3)

        IncidentSeenStore(defaults: defaults).markSeen(id: alert.id, occurrenceCount: 3)

        XCTAssertFalse(
            IncidentSeenStore(defaults: defaults).isUnseen(id: alert.id, occurrenceCount: 3)
        )
    }

    private func headline(for incident: SecurityIncident) -> String {
        let status = ProtectionStatus.evaluate(
            actionableAlerts: [],
            incidents: [incident],
            auditIssueCount: 0,
            sensorRunning: true
        )
        return ProtectionStatusPresentation(status: status).displayText
    }

    private func makeAlert() -> ThreatAlert {
        let signal = ThreatSignal(
            source: .endpointSecurity,
            severity: .critical,
            title: "Download-to-shell command detected",
            description: "A shell ran downloaded content.",
            context: ThreatSignalContext(metadata: [
                "class": "behavior",
                "detectionKind": "lolbin-behavior",
                "rule": "curl_pipe_shell"
            ])
        )
        return ThreatAlert(
            score: 0.9,
            content: AlertContent(
                title: signal.title,
                description: signal.description,
                severity: .critical,
                recommendedAction: "Review the command."
            ),
            contributingSignals: [signal]
        )
    }
}
