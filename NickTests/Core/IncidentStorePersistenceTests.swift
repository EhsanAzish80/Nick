import XCTest
@testable import Nick

final class IncidentStorePersistenceTests: XCTestCase {
    @MainActor
    func test_duplicateEventWithUnconfirmedStateQueuesNewGeneration() throws {
        let store = IncidentStore(persistOnInit: false)
        var writes: [UInt64] = []
        let snapshot = try JSONEncoder().encode(IncidentStoreSnapshot(
            incidents: [], dismissalTombstones: [], expectedCooldowns: [:]
        ))
        try store.installPrivilegedSnapshot(snapshot) { _, generation in
            writes.append(generation)
        }
        let alert = try tamperAlert(operation: .unlink)

        let first = store.ingest([alert])
        XCTAssertEqual(first.outcomes, [.persisted(1)])
        XCTAssertEqual(writes, [1])
        XCTAssertTrue(store.hasUnconfirmedChanges)

        let replay = store.ingest([alert])
        XCTAssertEqual(replay.outcomes, [.coalesced(2)])
        XCTAssertEqual(writes, [1, 2])
        XCTAssertTrue(store.hasUnconfirmedChanges)

        store.confirmDurablePersistence(generation: 2)
        XCTAssertFalse(store.hasUnconfirmedChanges)
        XCTAssertEqual(store.ingest([alert]).outcomes, [.suppressedByPolicy("duplicate event identifier")])
    }

    @MainActor
    func test_dismissedProtectedTamperReopensOnNewOccurrence() throws {
        var clock = Date(timeIntervalSince1970: 10_000)
        let store = IncidentStore(persistOnInit: false, now: { clock })
        let first = try tamperAlert(operation: .unlink)
        _ = store.ingest([first])
        store.performAuthenticatedUserAction(.dismissed, alertID: first.id)

        clock = clock.addingTimeInterval(60)
        let result = store.ingest([try tamperAlert(operation: .unlink)])

        XCTAssertEqual(result.outcomes, [.persisted(3)])
        XCTAssertEqual(result.newlyActionable.count, 1)
        XCTAssertEqual(store.incidents.first?.state, .new)
        XCTAssertEqual(store.incidents.first?.alert.occurrenceCount, 2)
        XCTAssertEqual(store.incidents.first?.previouslyDismissedAt, Date(timeIntervalSince1970: 10_000))
    }

    @MainActor
    func test_reviewTierDismissalRemainsSuppressedByPolicy() throws {
        let store = IncidentStore(persistOnInit: false)
        let signal = ThreatSignal(
            source: .process,
            severity: .info,
            title: "Review activity",
            description: "Review only",
            context: ThreatSignalContext(metadata: [
                "class": "audit", "reason": "endpoint_management_observed",
                "rule": "endpoint_management_observed", "ruleTier": "review",
            ])
        )
        let alert = ThreatAlert(
            score: 0.4,
            content: AlertContent(title: signal.title, description: signal.description, severity: .info, recommendedAction: "Review"),
            contributingSignals: [signal], timestamp: signal.timestamp
        )
        _ = store.ingest([alert])
        store.performAuthenticatedUserAction(.dismissed, alertID: alert.id)
        XCTAssertEqual(store.ingest([alert]).outcomes, [.suppressedByPolicy("dismissal")])
    }

    @MainActor
    func test_resolvedProtectedTamperRemainsVisibleAsHistory() throws {
        let store = IncidentStore(persistOnInit: false)
        let alert = try tamperAlert(operation: .openWrite)
        _ = store.ingest([alert])
        store.performAuthenticatedUserAction(.resolved, alertID: alert.id)

        XCTAssertEqual(store.incidents.first?.state, .resolved)
        let simpleIDs = Set(SimpleActivityFeed.alertInputs(
            from: store.visibleAlerts,
            actionable: []
        ).map(\.id))
        let advancedIDs = Set(store.visibleAlerts.filter {
            $0.isVisibleInActiveAlerts(showInformational: true)
        }.map(\.id))
        XCTAssertEqual(simpleIDs, [alert.id])
        XCTAssertEqual(advancedIDs, simpleIDs)
    }

    @MainActor
    func test_allDeniedTamperOperationsProduceDistinctEvidence() throws {
        let store = IncidentStore(persistOnInit: false)
        for operation in TamperProtectedOperation.allCases {
            _ = store.ingest([try tamperAlert(operation: operation)])
        }
        XCTAssertEqual(store.incidents.count, TamperProtectedOperation.allCases.count)
    }

    @MainActor
    func test_sameTamperOperationCoalescesAndDifferentOperationDoesNot() throws {
        let store = IncidentStore(persistOnInit: false)
        _ = store.ingest([try tamperAlert(operation: .openWrite)])
        _ = store.ingest([try tamperAlert(operation: .openWrite)])
        _ = store.ingest([try tamperAlert(operation: .truncate)])

        XCTAssertEqual(store.incidents.count, 2)
        XCTAssertEqual(store.incidents.first {
            $0.alert.contributingSignals.first?.metadata["tamperOperation"] == TamperProtectedOperation.openWrite.rawValue
        }?.alert.occurrenceCount, 2)
    }

    @MainActor
    private func tamperAlert(operation: TamperProtectedOperation) throws -> ThreatAlert {
        let finding = try XCTUnwrap(ExtensionFinding(event: Self.tamperEvent(operation: operation)))
        return ThreatAlert(
            score: finding.score,
            content: AlertContent(
                title: finding.signal.title, description: finding.signal.description,
                severity: finding.signal.severity, recommendedAction: finding.recommendedAction
            ),
            contributingSignals: [finding.signal], timestamp: finding.signal.timestamp
        )
    }

    static func tamperEvent(
        operation: TamperProtectedOperation,
        target: String = "/Applications/Nick.app/test"
    ) -> ESEvent {
        ESEvent(
            eventType: .notifyWrite, processPath: "/usr/bin/test-actor",
            pid: 123, parentPid: 1, filePath: target, decision: .deny,
            threat: .init(
                threatName: "Nick protected path change blocked", threatFamily: "tamper",
                metadata: ["tamperOperation": operation.rawValue, "tamperTarget": target]
            )
        )
    }
}

