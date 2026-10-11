import XCTest
@testable import Nick

final class ExtensionXPCClientIncidentTests: XCTestCase {
    @MainActor
    func test_failedRootWriteRedeliveryUsesRealStoreAndAcksOnlyRetryGeneration() async throws {
        let client = ExtensionXPCClient()
        let store = IncidentStore(persistOnInit: false)
        let snapshot = try JSONEncoder().encode(IncidentStoreSnapshot(
            incidents: [], dismissalTombstones: [], expectedCooldowns: [:]
        ))
        try store.installPrivilegedSnapshot(snapshot) { _, _ in }
        client.findingHandler = { finding in
            let alert = ThreatAlert(
                score: finding.score,
                content: AlertContent(
                    title: finding.signal.title, description: finding.signal.description,
                    severity: finding.signal.severity, recommendedAction: finding.recommendedAction
                ),
                contributingSignals: [finding.signal], timestamp: finding.signal.timestamp
            )
            return store.ingest([alert]).outcomes.first ?? .failed
        }
        var attempts = 0
        client.incidentPersistenceOverride = { generation in
            attempts += 1
            guard attempts > 1 else { return (generation, false) }
            store.confirmDurablePersistence(generation: generation)
            return (generation, true)
        }
        let event = IncidentStorePersistenceTests.tamperEvent(operation: .unlink)
        let persisted = PersistedExtensionFinding(kind: .threat, payload: try JSONEncoder().encode(event))

        let first = await client.receivePersisted(persisted)
        XCTAssertNil(first)
        XCTAssertEqual(client.ackWithoutPersistenceCount, 0)
        XCTAssertTrue(store.hasUnconfirmedChanges)

        let retry = await client.receivePersisted(persisted)
        XCTAssertEqual(retry, event.id)
        XCTAssertEqual(client.ackWithoutPersistenceCount, 0)
        XCTAssertFalse(store.hasUnconfirmedChanges)
        XCTAssertEqual(store.incidents.first?.alert.occurrenceCount, 1)
    }

    @MainActor
    func test_suppressedDismissalAcksAndCountsWithoutPersistenceWait() async throws {
        let client = ExtensionXPCClient()
        client.findingHandler = { _ in .suppressedByPolicy("dismissal") }
        client.incidentPersistenceOverride = { _ in XCTFail("suppression must not await a write"); return nil }
        let event = IncidentStorePersistenceTests.tamperEvent(operation: .unlink)
        let persisted = PersistedExtensionFinding(kind: .threat, payload: try JSONEncoder().encode(event))

        let result = await client.receivePersisted(persisted)
        XCTAssertEqual(result, event.id)
        XCTAssertEqual(client.suppressedByDismissalCount, 1)
        XCTAssertEqual(client.ackWithoutPersistenceCount, 0)
    }

    @MainActor
    func test_persistedOutcomeCannotAckFromDifferentGeneration() async throws {
        let client = ExtensionXPCClient()
        client.findingHandler = { _ in .coalesced(7) }
        client.incidentPersistenceOverride = { _ in (8, true) }
        let event = IncidentStorePersistenceTests.tamperEvent(operation: .openWrite)
        let persisted = PersistedExtensionFinding(kind: .threat, payload: try JSONEncoder().encode(event))

        let result = await client.receivePersisted(persisted)
        XCTAssertNil(result)
        XCTAssertTrue(client.failedThreatEventIDs.contains(event.id))
        XCTAssertEqual(client.ackWithoutPersistenceCount, 0)
    }

}
