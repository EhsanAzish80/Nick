import XCTest
@testable import Nick

final class ExtensionXPCClientIncidentTests: XCTestCase {
    @MainActor
    func test_preStoreThreatWaitsThenDeliversAndAcknowledgesExactlyOnce() async throws {
        let client = ExtensionXPCClient()
        var storeReady = false
        client.incidentStoreReadyProvider = { storeReady }
        var ingestCount = 0
        client.findingHandler = { _ in
            ingestCount += 1
            return .persisted(7)
        }
        client.incidentPersistenceOverride = { generation in (generation, true) }
        var acknowledged: [UUID] = []
        let acknowledgedOnce = expectation(description: "durable threat acknowledged")
        client.threatAcknowledgementOverride = { id in
            acknowledged.append(id)
            acknowledgedOnce.fulfill()
        }
        let event = IncidentStorePersistenceTests.tamperEvent(operation: .unlink)
        let persisted = PersistedExtensionFinding(
            kind: .threat,
            payload: try JSONEncoder().encode(event)
        )

        let beforeReady = await client.receivePersisted(persisted)
        XCTAssertNil(beforeReady)
        XCTAssertEqual(ingestCount, 0)
        XCTAssertTrue(acknowledged.isEmpty)
        XCTAssertEqual(client.ackWithoutPersistenceCount, 0)

        // A bootstrap that never finishes leaves the journal item untouched.
        client.incidentStoreDidBecomeReady()
        await Task.yield()
        XCTAssertEqual(ingestCount, 0)
        XCTAssertTrue(acknowledged.isEmpty)

        storeReady = true
        client.incidentStoreDidBecomeReady()
        await fulfillment(of: [acknowledgedOnce], timeout: 2)
        XCTAssertEqual(ingestCount, 1)
        XCTAssertEqual(acknowledged, [event.id])
        XCTAssertEqual(client.ackWithoutPersistenceCount, 0)

        // Journal replay of the same UUID is acknowledged without re-ingest.
        let replay = await client.receivePersisted(persisted)
        XCTAssertEqual(replay, event.id)
        XCTAssertEqual(ingestCount, 1)
        XCTAssertEqual(client.ackWithoutPersistenceCount, 0)
    }

    @MainActor
    func test_disconnectedManualQuarantineUsesProtectionDisconnectedWording() {
        let client = ExtensionXPCClient()
        let completed = expectation(description: "quarantine reply")

        client.requestQuarantineFile(path: "/tmp/eicar.com", expectedThreatName: "EICAR") { result in
            guard case .failure(let failure) = result else {
                XCTFail("Expected disconnected quarantine to fail")
                completed.fulfill()
                return
            }
            XCTAssertEqual(failure.reason, .protectionDisconnected)
            XCTAssertEqual(failure.statusLine, "Real-Time Protection is not connected")
            XCTAssertEqual(
                failure.guidance,
                "Open Settings and reconnect Real-Time Protection, then retry quarantine."
            )
            XCTAssertFalse(failure.statusLine.contains("NickExtensionXPC"))
            completed.fulfill()
        }

        wait(for: [completed], timeout: 1)
    }

    @MainActor
    func test_automaticEROFSUsesSharedWordingAndNotifiesOnce() throws {
        let failure = QuarantineFailure(
            reason: .readOnlyVolume,
            errorDomain: NSPOSIXErrorDomain,
            errorCode: Int(EROFS),
            volumeName: "NickReadOnly"
        )
        let report = RemediationReport(
            timestamp: Date(timeIntervalSince1970: 123),
            threatPath: "/Volumes/NickReadOnly/eicar.com",
            threatName: "EICAR Anti-Malware Test File",
            quarantineRecord: nil,
            actions: [RemediationAction(
                type: .quarantineFile,
                target: "/Volumes/NickReadOnly/eicar.com",
                success: false,
                detail: failure.statusLine,
                quarantineFailure: failure
            )]
        )
        let finding = ExtensionFinding(report: report)
        XCTAssertEqual(finding.signal.title, "EICAR Anti-Malware Test File")
        XCTAssertEqual(finding.signal.metadata["remediationStatusLine"], failure.statusLine)
        XCTAssertEqual(finding.recommendedAction, failure.guidance)

        let store = IncidentStore(persistOnInit: false)
        let alert = ThreatAlert(
            score: finding.score,
            content: AlertContent(
                title: finding.signal.title, description: finding.signal.description,
                severity: finding.signal.severity, recommendedAction: finding.recommendedAction
            ),
            contributingSignals: [finding.signal], timestamp: finding.signal.timestamp
        )
        let result = store.ingest([alert])
        XCTAssertEqual(result.newlyActionable.count, 1)
        XCTAssertEqual(store.incidents.first?.actions.last?.action, .quarantineFailed)
        XCTAssertEqual(store.ingest([alert]).newlyActionable.count, 0)
    }

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
