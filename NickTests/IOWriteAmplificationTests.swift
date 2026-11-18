import XCTest
@testable import Nick

final class IOWriteAmplificationTests: XCTestCase {
    private func directory() throws -> URL {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }

    func testUnknownAndRepeatedEndpointAcknowledgementsDoNotRewriteSnapshots() throws {
        let root = try directory()
        defer { try? FileManager.default.removeItem(at: root) }
        var compactions = 0
        let store = EndpointEventStore(path: root.appendingPathComponent("events.json").path,
            legacyPath: root.appendingPathComponent("legacy.json").path,
            writeObserver: { writer, _ in if writer == "endpoint-event-compaction" { compactions += 1 } })
        let event = ESEvent(eventType: .authExec, processPath: root.appendingPathComponent("fixture").path, pid: 42, parentPid: 1,
                            decision: .deny, threat: .init(threatName: "Synthetic deny", threatFamily: "test"))
        store.appendSynchronously(.init(kind: .threat, payload: try JSONEncoder().encode(event)))
        for _ in 0..<50 { store.removeThreats(eventIDs: [UUID()]) }
        _ = store.snapshot() // Drain the real production serial writer.
        XCTAssertEqual(compactions, 0, "Acknowledging absent IDs must perform no snapshot writes")
        store.removeThreats(eventIDs: [event.id])
        _ = store.snapshot()
        for _ in 0..<50 { store.removeThreats(eventIDs: [event.id]) }
        _ = store.snapshot()
        XCTAssertEqual(compactions, 0, "Acknowledgements must journal a small tombstone, not rewrite the retained ring")
        let restored = EndpointEventStore(path: root.appendingPathComponent("events.json").path,
                                          legacyPath: root.appendingPathComponent("legacy.json").path)
        XCTAssertTrue(try JSONDecoder().decode([PersistedExtensionFinding].self, from: restored.snapshot()).isEmpty)
    }

    func testEndpointCheckpointAndAcknowledgementReplayPreserveUnrelatedEvidence() throws {
        let root = try directory()
        defer { try? FileManager.default.removeItem(at: root) }
        let path = root.appendingPathComponent("events.json").path
        let legacy = root.appendingPathComponent("legacy.json").path
        let store = EndpointEventStore(path: path, legacyPath: legacy, maximumJournalBytes: 8_192)
        var eventIDs: Set<UUID> = []
        var retainedIDs: Set<UUID> = []
        for index in 0..<100 {
            let event = ESEvent(eventType: .authExec, processPath: "/fixture/\(index)", pid: 42, parentPid: 1,
                decision: .deny, threat: .init(threatName: "Synthetic deny", threatFamily: "test"))
            let finding = PersistedExtensionFinding(kind: .threat, payload: try JSONEncoder().encode(event))
            store.appendSynchronously(finding)
            if index % 2 == 0 { eventIDs.insert(event.id) } else { retainedIDs.insert(finding.id) }
        }
        store.removeThreats(eventIDs: eventIDs)
        _ = store.snapshot()
        XCTAssertTrue(FileManager.default.fileExists(atPath: path), "Test must cross a real checkpoint")
        let restored = EndpointEventStore(path: path, legacyPath: legacy)
        let findings = try JSONDecoder().decode([PersistedExtensionFinding].self, from: restored.snapshot())
        XCTAssertEqual(Set(findings.map(\.id)), retainedIDs)
        let mode = try FileManager.default.attributesOfItem(atPath: path)[.posixPermissions] as? NSNumber
        XCTAssertEqual(mode?.intValue, 0o600)
    }

    func testTenThousandUniqueHostsKeepThrottleBoundedAndRetainedHostsDebounced() {
        let throttle = NetworkObservationThrottle()
        let now = Date(timeIntervalSince1970: 100)
        for index in 0..<10_000 {
            XCTAssertTrue(throttle.shouldRecord(key: "host-\(index)", now: now, interval: 300))
            XCTAssertLessThanOrEqual(throttle.retainedCount, 1_024)
        }
        XCTAssertEqual(throttle.retainedCount, 1_024)
        XCTAssertFalse(throttle.shouldRecord(key: "host-9999", now: now.addingTimeInterval(299), interval: 300))
        XCTAssertTrue(throttle.shouldRecord(key: "host-9999", now: now.addingTimeInterval(300), interval: 300))
        XCTAssertEqual(throttle.retainedCount, 1_024)
    }

    func testNetworkBurstPersistsEveryEventWithoutFullArrayWritePerFlow() throws {
        let root = try directory()
        defer { try? FileManager.default.removeItem(at: root) }
        var bytes = 0
        let url = root.appendingPathComponent("network.json")
        let store = NetworkBlockEventStore(url: url, writeObserver: { bytes += $0 })
        for index in 0..<200 {
            store.append(NetworkBlockEvent(host: "host-\(index).invalid", appIdentifier: "test.fixture",
                decision: .observed, reason: "fixture", reasonTitle: "Synthetic observation"))
        }
        XCTAssertEqual(NetworkBlockEventStore.readEvents(at: url).count, 200)
        XCTAssertLessThan(bytes, 200_000, "200 small records should not rewrite the full 500-event ring for each arrival")
    }

    func testNetworkCheckpointRetainsBoundedEventsAndLegacySnapshot() throws {
        let root = try directory()
        defer { try? FileManager.default.removeItem(at: root) }
        let url = root.appendingPathComponent("network.json")
        let legacy = NetworkBlockEvent(host: "legacy.invalid", appIdentifier: nil,
            decision: .observed, reason: "fixture", reasonTitle: "Legacy")
        try JSONEncoder().encode([legacy]).write(to: url)
        let store = NetworkBlockEventStore(url: url, maximumJournalBytes: 4_096)
        var ids: [UUID] = []
        for index in 0..<650 {
            let event = NetworkBlockEvent(timestamp: Date().addingTimeInterval(Double(index)),
                host: "host-\(index).invalid", appIdentifier: nil,
                decision: .observed, reason: "fixture", reasonTitle: "Checkpoint")
            ids.append(event.id)
            store.append(event)
        }
        let restored = NetworkBlockEventStore.readEvents(at: url)
        XCTAssertEqual(restored.count, 500)
        XCTAssertEqual(Set(restored.map(\.id)), Set(ids.suffix(500)))
        XCTAssertLessThan(try Data(contentsOf: URL(fileURLWithPath: url.path + ".journal")).count, 4_096)
    }

    func testUnreadableNetworkHistoryCannotBootstrapAnEmptyDeliveryCursor() throws {
        let root = try directory()
        defer { try? FileManager.default.removeItem(at: root) }
        let url = root.appendingPathComponent("network.json")
        XCTAssertNil(NetworkBlockEventStore.readValidatedEvents(at: url))
        try Data("{corrupt".utf8).write(to: url)
        XCTAssertNil(NetworkBlockEventStore.readValidatedEvents(at: url))
        try FileManager.default.removeItem(at: url)
        try Data("{partial".utf8).write(to: URL(fileURLWithPath: url.path + ".journal"))
        XCTAssertNil(NetworkBlockEventStore.readValidatedEvents(at: url))
    }

    func testNetworkCrashTailDoesNotDiscardTheNextCompletedEvent() throws {
        let root = try directory()
        defer { try? FileManager.default.removeItem(at: root) }
        let url = root.appendingPathComponent("network.json")
        let first = NetworkBlockEvent(host: "one.invalid", appIdentifier: nil,
            decision: .observed, reason: "fixture", reasonTitle: "One")
        NetworkBlockEventStore(url: url).append(first)
        let journal = URL(fileURLWithPath: url.path + ".journal")
        let handle = try FileHandle(forWritingTo: journal)
        try handle.seekToEnd()
        try handle.write(contentsOf: Data("{broken".utf8))
        try handle.close()
        let second = NetworkBlockEvent(host: "two.invalid", appIdentifier: nil,
            decision: .observed, reason: "fixture", reasonTitle: "Two")
        NetworkBlockEventStore(url: url).append(second)
        XCTAssertEqual(Set(NetworkBlockEventStore.readEvents(at: url).map(\.id)), [first.id, second.id])
    }

    @MainActor
    func testNetworkFloodBatchesRealRootWritesAndAcknowledgesOnlyDurableGenerations() async throws {
        let root = try directory()
        defer { try? FileManager.default.removeItem(at: root) }
        let rootStore = PrivilegedIncidentFileStore(fileURL: root.appendingPathComponent("state/incidents.json"))
        let empty = try JSONEncoder().encode(IncidentStoreSnapshot(incidents: [], dismissalTombstones: [], expectedCooldowns: [:]))
        let initial = try JSONDecoder().decode(PrivilegedIncidentStoreRecord.self, from: rootStore.migrate(payload: empty).record)
        let client = ExtensionXPCClient()
        client.configureIncidentStoreTransportForTesting(revision: initial.revision)
        let incidents = IncidentStore(persistOnInit: false)
        try incidents.installPrivilegedSnapshot(empty) { payload, generation in
            client.persistIncidentStore(payload, generation: generation)
        }
        var writes = 0
        var failWrites = false
        client.incidentStoreWriteOverride = { payload, revision, _, reply in
            writes += 1
            if failWrites { reply(false, Data()); return }
            let result = rootStore.replace(payload: payload, expectedRevision: revision)
            reply(result.accepted, result.record)
        }
        client.incidentPersistenceConfirmationHandler = { incidents.confirmDurablePersistence(generation: $0) }
        let manager = NetworkProtectionManager(eventsURLProvider: { nil })
        manager.activateDurableCursor(deliveredEventIDs: [])
        let submitted = expectation(description: "all network generations submitted")
        submitted.expectedFulfillmentCount = 101
        manager.findingHandler = { finding in
            let alert = ThreatAlert(score: finding.score,
                content: AlertContent(title: finding.signal.title, description: finding.signal.description,
                    severity: finding.signal.severity, recommendedAction: finding.recommendedAction),
                contributingSignals: [finding.signal], timestamp: finding.signal.timestamp)
            return incidents.ingest([alert]).outcomes[0]
        }
        manager.incidentPersistenceHandler = { generation, urgent in
            submitted.fulfill()
            return await client.awaitIncidentStorePersistence(generation: generation, urgent: urgent)
        }
        func event() -> NetworkBlockEvent {
            NetworkBlockEvent(host: "repeat.invalid", appIdentifier: "test.fixture", decision: .observed,
                reason: NetworkObservationReason.knownThreat.rawValue, reasonTitle: "Synthetic observation")
        }
        let firstDurable = expectation(description: "first network incident durable")
        client.incidentPersistenceConfirmationHandler = { generation in
            incidents.confirmDurablePersistence(generation: generation)
            firstDurable.fulfill()
        }
        manager.ingestEvents([event()])
        await fulfillment(of: [firstDurable], timeout: 3)
        for _ in 0..<10 { await Task.yield() }
        XCTAssertEqual(manager.deliveredEventCount, 1)
        client.incidentPersistenceConfirmationHandler = { incidents.confirmDurablePersistence(generation: $0) }
        for _ in 0..<100 { manager.ingestEvents([event()]) }
        await fulfillment(of: [submitted], timeout: 3)
        XCTAssertEqual(writes, 1, "Recurrences cannot force per-flow root snapshots")
        XCTAssertEqual(manager.deliveredEventCount, 1, "Uncommitted cursors must remain eligible for replay")
        let batch = expectation(description: "batch durable")
        client.incidentPersistenceConfirmationHandler = { generation in
            incidents.confirmDurablePersistence(generation: generation)
            batch.fulfill()
        }
        client.flushRoutineIncidentStoreForTesting()
        await fulfillment(of: [batch], timeout: 3)
        for _ in 0..<100 { await Task.yield() }
        XCTAssertEqual(writes, 2)
        XCTAssertEqual(manager.deliveredEventCount, 101)
        let record = try JSONDecoder().decode(PrivilegedIncidentStoreRecord.self, from: rootStore.load())
        let restored = try JSONDecoder().decode(IncidentStoreSnapshot.self, from: record.payload)
        XCTAssertEqual(restored.incidents.first?.alert.occurrenceCount, 101)
        // A new incident still requests immediate persistence, and failure must not ack it.
        failWrites = true
        manager.incidentPersistenceHandler = { generation, urgent in
            XCTAssertTrue(urgent)
            return await client.awaitIncidentStorePersistence(generation: generation, urgent: urgent)
        }
        manager.ingestEvents([NetworkBlockEvent(host: "new.invalid", appIdentifier: "other.fixture", decision: .observed,
            reason: NetworkObservationReason.knownThreat.rawValue, reasonTitle: "Different incident")])
        for _ in 0..<100 { await Task.yield() }
        XCTAssertEqual(writes, 3)
        XCTAssertEqual(manager.deliveredEventCount, 101)
    }

    @MainActor
    func testRepeatedNetworkEnforcementStillForcesImmediateDurability() async {
        let manager = NetworkProtectionManager(eventsURLProvider: { nil })
        manager.activateDurableCursor(deliveredEventIDs: [])
        manager.findingHandler = { _ in .coalesced(7) }
        let submitted = expectation(description: "enforcement persistence requested")
        manager.incidentPersistenceHandler = { generation, urgent in
            XCTAssertTrue(urgent, "Repeated blocked evidence cannot use the routine observation batch")
            submitted.fulfill()
            return (generation, true)
        }
        manager.ingestEvents([NetworkBlockEvent(host: "test.invalid", appIdentifier: "test.fixture",
            decision: .blocked, reason: NetworkObservationReason.knownThreat.rawValue,
            reasonTitle: "Synthetic blocked event")])
        await fulfillment(of: [submitted], timeout: 3)
    }

    @MainActor
    func testNetworkCoalescedFindingDoesNotForceAnUrgentIncidentSnapshot() async {
        let manager = NetworkProtectionManager(eventsURLProvider: { nil })
        manager.activateDurableCursor(deliveredEventIDs: [])
        manager.findingHandler = { _ in .coalesced(7) }
        let submitted = expectation(description: "network persistence requested")
        manager.incidentPersistenceHandler = { generation, urgent in
            XCTAssertEqual(generation, 7)
            XCTAssertFalse(urgent, "The network path must use the same recurrence batching as ES")
            submitted.fulfill()
            return (generation, true)
        }
        manager.ingestEvents([NetworkBlockEvent(host: "test.invalid", appIdentifier: "test.fixture",
            decision: .observed, reason: NetworkObservationReason.knownThreat.rawValue,
            reasonTitle: "Synthetic observation")])
        await fulfillment(of: [submitted], timeout: 5)
    }
}
