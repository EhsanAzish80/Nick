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
    func test_resolvedReviewedAndHiddenProtectedIncidentsReopenVisibleAndNotifyOnce() throws {
        for action in [IncidentActionKind.resolved, .reviewed, .hidden] {
            var clock = Date(timeIntervalSince1970: 20_000)
            let store = IncidentStore(persistOnInit: false, now: { clock })
            let first = try tamperAlert(operation: .unlink)
            _ = store.ingest([first])
            store.performAuthenticatedUserAction(action, alertID: first.id)

            clock.addTimeInterval(60)
            let result = store.ingest([try tamperAlert(operation: .unlink)])

            XCTAssertEqual(result.newlyActionable.count, 1, "action=\(action)")
            XCTAssertEqual(store.incidents.first?.state, .new)
            XCTAssertEqual(store.incidents.first?.isVisible, true)
            XCTAssertEqual(store.incidents.first?.alert.occurrenceCount, 2)
            XCTAssertEqual(store.incidents.first?.actions.last?.action, .reopened)
            XCTAssertEqual(
                store.incidents.first?.reopenedAfterState,
                action == .resolved ? .resolved : (action == .hidden ? .hidden : .reviewed)
            )
        }
    }

    @MainActor
    func test_newProtectedRepeatWithinTenMinutesIncrementsWithoutSecondNotification() throws {
        var clock = Date(timeIntervalSince1970: 30_000)
        let store = IncidentStore(persistOnInit: false, now: { clock })
        let first = store.ingest([try tamperAlert(operation: .unlink)])
        XCTAssertEqual(first.newlyActionable.count, 1)

        clock.addTimeInterval(599)
        let repeatResult = store.ingest([try tamperAlert(operation: .unlink)])
        XCTAssertEqual(repeatResult.newlyActionable.count, 0)
        XCTAssertEqual(store.incidents.first?.alert.occurrenceCount, 2)
    }

    @MainActor
    func test_newProtectedRepeatAfterTenMinutesNotifiesWithSameIncidentIdentifier() throws {
        var clock = Date(timeIntervalSince1970: 40_000)
        let store = IncidentStore(persistOnInit: false, now: { clock })
        let first = try tamperAlert(operation: .unlink)
        _ = store.ingest([first])
        let incidentID = try XCTUnwrap(store.incidents.first?.alert.id)

        clock.addTimeInterval(600)
        let repeatResult = store.ingest([try tamperAlert(operation: .unlink)])
        XCTAssertEqual(repeatResult.newlyActionable.map(\.id), [incidentID])
        XCTAssertEqual(store.incidents.first?.alert.occurrenceCount, 2)
    }

    @MainActor
    func test_persistedEventRedeliveryDoesNotNotifyOrIncrement() throws {
        let store = IncidentStore(persistOnInit: false)
        let alert = try tamperAlert(operation: .unlink)
        _ = store.ingest([alert])

        let replay = store.ingest([alert])

        XCTAssertEqual(replay.outcomes, [.suppressedByPolicy("duplicate event identifier")])
        XCTAssertTrue(replay.newlyActionable.isEmpty)
        XCTAssertEqual(store.incidents.first?.alert.occurrenceCount, 1)
    }

    @MainActor
    func test_persistenceFailureDefersNotificationAndSuccessfulRetryDeliversExactlyOnce() throws {
        let store = IncidentStore(persistOnInit: false)
        let queue = DurableIncidentNotificationQueue()
        var writes: [UInt64] = []
        let snapshot = try JSONEncoder().encode(IncidentStoreSnapshot(
            incidents: [], dismissalTombstones: [], expectedCooldowns: [:]
        ))
        try store.installPrivilegedSnapshot(snapshot) { _, generation in writes.append(generation) }
        let alert = try tamperAlert(operation: .unlink)

        let first = store.ingest([alert])
        guard case .persisted(let firstGeneration) = first.outcomes.first else {
            return XCTFail("Expected persisted outcome")
        }
        queue.stage(first.newlyActionable, for: firstGeneration)
        let retry = store.ingest([alert])
        guard case .coalesced(let retryGeneration) = retry.outcomes.first else {
            return XCTFail("Expected retry persistence")
        }
        queue.stage(retry.newlyActionable, for: retryGeneration)
        store.confirmDurablePersistence(generation: retryGeneration)
        XCTAssertEqual(queue.confirm(generation: retryGeneration).count, 1)
        XCTAssertTrue(queue.confirm(generation: retryGeneration).isEmpty)
        XCTAssertEqual(writes, [firstGeneration, retryGeneration])
        XCTAssertEqual(store.incidents.first?.alert.occurrenceCount, 1)
    }

    @MainActor
    func test_reviewTierRepeatBehaviorIsUnchanged() {
        let store = IncidentStore(persistOnInit: false)
        let signal = ThreatSignal(
            source: .process, severity: .info, title: "Review activity", description: "Review only",
            context: ThreatSignalContext(metadata: [
                "class": "audit", "reason": "endpoint_management_observed",
                "rule": "endpoint_management_observed", "ruleTier": "review",
            ])
        )
        let first = ThreatAlert(
            score: 0.1,
            content: AlertContent(title: signal.title, description: signal.description, severity: .info, recommendedAction: "Review"),
            contributingSignals: [signal], timestamp: signal.timestamp
        )
        _ = store.ingest([first])
        let repeatSignal = ThreatSignal(
            source: .process, severity: .info, title: "Review activity", description: "Review only",
            context: ThreatSignalContext(metadata: [
                "class": "audit", "reason": "endpoint_management_observed",
                "rule": "endpoint_management_observed", "ruleTier": "review",
            ])
        )
        let repeatAlert = ThreatAlert(
            score: 0.1,
            content: AlertContent(
                title: repeatSignal.title,
                description: repeatSignal.description,
                severity: .info,
                recommendedAction: "Review"
            ),
            contributingSignals: [repeatSignal], timestamp: repeatSignal.timestamp
        )
        let result = store.ingest([repeatAlert])
        XCTAssertTrue(result.newlyActionable.isEmpty)
        XCTAssertEqual(store.incidents.first?.state, .new)
        XCTAssertEqual(store.incidents.first?.alert.occurrenceCount, 2)
    }

    @MainActor
    func test_latestWinsBurstCoversAllWaitersAndDeliversThreeNotifications() async throws {
        let client = ExtensionXPCClient()
        let store = try privilegedStore()
        let queue = DurableIncidentNotificationQueue()
        let alerts = try [
            tamperAlert(operation: .unlink),
            tamperAlert(operation: .renameDestination),
            tamperAlert(operation: .openWrite),
        ]
        var generations: [UInt64] = []
        for alert in alerts {
            let result = store.ingest([alert])
            let generation = try XCTUnwrap(result.outcomes.first?.generation)
            generations.append(generation)
            queue.stage(result.newlyActionable, for: generation)
            client.registerIncidentWriteGenerationForTesting(generation)
        }
        let waiters = generations.map { generation in
            Task { @MainActor in await client.awaitIncidentStorePersistenceForTesting(generation: generation) }
        }
        await Task.yield()
        XCTAssertEqual(client.pendingIncidentWriteWaiterCount, 3)

        let finalGeneration = try XCTUnwrap(generations.last)
        client.completeIncidentWriteForTesting(through: finalGeneration, succeeded: true)
        store.confirmDurablePersistence(generation: finalGeneration)

        for (index, waiter) in waiters.enumerated() {
            let result = await waiter.value
            XCTAssertEqual(result.0, generations[index])
            XCTAssertEqual(result.1, true)
        }
        XCTAssertEqual(client.pendingIncidentWriteWaiterCount, 0)
        XCTAssertEqual(Set(queue.confirm(generation: finalGeneration).map(\.id)).count, 3)
        XCTAssertEqual(queue.pendingGenerationCount, 0)
    }

    @MainActor
    func test_failedLatestWinsBurstRetainsNotificationsUntilRetrySucceeds() async throws {
        let client = ExtensionXPCClient()
        let store = try privilegedStore()
        let queue = DurableIncidentNotificationQueue()
        let alerts = try [
            tamperAlert(operation: .unlink),
            tamperAlert(operation: .renameDestination),
            tamperAlert(operation: .openWrite),
        ]
        var failedWaiters: [Task<(UInt64, Bool)?, Never>] = []
        var failedThrough: UInt64 = 0
        for alert in alerts {
            let result = store.ingest([alert])
            let generation = try XCTUnwrap(result.outcomes.first?.generation)
            failedThrough = generation
            queue.stage(result.newlyActionable, for: generation)
            client.registerIncidentWriteGenerationForTesting(generation)
            failedWaiters.append(Task { @MainActor in
                await client.awaitIncidentStorePersistenceForTesting(generation: generation)
            })
        }
        await Task.yield()
        client.completeIncidentWriteForTesting(through: failedThrough, succeeded: false)
        for waiter in failedWaiters {
            let result = await waiter.value
            XCTAssertEqual(result?.1, false)
        }
        XCTAssertEqual(client.pendingIncidentWriteWaiterCount, 0)
        XCTAssertEqual(queue.pendingGenerationCount, 3)

        var retryWaiters: [Task<(UInt64, Bool)?, Never>] = []
        var successfulThrough: UInt64 = failedThrough
        for alert in alerts {
            let retry = store.ingest([alert])
            let generation = try XCTUnwrap(retry.outcomes.first?.generation)
            successfulThrough = generation
            queue.stage(retry.newlyActionable, for: generation)
            client.registerIncidentWriteGenerationForTesting(generation)
            retryWaiters.append(Task { @MainActor in
                await client.awaitIncidentStorePersistenceForTesting(generation: generation)
            })
        }
        await Task.yield()
        client.completeIncidentWriteForTesting(through: successfulThrough, succeeded: true)
        store.confirmDurablePersistence(generation: successfulThrough)
        for waiter in retryWaiters {
            let result = await waiter.value
            XCTAssertEqual(result?.1, true)
        }
        XCTAssertEqual(client.pendingIncidentWriteWaiterCount, 0)
        XCTAssertEqual(Set(queue.confirm(generation: successfulThrough).map(\.id)).count, 3)
        XCTAssertTrue(queue.confirm(generation: successfulThrough).isEmpty)
    }

    @MainActor
    func test_supersededCoalescedBurstDeliversFinalOccurrenceCountOnce() throws {
        let store = try privilegedStore()
        let queue = DurableIncidentNotificationQueue()
        for _ in 0..<3 {
            let result = store.ingest([try tamperAlert(operation: .unlink)])
            let generation = try XCTUnwrap(result.outcomes.first?.generation)
            queue.stage(result.newlyActionable, for: generation)
        }
        store.confirmDurablePersistence(generation: 3)
        let delivered = queue.confirm(generation: 3)
        XCTAssertEqual(delivered.count, 1)
        XCTAssertEqual(delivered.first?.occurrenceCount, 3)
    }

    @MainActor
    func test_failedWriteThenDistinctOccurrenceInsideWindowDeliversOnce() throws {
        var clock = Date(timeIntervalSince1970: 50_000)
        let store = try privilegedStore(now: { clock })
        let queue = DurableIncidentNotificationQueue()
        let first = store.ingest([try tamperAlert(operation: .unlink)])
        queue.stage(first.newlyActionable, for: 1)

        clock.addTimeInterval(60)
        let second = store.ingest([try tamperAlert(operation: .unlink)])
        queue.stage(second.newlyActionable, for: 2)
        store.confirmDurablePersistence(generation: 2)

        let delivered = queue.confirm(generation: 2)
        XCTAssertEqual(delivered.count, 1)
        XCTAssertEqual(delivered.first?.occurrenceCount, 2)
    }

    @MainActor
    func test_allowedProtectedIncidentReopensAfterAlwaysAllow() throws {
        let store = IncidentStore(persistOnInit: false)
        let first = try tamperAlert(operation: .unlink)
        _ = store.ingest([first])
        store.performAuthenticatedUserAction(.alwaysAllowed, alertID: first.id)
        _ = store.ingest([try tamperAlert(operation: .unlink)])
        XCTAssertEqual(store.incidents.first?.reopenedAfterState, .allowed)
        XCTAssertEqual(store.incidents.first?.reopenedAfterState?.displayName, "Always Allow")
    }

    @MainActor
    func test_tamperNotificationBodyUsesCapitalizedSingularAndPluralWording() throws {
        let single = try tamperAlert(operation: .unlink)
        let signal = try XCTUnwrap(single.contributingSignals.first)
        XCTAssertEqual(
            NotificationManager.tamperNotificationBody(alert: single, signal: signal),
            "Delete by test-actor — attempted 1 time"
        )
        XCTAssertEqual(
            NotificationManager.tamperNotificationBody(
                alert: single.withOccurrenceCount(3), signal: signal
            ),
            "Delete by test-actor — attempted 3 times"
        )
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

    @MainActor
    private func privilegedStore(now: @escaping () -> Date = Date.init) throws -> IncidentStore {
        let store = IncidentStore(persistOnInit: false, now: now)
        let snapshot = try JSONEncoder().encode(IncidentStoreSnapshot(
            incidents: [], dismissalTombstones: [], expectedCooldowns: [:]
        ))
        try store.installPrivilegedSnapshot(snapshot) { _, _ in }
        return store
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

