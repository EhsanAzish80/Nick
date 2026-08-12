import XCTest
@testable import Nick

final class RuntimeCompareIdentityTests: XCTestCase {
    func test_processIdentityIgnoresPIDAndStartTime() {
        let first = process(id: "first", pid: 41, start: Date(timeIntervalSince1970: 10))
        let second = process(id: "second", pid: 9_999, start: Date(timeIntervalSince1970: 500))

        XCTAssertEqual(first.stableKey, second.stableKey)
    }

    func test_listenerIdentityNormalizesWildcardAddressAndIgnoresPID() {
        let first = listener(id: "first", address: "0.0.0.0", pid: 10)
        let second = listener(id: "second", address: "::", pid: 20)

        XCTAssertEqual(first.stableKey, second.stableKey)
    }

    func test_connectionIdentityIgnoresObservationTimesAndCounts() {
        let first = connection(id: "first", firstSeen: .distantPast, count: 1)
        let second = connection(id: "second", firstSeen: .distantFuture, count: 400)

        XCTAssertEqual(first.stableKey, second.stableKey)
    }

    func test_systemExtensionParserPreservesCategoryAndState() throws {
        let output = """
        1 extension(s)
        --- com.apple.system_extension.endpoint_security_extension (Go to 'System Settings > General > Login Items & Extensions > Endpoint Security Extensions' to modify these system extension(s))
        enabled active teamID bundleID (version) name [state]
        * * UXGW5V3BY6 com.ehsanazish.nick.extension (4.1/410) NickExtension [activated enabled]
        --- com.apple.system_extension.network_extension (Go to 'System Settings > General > Login Items & Extensions > Network Extensions' to modify these system extension(s))
        * * UXGW5V3BY6 com.ehsanazish.nick.netfilter (4.1/410) NickNetFilter [activated enabled]
        """

        let records = SystemExtensionInventory.parse(output)

        XCTAssertEqual(records.count, 2)
        let endpoint = try XCTUnwrap(records.first { $0.category == .endpointSecurity })
        XCTAssertEqual(endpoint.bundleIdentifier, "com.ehsanazish.nick.extension")
        XCTAssertEqual(endpoint.teamIdentifier, "UXGW5V3BY6")
        XCTAssertEqual(endpoint.version, "4.1")
        XCTAssertTrue(endpoint.isActivated)
        XCTAssertTrue(endpoint.isEnabled)
        XCTAssertNotNil(records.first { $0.category == .network })
    }

    private func process(id: String, pid: Int32, start: Date) -> RuntimeProcessRecord {
        RuntimeProcessRecord(
            id: id, pid: pid, name: "Example", path: "/Applications/Example.app/Contents/MacOS/Example",
            parentPID: 1, parentName: "launchd", user: "tester", startTime: start,
            signingState: "Signed", teamID: "TEAM123"
        )
    }

    private func listener(id: String, address: String, pid: Int32) -> RuntimeListenerRecord {
        RuntimeListenerRecord(
            id: id, transport: "TCP", localAddress: address, localPort: 8080,
            ownerName: "Example", ownerPath: "/usr/local/bin/example", pid: pid
        )
    }

    private func connection(id: String, firstSeen: Date, count: Int) -> RuntimeConnectionRecord {
        RuntimeConnectionRecord(
            id: id, transport: "TCP", remoteAddress: "203.0.113.8", remotePort: 443,
            ownerName: "Example", ownerPath: "/Applications/Example.app/Contents/MacOS/Example",
            firstSeen: firstSeen, lastSeen: firstSeen, observationCount: count
        )
    }
}

final class RuntimeSnapshotComparatorTests: XCTestCase {
    func test_pidAndObservationNoiseProduceNoFindings() {
        let beforeProcess = process(id: "before", pid: 10)
        let afterProcess = process(id: "after", pid: 20)
        let beforeConnection = connection(id: "before-flow", count: 1)
        let afterConnection = connection(id: "after-flow", count: 18)
        let baseline = snapshot(processes: [beforeProcess], connections: [beforeConnection])
        let followUp = snapshot(processes: [afterProcess], connections: [afterConnection])

        XCTAssertTrue(RuntimeSnapshotComparator.compare(baseline: baseline, followUp: followUp).isEmpty)
    }

    func test_addedListenerAndDisabledExtensionAreEvidenceBacked() throws {
        let baselineExtension = extensionRecord(enabled: true)
        let followUpExtension = extensionRecord(enabled: false)
        let newListener = RuntimeListenerRecord(
            id: "new-listener", transport: "TCP", localAddress: "0.0.0.0", localPort: 4444,
            ownerName: "Agent", ownerPath: "/tmp/agent", pid: 99
        )
        let baseline = snapshot(extensions: [baselineExtension])
        let followUp = snapshot(listeners: [newListener], extensions: [followUpExtension])

        let findings = RuntimeSnapshotComparator.compare(baseline: baseline, followUp: followUp)

        let listenerFinding = try XCTUnwrap(findings.first { $0.category == .listener })
        XCTAssertEqual(listenerFinding.change, .added)
        XCTAssertEqual(listenerFinding.evidence, .observed)
        XCTAssertEqual(listenerFinding.sourceReferences, ["new-listener"])
        let extensionFinding = try XCTUnwrap(findings.first { $0.change == .changed })
        XCTAssertEqual(extensionFinding.attention, .important)
        XCTAssertEqual(Set(extensionFinding.sourceReferences), ["extension-before", "extension-after"])
    }

    func test_mismatchedCaptureQualityProducesExplicitLimitations() {
        let baseline = snapshot(
            boot: "boot-a", observationSeconds: 30,
            sensor: RuntimeSensorHealth(endpointSecurityResponding: true, networkFilterResponding: true, networkFilterState: "active")
        )
        let followUp = snapshot(
            boot: "boot-b", observationSeconds: 60,
            sensor: RuntimeSensorHealth(endpointSecurityResponding: false, networkFilterResponding: true, networkFilterState: "active"),
            health: [.init(provider: "Endpoint Security", state: .partial, message: "No heartbeat", recordCount: 0)]
        )

        let findings = RuntimeSnapshotComparator.compare(baseline: baseline, followUp: followUp)

        XCTAssertTrue(findings.contains { $0.id.contains("boot-session") })
        XCTAssertTrue(findings.contains { $0.id.contains("observation-window") })
        XCTAssertTrue(findings.contains { $0.id.contains("sensor-health") && $0.attention == .important })
        XCTAssertTrue(findings.contains { $0.evidence == .cannotConfirm })
    }

    func test_comparisonOrderingIsDeterministic() {
        let baseline = snapshot()
        let followUp = snapshot(
            processes: [
                RuntimeProcessRecord(id: "z", pid: 1, name: "Zulu", path: "/tmp/zulu", parentPID: 0, parentName: nil, user: nil, startTime: nil, signingState: "Unsigned", teamID: nil),
                RuntimeProcessRecord(id: "a", pid: 2, name: "Alpha", path: "/tmp/alpha", parentPID: 0, parentName: nil, user: nil, startTime: nil, signingState: "Signed", teamID: nil),
            ]
        )

        let first = RuntimeSnapshotComparator.compare(baseline: baseline, followUp: followUp)
        let second = RuntimeSnapshotComparator.compare(baseline: baseline, followUp: followUp)

        XCTAssertEqual(first, second)
        XCTAssertEqual(first.first?.title, "Process appeared: Zulu")
    }

    func test_duplicateStableProcessIdentitiesDoNotCrashComparison() {
        let first = process(id: "process-z", pid: 10)
        let duplicate = process(id: "process-a", pid: 20)

        let findings = RuntimeSnapshotComparator.compare(
            baseline: snapshot(),
            followUp: snapshot(processes: [first, duplicate])
        )

        XCTAssertEqual(findings.filter { $0.category == .process }.count, 1)
        XCTAssertEqual(findings.first { $0.category == .process }?.sourceReferences, ["process-a"])
    }

    func test_duplicateStableExtensionIdentitiesDoNotCrashComparison() {
        let first = RuntimeExtensionRecord(
            id: "extension-z", category: .endpointSecurity,
            bundleIdentifier: "com.example.security", teamIdentifier: "TEAM123", version: "1.0",
            isActivated: true, isEnabled: true, stateDescription: "activated enabled"
        )
        let duplicate = RuntimeExtensionRecord(
            id: "extension-a", category: .endpointSecurity,
            bundleIdentifier: "com.example.security", teamIdentifier: "TEAM123", version: "1.0",
            isActivated: true, isEnabled: true, stateDescription: "activated enabled"
        )

        let findings = RuntimeSnapshotComparator.compare(
            baseline: snapshot(extensions: [first, duplicate]),
            followUp: snapshot(extensions: [duplicate, first])
        )

        XCTAssertTrue(findings.filter { $0.category == .systemExtension }.isEmpty)
    }

    func test_unavailableProcessInventoryDoesNotCreateFalseRemovals() {
        let baseline = snapshot(
            processes: [process(id: "baseline-process", pid: 10)],
            health: [.init(provider: "Processes", state: .available, message: nil, recordCount: 1)]
        )
        let followUp = snapshot(
            health: [.init(provider: "Processes", state: .unavailable, message: "errno 12", recordCount: 0)]
        )

        let findings = RuntimeSnapshotComparator.compare(baseline: baseline, followUp: followUp)

        XCTAssertTrue(findings.filter { $0.category == .process }.isEmpty)
        XCTAssertEqual(findings.filter { $0.id.contains("provider-Processes") }.count, 1)
    }

    func test_crossBootComparisonSuppressesProcessChurn() {
        let baseline = snapshot(
            boot: "boot-before",
            processes: [process(id: "baseline-process", pid: 10)]
        )
        let followUp = snapshot(
            boot: "boot-after",
            processes: [RuntimeProcessRecord(
                id: "follow-up-process", pid: 20, name: "Different",
                path: "/usr/libexec/different", parentPID: 1, parentName: "launchd",
                user: "tester", startTime: Date(), signingState: "Signed", teamID: "APPLE"
            )]
        )

        let findings = RuntimeSnapshotComparator.compare(baseline: baseline, followUp: followUp)

        XCTAssertTrue(findings.filter { $0.category == .process }.isEmpty)
        XCTAssertEqual(findings.filter { $0.id.contains("boot-session") }.count, 1)
    }

    func test_retiringDuplicateExtensionDoesNotCreateFalseStateChange() {
        let active = RuntimeExtensionRecord(
            id: "same-extension", category: .network,
            bundleIdentifier: "com.example.filter", teamIdentifier: "TEAM123", version: "1.0",
            isActivated: true, isEnabled: true, stateDescription: "activated enabled"
        )
        let retiring = RuntimeExtensionRecord(
            id: "same-extension", category: .network,
            bundleIdentifier: "com.example.filter", teamIdentifier: "TEAM123", version: "1.0",
            isActivated: false, isEnabled: false, stateDescription: "terminated waiting to uninstall on reboot"
        )

        let findings = RuntimeSnapshotComparator.compare(
            baseline: snapshot(extensions: [retiring, active]),
            followUp: snapshot(extensions: [active])
        )

        XCTAssertTrue(findings.filter { $0.category == .systemExtension }.isEmpty)
    }

    func test_partialConnectionInventorySuppressesListenerAndConnectionDifferences() {
        let baseline = snapshot(
            listeners: [RuntimeListenerRecord(
                id: "listener", transport: "TCP", localAddress: "0.0.0.0", localPort: 443,
                ownerName: "Example", ownerPath: "/Applications/Example.app/Contents/MacOS/Example", pid: 10
            )],
            connections: [connection(id: "connection", count: 1)],
            health: [.init(provider: "Connections", state: .available, message: nil, recordCount: 2)]
        )
        let followUp = snapshot(
            health: [.init(provider: "Connections", state: .partial, message: "missed sample", recordCount: 0)]
        )

        let findings = RuntimeSnapshotComparator.compare(baseline: baseline, followUp: followUp)

        XCTAssertTrue(findings.filter { $0.category == .listener || $0.category == .connection }.isEmpty)
        XCTAssertEqual(findings.filter { $0.id.contains("provider-Connections") }.count, 1)
    }

    private func process(id: String, pid: Int32) -> RuntimeProcessRecord {
        RuntimeProcessRecord(
            id: id, pid: pid, name: "Example", path: "/Applications/Example.app/Contents/MacOS/Example",
            parentPID: 1, parentName: "launchd", user: "tester", startTime: Date(),
            signingState: "Signed", teamID: "TEAM123"
        )
    }

    private func connection(id: String, count: Int) -> RuntimeConnectionRecord {
        RuntimeConnectionRecord(
            id: id, transport: "TCP", remoteAddress: "198.51.100.8", remotePort: 443,
            ownerName: "Example", ownerPath: "/Applications/Example.app/Contents/MacOS/Example",
            firstSeen: Date().addingTimeInterval(-30), lastSeen: Date(), observationCount: count
        )
    }

    private func extensionRecord(enabled: Bool) -> RuntimeExtensionRecord {
        RuntimeExtensionRecord(
            id: enabled ? "extension-before" : "extension-after", category: .endpointSecurity,
            bundleIdentifier: "com.example.security", teamIdentifier: "TEAM123", version: "1.0",
            isActivated: enabled, isEnabled: enabled, stateDescription: enabled ? "activated enabled" : "terminated disabled"
        )
    }
}

final class RuntimeSupportBundleTests: XCTestCase {
    func test_sanitizationIsStableAndDoesNotModifyOriginal() throws {
        let privatePath = "/Users/alice/Documents/Example.app/Contents/MacOS/Example"
        let privateAddress = "203.0.113.55"
        let baseline = snapshot(
            deviceToken: "private-device-token",
            processes: [RuntimeProcessRecord(
                id: "process", pid: 8, name: "Example", path: privatePath,
                parentPID: 1, parentName: "launchd", user: "alice", startTime: nil,
                signingState: "Signed", teamID: "TEAM123"
            )],
            connections: [RuntimeConnectionRecord(
                id: "connection", transport: "TCP", remoteAddress: privateAddress, remotePort: 443,
                ownerName: "Example", ownerPath: privatePath, firstSeen: Date(), lastSeen: Date(), observationCount: 1
            )]
        )
        let original = RuntimeComparison(
            id: UUID(), label: "Private test", scenario: .custom, createdAt: Date(), updatedAt: Date(),
            state: .awaitingFollowUp, baseline: baseline, followUp: nil, findings: []
        )

        let first = RuntimeComparisonSanitizer.sanitize(original)
        let second = RuntimeComparisonSanitizer.sanitize(original)
        let files = try RuntimeSupportBundleBuilder.files(for: original, sanitized: true)
        let exportedJSON = try XCTUnwrap(String(data: files.json, encoding: .utf8))

        XCTAssertEqual(first, second)
        XCTAssertEqual(original.baseline?.processes.first?.path, privatePath)
        XCTAssertEqual(original.baseline?.connections.first?.remoteAddress, privateAddress)
        XCTAssertFalse(exportedJSON.contains(privatePath))
        XCTAssertFalse(exportedJSON.contains(privateAddress))
        XCTAssertFalse(exportedJSON.contains("private-device-token"))
        XCTAssertTrue(exportedJSON.contains("<redacted-"))
    }

    func test_supportBundleRejectsConfiguredSizeLimit() {
        let comparison = RuntimeComparison(
            id: UUID(), label: "Size test", scenario: .custom, createdAt: Date(), updatedAt: Date(),
            state: .awaitingFollowUp, baseline: snapshot(), followUp: nil, findings: []
        )

        XCTAssertThrowsError(
            try RuntimeSupportBundleBuilder.files(for: comparison, sanitized: false, maximumBytes: 1)
        ) { error in
            XCTAssertTrue(error is RuntimeSupportBundleBuilder.ExportError)
        }
    }

    @MainActor
    func test_storeRoundTripsAndBoundsRetention() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("RuntimeComparisonStoreTests-\(UUID().uuidString)", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = RuntimeComparisonStore(directory: directory)

        for index in 0..<24 {
            _ = store.create(label: "Comparison \(index)", scenario: .custom)
        }

        XCTAssertEqual(store.comparisons.count, 20)
        let reloaded = RuntimeComparisonStore(directory: directory)
        XCTAssertEqual(reloaded.comparisons.count, 20)
        XCTAssertEqual(Set(reloaded.comparisons.map(\.id)), Set(store.comparisons.map(\.id)))
    }

    @MainActor
    func test_storeAllowsRetentionToBeConfiguredDownward() {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("RuntimeComparisonRetentionTests-\(UUID().uuidString)", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = RuntimeComparisonStore(directory: directory, maximumCount: 3)

        for index in 0..<5 { _ = store.create(label: "Comparison \(index)", scenario: .custom) }

        XCTAssertEqual(store.comparisons.count, 3)
    }
}

final class RuntimeComparisonImportTests: XCTestCase {
    @MainActor
    func test_completedComparisonImportsWithNewIdentityAndRecomputedFindings() throws {
        let directory = temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let originalID = UUID()
        let baseline = snapshot(deviceToken: "same-device")
        let followUp = snapshot(
            deviceToken: "same-device",
            processes: [RuntimeProcessRecord(
                id: "process-added", pid: 42, name: "Added", path: "/Applications/Added.app/Contents/MacOS/Added",
                parentPID: 1, parentName: "launchd", user: nil, startTime: nil,
                signingState: "Signed", teamID: "TEAM"
            )]
        )
        let original = RuntimeComparison(
            id: originalID, label: "Imported", scenario: .appChange, createdAt: Date(), updatedAt: Date(),
            state: .completed, baseline: baseline, followUp: followUp, findings: []
        )
        let files = try RuntimeSupportBundleBuilder.files(for: original, sanitized: false)
        let store = RuntimeComparisonStore(directory: directory)

        let importedID = try store.importComparison(data: files.json, expectedDeviceToken: "same-device")
        let imported = try XCTUnwrap(store.comparison(importedID))

        XCTAssertNotEqual(importedID, originalID)
        XCTAssertEqual(imported.state, .completed)
        XCTAssertFalse(imported.findings.isEmpty)
    }

    @MainActor
    func test_baselineImportCanResumeAfterStoreRestart() throws {
        let directory = temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let original = RuntimeComparison(
            id: UUID(), label: "Restart", scenario: .custom, createdAt: Date(), updatedAt: Date(),
            state: .awaitingFollowUp, baseline: snapshot(deviceToken: "same-device"), followUp: nil, findings: []
        )
        let files = try RuntimeSupportBundleBuilder.files(for: original, sanitized: false)
        let firstStore = RuntimeComparisonStore(directory: directory)
        let importedID = try firstStore.importComparison(data: files.json, expectedDeviceToken: "same-device")

        let restartedStore = RuntimeComparisonStore(directory: directory)
        try restartedStore.setFollowUp(snapshot(deviceToken: "same-device"), for: importedID)

        XCTAssertEqual(restartedStore.comparison(importedID)?.state, .completed)
    }

    @MainActor
    func test_importRejectsDifferentDeviceAndUnsupportedSchema() throws {
        let directory = temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = RuntimeComparisonStore(directory: directory)
        let foreign = comparison(with: snapshot(deviceToken: "foreign-device"))
        let unsupported = comparison(with: snapshot(schemaVersion: RuntimeSnapshot.currentSchemaVersion + 1))

        XCTAssertThrowsError(try store.importComparison(data: encoded(foreign), expectedDeviceToken: "local-device")) {
            XCTAssertEqual($0 as? RuntimeComparisonStore.ImportError, .differentDevice)
        }
        XCTAssertThrowsError(try store.importComparison(data: encoded(unsupported), expectedDeviceToken: "device-token")) {
            XCTAssertEqual($0 as? RuntimeComparisonStore.ImportError, .unsupportedSchema(RuntimeSnapshot.currentSchemaVersion + 1))
        }
    }

    @MainActor
    func test_importRejectsInvalidAndMissingEvidence() throws {
        let directory = temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = RuntimeComparisonStore(directory: directory)
        let empty = RuntimeComparison(
            id: UUID(), label: "Empty", scenario: .custom, createdAt: Date(), updatedAt: Date(),
            state: .awaitingBaseline, baseline: nil, followUp: nil, findings: []
        )

        XCTAssertThrowsError(try store.importComparison(data: Data("not json".utf8), expectedDeviceToken: "device-token")) {
            XCTAssertEqual($0 as? RuntimeComparisonStore.ImportError, .invalidFile)
        }
        XCTAssertThrowsError(try store.importComparison(data: encoded(empty), expectedDeviceToken: "device-token")) {
            XCTAssertEqual($0 as? RuntimeComparisonStore.ImportError, .missingEvidence)
        }
    }

    private func temporaryDirectory() -> URL {
        FileManager.default.temporaryDirectory
            .appendingPathComponent("RuntimeImportTests-\(UUID().uuidString)", isDirectory: true)
    }

    private func comparison(with baseline: RuntimeSnapshot) -> RuntimeComparison {
        RuntimeComparison(
            id: UUID(), label: "Import", scenario: .custom, createdAt: Date(), updatedAt: Date(),
            state: .awaitingFollowUp, baseline: baseline, followUp: nil, findings: []
        )
    }

    private func encoded(_ comparison: RuntimeComparison) throws -> Data {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        return try encoder.encode(comparison)
    }
}

final class RuntimeEvidenceResolverTests: XCTestCase {
    func test_resolverReturnsBaselineAndFollowUpSourceRecords() {
        let before = RuntimeExtensionRecord(
            id: "extension-before", category: .network, bundleIdentifier: "com.example.filter",
            teamIdentifier: "TEAM", version: "1", isActivated: true, isEnabled: true,
            stateDescription: "activated enabled"
        )
        let after = RuntimeExtensionRecord(
            id: "extension-after", category: .network, bundleIdentifier: "com.example.filter",
            teamIdentifier: "TEAM", version: "2", isActivated: false, isEnabled: false,
            stateDescription: "terminated disabled"
        )
        let finding = RuntimeFinding(
            id: "finding", category: .systemExtension, change: .changed, evidence: .observed,
            attention: .important, title: "Extension changed", explanation: "Observed change.",
            limitation: nil, sourceReferences: [before.id, after.id, "missing"]
        )
        let comparison = RuntimeComparison(
            id: UUID(), label: "Evidence", scenario: .custom, createdAt: Date(), updatedAt: Date(),
            state: .completed, baseline: snapshot(extensions: [before]), followUp: snapshot(extensions: [after]),
            findings: [finding]
        )

        let evidence = RuntimeEvidenceResolver.resolve(finding, in: comparison)

        XCTAssertEqual(evidence.count, 2)
        XCTAssertEqual(Set(evidence.map(\.capture)), [.baseline, .followUp])
        XCTAssertTrue(evidence.flatMap(\.details).contains { $0.label == "State" && $0.value == "terminated disabled" })
    }
}

final class RuntimeConnectionBufferTests: XCTestCase {
    func test_bufferCoalescesRepeatedEvidenceAndBoundsDistinctRecords() {
        var buffer = RuntimeConnectionBuffer(maximumCount: 3)
        let now = Date()
        for index in 0..<100_000 {
            let destination = index < 99_997 ? index % 3 : index
            buffer.record(RuntimeConnectionRecord(
                id: "record-\(index)", transport: "TCP", remoteAddress: "198.51.100.\(destination)",
                remotePort: 443, ownerName: "Example", ownerPath: "/Applications/Example.app",
                firstSeen: now, lastSeen: now, observationCount: 1
            ), seenAt: now.addingTimeInterval(Double(index)))
        }

        XCTAssertEqual(buffer.sortedRecords.count, 3)
        XCTAssertEqual(buffer.droppedDistinctRecords, 3)
        XCTAssertEqual(buffer.sortedRecords.map(\.observationCount).reduce(0, +), 99_997)
    }
}

final class RuntimeConnectionObserverTests: XCTestCase {
    func test_observationReportsPartialSampleFailureAndCompletesWindow() async throws {
        var attempts = 0
        let result: RuntimeConnectionObservation<Int> = try await RuntimeConnectionObserver.observe(
            requestedSeconds: 2,
            intervalSeconds: 1,
            sample: {
                attempts += 1
                if attempts == 2 { return .failure(TestError.sampleFailed) }
                return .success(attempts)
            },
            sleep: { _ in },
            progress: { _ in }
        )

        XCTAssertEqual(result.elapsedSeconds, 2)
        XCTAssertEqual(result.samples, [1, 3])
        XCTAssertEqual(result.failedSampleCount, 1)
    }

    func test_observationCancellationStopsBeforeAnotherSample() async {
        let task = Task {
            try await RuntimeConnectionObserver.observe(
                requestedSeconds: 30,
                intervalSeconds: 5,
                sample: { .success(1) },
                sleep: { _ in try await Task.sleep(for: .seconds(30)) },
                progress: { _ in }
            )
        }
        task.cancel()

        do {
            _ = try await task.value
            XCTFail("Expected cancellation")
        } catch is CancellationError {
            // Expected.
        } catch {
            XCTFail("Unexpected error: \(error)")
        }
    }

    private enum TestError: Error { case sampleFailed }
}

private func snapshot(
    schemaVersion: Int = RuntimeSnapshot.currentSchemaVersion,
    boot: String = "boot-a",
    observationSeconds: Int = 30,
    deviceToken: String = "device-token",
    processes: [RuntimeProcessRecord] = [],
    listeners: [RuntimeListenerRecord] = [],
    connections: [RuntimeConnectionRecord] = [],
    persistence: [RuntimePersistenceRecord] = [],
    extensions: [RuntimeExtensionRecord] = [],
    sensor: RuntimeSensorHealth = RuntimeSensorHealth(
        endpointSecurityResponding: true, networkFilterResponding: true, networkFilterState: "active"
    ),
    health: [RuntimeProviderHealth] = []
) -> RuntimeSnapshot {
    RuntimeSnapshot(
        id: UUID(), schemaVersion: schemaVersion, label: "Fixture",
        scenario: .custom, startedAt: Date(timeIntervalSince1970: 1_000),
        completedAt: Date(timeIntervalSince1970: 1_030), nickVersion: "4.1", macOSVersion: "27.0",
        architecture: "arm64", deviceToken: deviceToken, bootSessionIdentifier: boot,
        configuration: RuntimeCaptureConfiguration(
            requestedObservationSeconds: observationSeconds, sampleIntervalSeconds: 5
        ),
        actualObservationSeconds: observationSeconds, processes: processes, listeners: listeners,
        connections: connections, persistence: persistence, extensions: extensions,
        sensorHealth: sensor, providerHealth: health
    )
}
