import XCTest
@testable import Nick

private actor NetworkSubmissionCounter {
    private var count = 0

    func increment() {
        count += 1
    }

    func value() -> Int {
        count
    }
}

final class NetworkProtectionPolicyTests: XCTestCase {

    func test_eventHandlerLabelsEveryProtectedAuthorizationOperation() throws {
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let source = try String(
            contentsOf: root.appendingPathComponent("NickExtension/EventHandler.swift"),
            encoding: .utf8
        )
        let requiredMappings = [
            "operation: .openWrite",
            "operation: .create",
            "operation: .truncate",
            "operation: .link",
            "operation: .clone",
            "operation: .copyfile",
            "handleRenameEvent(",
            "handleUnlinkEvent(",
        ]
        for mapping in requiredMappings {
            XCTAssertTrue(source.contains(mapping), mapping)
        }
    }

    func test_completedWriteHashingRunsOnlyFromAsynchronousNotifyPaths() throws {
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let source = try String(
            contentsOf: root.appendingPathComponent("NickExtension/EventHandler.swift"),
            encoding: .utf8
        )
        let closeStart = try XCTUnwrap(source.range(of: "case ES_EVENT_TYPE_NOTIFY_CLOSE:"))
        let renameStart = try XCTUnwrap(source.range(of: "case ES_EVENT_TYPE_NOTIFY_RENAME:"))
        let unlinkStart = try XCTUnwrap(source.range(of: "case ES_EVENT_TYPE_AUTH_UNLINK:"))
        let closeSection = String(source[closeStart.lowerBound..<renameStart.lowerBound])
        let renameSection = String(source[renameStart.lowerBound..<unlinkStart.lowerBound])

        XCTAssertTrue(closeSection.contains("dispatchQueue.async"))
        XCTAssertTrue(closeSection.contains("scanner.exactSignatureMatch"))
        XCTAssertTrue(renameSection.contains("dispatchQueue.async"))
        XCTAssertTrue(renameSection.contains("scanner.exactSignatureMatch"))
        XCTAssertTrue(source.contains("Completed-write exact-signature check skipped over size cap"))
    }

    func test_networkEventPersistenceRunsOffTheFlowVerdictPath() throws {
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let source = try String(
            contentsOf: root.appendingPathComponent("NickNetFilter/FilterDataProvider.swift"),
            encoding: .utf8
        )
        let recordStart = try XCTUnwrap(source.range(of: "private func recordObservation("))
        let signingStart = try XCTUnwrap(source.range(of: "private func signingIdentifier("))
        let recordSection = String(source[recordStart.lowerBound..<signingStart.lowerBound])

        XCTAssertTrue(recordSection.contains("eventWriteQueue.async"))
        XCTAssertTrue(recordSection.contains("eventStore.append(event)"))
        XCTAssertFalse(recordSection.contains("eventStore.append(NetworkBlockEvent("))
    }

    func test_systemExtensionDeclaresFilterDataProvider() throws {
        let repositoryRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        if repositoryRoot.path.contains("/Documents/") {
            throw XCTSkip("Info.plist source-file check runs in CI outside macOS protected folders")
        }
        let plistURL = repositoryRoot
            .appendingPathComponent("NickNetFilter")
            .appendingPathComponent("Info.plist")
        let data = try Data(contentsOf: plistURL)
        let plist = try XCTUnwrap(
            PropertyListSerialization.propertyList(
                from: data,
                options: [],
                format: nil
            ) as? [String: Any]
        )
        let networkExtension = try XCTUnwrap(
            plist["NetworkExtension"] as? [String: Any]
        )

        let providerClasses = try XCTUnwrap(
            networkExtension["NEProviderClasses"] as? [String: String]
        )
        XCTAssertEqual(
            providerClasses["com.apple.networkextension.filter-data"],
            "$(PRODUCT_MODULE_NAME).FilterDataProvider"
        )
    }

    func test_filterHealthUsesSystemReadableLocation() {
        XCTAssertEqual(
            NetworkProtectionSharedStore.healthURL()?.path,
            "/Library/Application Support/com.ehsanazish.nick/network-filter-health.json"
        )
        XCTAssertEqual(
            NetworkProtectionSharedStore.eventsURL()?.path,
            "/Library/Application Support/com.ehsanazish.nick/network-block-events.json"
        )
        XCTAssertEqual(
            NetworkProtectionSharedStore.signedRulesURL()?.path,
            "/Library/Application Support/com.ehsanazish.nick/network-rules-v1.json"
        )
        XCTAssertEqual(
            NetworkProtectionSharedStore.signedRulesVersionURL()?.path,
            "/Library/Application Support/com.ehsanazish.nick/network-rules-version"
        )
    }

    func test_signedRuleVersionsRejectRollback() {
        XCTAssertTrue(NetworkRuleVersionPolicy.accepts(candidateVersion: 1, highestAcceptedVersion: nil))
        XCTAssertTrue(NetworkRuleVersionPolicy.accepts(candidateVersion: 7, highestAcceptedVersion: 7))
        XCTAssertTrue(NetworkRuleVersionPolicy.accepts(candidateVersion: 8, highestAcceptedVersion: 7))
        XCTAssertFalse(NetworkRuleVersionPolicy.accepts(candidateVersion: 6, highestAcceptedVersion: 7))
        XCTAssertFalse(NetworkRuleVersionPolicy.accepts(candidateVersion: 0, highestAcceptedVersion: nil))
    }

    func test_networkExtensionEntitlementsMatchReleaseProfile() throws {
        let repositoryRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        // A sandboxed XCTest host without Full Disk Access can block indefinitely
        // when opening source files below ~/Documents. CI checks this assertion
        // from its unprotected workspace, while local runs must remain independent
        // of Nick's production privacy permissions.
        if repositoryRoot.path.contains("/Documents/") {
            throw XCTSkip("Entitlement source-file check runs in CI outside macOS protected folders")
        }

        for fileName in ["NickNetFilter.entitlements", "NickNetFilter.Release.entitlements"] {
            let data = try Data(contentsOf: repositoryRoot
                .appendingPathComponent("NickNetFilter")
                .appendingPathComponent(fileName))
            let entitlements = try XCTUnwrap(
                PropertyListSerialization.propertyList(
                    from: data,
                    options: [],
                    format: nil
                ) as? [String: Any]
            )
            XCTAssertNil(
                entitlements["com.apple.security.application-groups"],
                "NickNetFilter's Developer ID profile does not grant App Groups"
            )
        }
    }

    func test_allowlistedDomain_takesPrecedenceOverBlocklist() {
        let policy = NetworkProtectionPolicy(configuration: .init(
            allowedDomains: ["example.com"]
        ))
        XCTAssertEqual(
            policy.evaluate(
                host: "login.example.com",
                appIdentifier: nil,
                isBlocklisted: { _ in true },
                isScam: { _ in true }
            ),
            .allow
        )
    }

    func test_allowlistedApp_takesPrecedenceOverScamVerdict() {
        let policy = NetworkProtectionPolicy(configuration: .init(
            allowedAppIdentifiers: ["com.example.browser"]
        ))
        XCTAssertEqual(
            policy.evaluate(
                host: "paypa1.com",
                appIdentifier: "COM.EXAMPLE.BROWSER",
                isBlocklisted: { _ in false },
                isScam: { _ in true }
            ),
            .allow
        )
    }

    func test_disabledProtection_failsOpen() {
        let policy = NetworkProtectionPolicy(configuration: .init(
            protectionEnabled: false
        ))
        XCTAssertEqual(
            policy.evaluate(
                host: "known-bad.example",
                appIdentifier: nil,
                isBlocklisted: { _ in true },
                isScam: { _ in true }
            ),
            .allow
        )
    }

    func test_missingAndMalformedHosts_failOpen() {
        let policy = NetworkProtectionPolicy(configuration: .init())
        for host in [nil, "", "bad/host", String(repeating: "a", count: 300)] {
            XCTAssertEqual(
                policy.evaluate(
                    host: host,
                    appIdentifier: nil,
                    isBlocklisted: { _ in true },
                    isScam: { _ in true }
                ),
                .allow
            )
        }
    }

    func test_signedBlocklistAndHeuristicAreReviewOnlyByDefault() {
        let policy = NetworkProtectionPolicy(configuration: .init())
        XCTAssertEqual(
            policy.evaluate(
                host: "malware.example",
                appIdentifier: nil,
                isBlocklisted: { _ in true },
                isScam: { _ in false }
            ),
            .observe(.knownThreat)
        )
        XCTAssertEqual(
            policy.evaluate(
                host: "paypa1.com",
                appIdentifier: nil,
                isBlocklisted: { _ in false },
                isScam: { _ in true }
            ),
            .observe(.scamGuardian)
        )
    }

    func test_blocklistMatchRemainsObservationOnly() {
        let policy = NetworkProtectionPolicy(configuration: .init())
        XCTAssertEqual(
            policy.evaluate(
                host: "malware.example",
                appIdentifier: nil,
                isBlocklisted: { _ in true },
                isScam: { _ in false }
            ),
            .observe(.knownThreat)
        )
    }

    func test_missingAndLegacyVendorConfigurationsStayInactive() {
        for vendorConfiguration: [String: Any]? in [
            nil,
            ["protectionEnabled": true, "blockingEnabled": true],
            [
                "configurationVersion": NetworkProtectionConfiguration.configurationVersion - 1,
                "protectionEnabled": true,
                "blockingEnabled": true,
            ],
        ] {
            let configuration = NetworkProtectionConfiguration(
                vendorConfiguration: vendorConfiguration
            )
            let policy = NetworkProtectionPolicy(configuration: configuration)
            XCTAssertEqual(
                policy.evaluate(
                    host: "malware.example",
                    appIdentifier: nil,
                    isBlocklisted: { _ in true },
                    isScam: { _ in true }
                ),
                .allow
            )
        }
    }

    func test_temporaryDomainAndAppAllowancesExpire() {
        let now = Date(timeIntervalSince1970: 1_000)
        let configuration = NetworkProtectionConfiguration(
            temporaryAllowedDomains: [
                "example.com": now.addingTimeInterval(60).timeIntervalSince1970,
                "expired.example": now.addingTimeInterval(-1).timeIntervalSince1970,
            ],
            temporaryAllowedAppIdentifiers: [
                "com.example.browser": now.addingTimeInterval(60).timeIntervalSince1970,
            ]
        )
        let policy = NetworkProtectionPolicy(configuration: configuration)

        XCTAssertEqual(
            policy.evaluate(
                host: "login.example.com",
                appIdentifier: nil,
                now: now,
                isBlocklisted: { _ in true },
                isScam: { _ in true }
            ),
            .allow
        )
        XCTAssertEqual(
            policy.evaluate(
                host: "malware.example",
                appIdentifier: "COM.EXAMPLE.BROWSER",
                now: now,
                isBlocklisted: { _ in true },
                isScam: { _ in true }
            ),
            .allow
        )
        XCTAssertEqual(
            policy.evaluate(
                host: "expired.example",
                appIdentifier: nil,
                now: now,
                isBlocklisted: { _ in true },
                isScam: { _ in false }
            ),
            .observe(.knownThreat)
        )
    }

    func test_legacyNetworkEventDefaultsToBlocked() throws {
        let id = UUID()
        let timestamp = Date(timeIntervalSince1970: 1_000)
        let payload: [String: Any] = [
            "id": id.uuidString,
            "timestamp": timestamp.timeIntervalSinceReferenceDate,
            "host": "malware.example",
            "reason": NetworkBlockReason.blocklist.rawValue,
        ]
        let data = try JSONSerialization.data(withJSONObject: payload)
        let event = try JSONDecoder().decode(NetworkBlockEvent.self, from: data)

        XCTAssertEqual(event.decision, .blocked)
        XCTAssertEqual(event.reasonTitle, NetworkBlockReason.blocklist.userTitle)
    }

    func test_unicodeDomain_normalizesToASCII() {
        let normalized = NetworkProtectionConfiguration.normalizedDomain("bücher.de")
        XCTAssertEqual(normalized, "xn--bcher-kva.de")
    }

    func test_networkEventContext_explainsObservedAppleDeviceTraffic() {
        let event = NetworkBlockEvent(
            host: "fe80::14ab:8892:d87b:7e8d%anrlo",
            appIdentifier: "com.apple.SyncServices.AppleMobileDeviceHelper",
            decision: .observed,
            reason: NetworkObservationReason.unusualPort.rawValue,
            reasonTitle: NetworkObservationReason.unusualPort.userTitle,
            port: 62078
        )

        let context = NetworkEventContext(event: event)
        XCTAssertEqual(context.appName, "Apple device sync")
        XCTAssertEqual(context.destinationKind, .localDevice)
        XCTAssertEqual(context.destinationLabel, "Nearby device")
        XCTAssertEqual(context.destinationActionLabel, "Allow This Destination")
        XCTAssertTrue(context.explanation.contains("tried to connect"))
        XCTAssertTrue(context.explanation.contains("it did not block it"))
        XCTAssertFalse(context.explanation.contains("connected to"))
        XCTAssertTrue(context.explanation.contains("Apple device pairing and sync"))
        XCTAssertTrue(context.guidance.contains("no action is required"))
    }

    func test_networkEventContext_distinguishesWebsiteAndNarrowAllowance() {
        let event = NetworkBlockEvent(
            host: "login.example.com",
            appIdentifier: "com.example.browser",
            decision: .blocked,
            reason: NetworkBlockReason.blocklist.rawValue,
            reasonTitle: NetworkBlockReason.blocklist.userTitle,
            port: 443
        )

        let context = NetworkEventContext(event: event)
        XCTAssertEqual(context.destinationKind, .website)
        XCTAssertEqual(context.destinationActionLabel, "Allow This Website")
        XCTAssertTrue(context.explanation.contains("Nick blocked"))
        XCTAssertTrue(context.explanation.contains("standard encrypted web port"))
        XCTAssertTrue(context.guidance.contains("narrowest exception"))
    }

    func test_networkEventContext_classifiesPrivateIPv4AsLocalAddress() {
        let privateAddress = [192, 168, 50, 210]
            .map(String.init)
            .joined(separator: ".")
        let event = NetworkBlockEvent(
            host: privateAddress,
            appIdentifier: "com.openai.codex.helper",
            decision: .observed,
            reason: NetworkObservationReason.unusualPort.rawValue,
            reasonTitle: NetworkObservationReason.unusualPort.userTitle,
            port: 5353
        )

        let context = NetworkEventContext(event: event)
        XCTAssertEqual(context.appName, "Codex")
        XCTAssertEqual(context.destinationKind, .localNetworkAddress)
        XCTAssertTrue(context.explanation.contains("local device discovery"))
    }

    func test_localDiscoveryPortsAreExpectedOnlyForLocalDestinations() {
        XCTAssertTrue(NetworkEventContext.isExpectedLocalDiscovery(
            host: "192.168.1.20",
            port: 5353
        ))
        XCTAssertTrue(NetworkEventContext.isExpectedLocalDiscovery(
            host: "fe80::1%en0",
            port: 62078
        ))
        XCTAssertFalse(NetworkEventContext.isExpectedLocalDiscovery(
            host: "203.0.113.20",
            port: 5353
        ))
        XCTAssertFalse(NetworkEventContext.isExpectedLocalDiscovery(
            host: "192.168.1.20",
            port: 4444
        ))
    }

    func test_privateDestinationEvidenceIsClassifiedLocal() {
        let event = NetworkBlockEvent(
            host: "10.0.0.42",
            appIdentifier: "com.example.tool",
            decision: .observed,
            reason: NetworkObservationReason.connectionRate.rawValue,
            reasonTitle: NetworkObservationReason.connectionRate.userTitle,
            port: 443
        )

        XCTAssertEqual(NetworkFinding(event: event).signal.metadata["destinationClass"], "local")
    }
}

@MainActor
final class UnifiedSourceFindingTests: XCTestCase {
    func test_detectorThreatsUseOnlyAcknowledgedThreatChannel() throws {
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let source = try String(
            contentsOf: root.appendingPathComponent("NickExtension/EventHandler.swift"),
            encoding: .utf8
        )

        XCTAssertTrue(source.contains("private func reportThreat(_ event: ESEvent)"))
        XCTAssertFalse(source.contains("self.pushEvent(threat)"))
        XCTAssertFalse(source.contains("pushEvent(ransomwareEvent)"))
    }

    @MainActor
    func test_eicarThreatPersistsAsOneCanonicalIncident() async throws {
        let event = ESEvent(
            eventType: .notifyWrite,
            processPath: "/usr/bin/curl",
            pid: 4242,
            parentPid: 1,
            filePath: "/private/tmp/nick-7b-eicar.exe",
            decision: .notApplicable,
            threat: .init(
                sha256: "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
                threatName: "EICAR Anti-Malware Test File",
                threatFamily: "Test"
            )
        )
        let envelope = PersistedExtensionFinding(
            kind: .threat,
            timestamp: event.timestamp,
            payload: try JSONEncoder().encode(event)
        )
        let client = ExtensionXPCClient()
        client.incidentStoreReadyProvider = { true }
        let store = IncidentStore(persistOnInit: false)
        client.findingHandler = { finding in
            let alert = ThreatAlert(
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
            _ = store.ingest([alert])
            return .suppressedByPolicy("test fixture")
        }

        let acknowledgement = await client.receivePersisted(envelope)
        XCTAssertEqual(acknowledgement, event.id)
        XCTAssertEqual(store.incidents.count, 1)
        XCTAssertEqual(store.incidents.first?.alert.contributingSignals.first?.id, event.id)
        XCTAssertEqual(store.incidents.first?.alert.detectedFilePath, event.filePath)
    }

    @MainActor
    func test_successfulQuarantineUpdatesQuarantineWithoutCreatingSecondFinding() async throws {
        let client = ExtensionXPCClient()
        var delivered = 0
        client.findingHandler = { _ in
            delivered += 1
            return .suppressedByPolicy("test fixture")
        }
        let record = QuarantineRecord(
            id: UUID(),
            originalPath: "/private/tmp/eicar.exe",
            quarantinedPath: "/Library/Application Support/com.ehsanazish.nick/quarantine/eicar.exe",
            hash: "abc",
            threatName: "EICAR",
            severity: "critical",
            quarantinedAt: Date(timeIntervalSince1970: 456),
            processPath: "/usr/bin/curl",
            pid: 42
        )
        let report = RemediationReport(
            timestamp: Date(timeIntervalSince1970: 456),
            threatPath: "/private/tmp/eicar.exe",
            threatName: "EICAR",
            quarantineRecord: record,
            actions: [.init(
                type: .quarantineFile,
                target: "/private/tmp/eicar.exe",
                success: true,
                detail: "Moved to quarantine"
            )]
        )

        client.reportRemediationAction(try JSONEncoder().encode(report))
        await Task.yield()
        await Task.yield()

        XCTAssertEqual(delivered, 0)
        XCTAssertEqual(client.quarantineRecords.map(\.id), [record.id])
    }

    @MainActor
    func test_failedQuarantineRemainsActionableAndIsDeliveredForNotification() async throws {
        let client = ExtensionXPCClient()
        let store = IncidentStore(persistOnInit: false)
        var delivered = 0
        var newlyActionable: [ThreatAlert] = []
        let delivery = expectation(description: "Failed quarantine reaches incident ingestion")
        client.findingHandler = { finding in
            delivered += 1
            let alert = ThreatAlert(
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
            newlyActionable = store.ingest([alert]).newlyActionable
            delivery.fulfill()
            return .suppressedByPolicy("test fixture")
        }
        let report = RemediationReport(
            timestamp: Date(timeIntervalSince1970: 789),
            threatPath: "/private/tmp/eicar.exe",
            threatName: "EICAR",
            quarantineRecord: nil,
            actions: [
                .init(type: .killProcess, target: "42", success: true, detail: "Stopped"),
                .init(
                    type: .quarantineFile,
                    target: "/private/tmp/eicar.exe",
                    success: false,
                    detail: "Permission denied"
                ),
            ]
        )

        client.reportRemediationAction(try JSONEncoder().encode(report))
        await fulfillment(of: [delivery], timeout: 2)

        XCTAssertEqual(delivered, 1)
        let alert = try XCTUnwrap(store.incidents.first?.alert)
        XCTAssertEqual(alert.title, "EICAR")
        XCTAssertEqual(alert.severity, .critical)
        XCTAssertEqual(alert.contributingSignals.first?.metadata["remediationStatus"], "quarantine-failed")
        XCTAssertEqual(
            alert.contributingSignals.first?.metadata["remediationFailureReason"],
            "Permission denied"
        )
        XCTAssertTrue(alert.description.contains("still present at its original location"))
        XCTAssertTrue(alert.description.contains("Permission denied"))
        XCTAssertEqual(newlyActionable.map(\.id), [alert.id], "Newly actionable findings trigger notification delivery")
    }

    func test_notificationTapHasMainWindowNavigationReceiver() throws {
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let mainWindow = try String(
            contentsOf: root.appendingPathComponent("Nick/App/MainWindowView.swift"),
            encoding: .utf8
        )
        let simpleActivity = try String(
            contentsOf: root.appendingPathComponent("Nick/App/Simple/SimpleActivityView.swift"),
            encoding: .utf8
        )

        XCTAssertTrue(mainWindow.contains("publisher(for: .nickNavigateToAlert)"))
        XCTAssertTrue(mainWindow.contains("simpleSelection = .activity"))
        XCTAssertTrue(mainWindow.contains("selectedSection = .alerts"))
        XCTAssertTrue(simpleActivity.contains("presentPendingNotificationAlert"))
    }

    func test_phishingObservationBecomesReviewableNetworkEvidence() {
        let event = NetworkBlockEvent(
            id: UUID(uuidString: "11111111-1111-1111-1111-111111111111")!,
            host: "nick-scam-test.invalid",
            appIdentifier: "com.example.browser",
            decision: .observed,
            reason: NetworkObservationReason.scamGuardian.rawValue,
            reasonTitle: NetworkObservationReason.scamGuardian.userTitle,
            port: 443
        )
        let finding = NetworkFinding(event: event)
        XCTAssertEqual(finding.signal.id, event.id)
        XCTAssertEqual(finding.signal.source, .network)
        XCTAssertEqual(finding.signal.severity, .medium)
        XCTAssertEqual(finding.signal.metadata["destination"], event.host)
        XCTAssertTrue(finding.signal.description.contains("did not block"))
    }

    func test_endpointThreatUsesStableIDAndProtectedTier() throws {
        let event = ESEvent(
            eventType: .authExec,
            processPath: "/usr/bin/open",
            pid: 42,
            parentPid: 1,
            filePath: "/private/tmp/eicar.com",
            decision: .deny,
            threat: .init(
                sha256: "abc",
                threatName: "EICAR",
                threatFamily: "test",
                isCodeSigned: true
            )
        )
        let finding = try XCTUnwrap(ExtensionFinding(event: event))
        XCTAssertEqual(finding.signal.id, event.id)
        XCTAssertEqual(finding.signal.source, .endpointSecurity)
        XCTAssertEqual(finding.signal.severity, .critical)
        XCTAssertEqual(finding.signal.metadata["ruleTier"], "protected")
        XCTAssertEqual(finding.signal.fileInfo?.path, "/private/tmp/eicar.com")
        XCTAssertEqual(
            finding.signal.processInfo?.signingStatus,
            .signed(teamID: "APPLE_PLATFORM", signingID: "com.apple.open")
        )
    }

    func test_lolbinExecEventMapsToProtectedCriticalEvidenceAndHonestWording() throws {
        let event = LOLBinTestFixtures.curlPipeEvent(pid: 420)

        let finding = try XCTUnwrap(ExtensionFinding(event: event))
        XCTAssertEqual(finding.signal.severity, .critical)
        XCTAssertEqual(finding.signal.metadata["class"], "behavior")
        XCTAssertEqual(finding.signal.metadata["ruleTier"], "protected")
        XCTAssertEqual(finding.signal.processInfo?.path, "/bin/sh")
        XCTAssertNil(finding.signal.metadata["arguments"])

        let alert = ThreatAlert(
            id: event.id,
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
        let copy = UserFacingAlertBuilder.shared.build(from: alert)
        XCTAssertEqual(copy.headline, "Download-to-shell command detected")
        XCTAssertEqual(copy.severity, .critical)
        XCTAssertTrue(copy.explanation.contains("recorded the launch"))
        XCTAssertTrue(copy.explanation.contains("did not block it"))
        XCTAssertFalse(copy.headline.contains("Developer command needs context"))
        XCTAssertFalse(copy.explanation.lowercased().contains("attack"))
    }

    func test_endpointFindingUsesOnlyConcreteSigningIdentity() throws {
        let event = ESEvent(
            eventType: .authExec,
            processPath: "/Applications/Example.app/Contents/MacOS/Example",
            pid: 43,
            parentPid: 1,
            decision: .allow,
            threat: .init(
                threatName: "Example detection",
                threatFamily: "test",
                isCodeSigned: true,
                teamID: "ABCDE12345",
                signingID: "com.example.app"
            )
        )
        let finding = try XCTUnwrap(ExtensionFinding(event: event))
        XCTAssertEqual(
            finding.signal.processInfo?.signingStatus,
            .signed(teamID: "ABCDE12345", signingID: "com.example.app")
        )
    }

    func test_systemExtensionListIsInformationalEndpointEvidence() throws {
        let event = ESEvent(
            eventType: .authExec,
            processPath: "/usr/bin/systemextensionsctl",
            pid: 44,
            parentPid: 1,
            decision: .notApplicable,
            threat: .init(
                threatName: "System extension management observed",
                threatFamily: "endpoint-management"
            )
        )
        let finding = try XCTUnwrap(ExtensionFinding(event: event))
        XCTAssertEqual(finding.signal.source, .endpointSecurity)
        XCTAssertEqual(finding.signal.severity, .info)
        XCTAssertEqual(finding.signal.metadata["class"], "audit")
        XCTAssertEqual(finding.signal.metadata["ruleTier"], "review")
        XCTAssertEqual(finding.signal.metadata["rule"], "endpoint_management_observed")
        XCTAssertNil(finding.signal.fileInfo)
        XCTAssertEqual(Evidence(signal: finding.signal).ruleTier, .review)
    }

    func test_blockedTamperIsCriticalProtectedEndpointEvidence() throws {
        let event = ESEvent(
            eventType: .notifyWrite,
            processPath: "/usr/bin/rm",
            pid: 45,
            parentPid: 1,
            filePath: "/Applications/Nick.app",
            decision: .deny,
            threat: .init(
                threatName: "Nick protected path change blocked",
                threatFamily: "tamper"
            )
        )
        let finding = try XCTUnwrap(ExtensionFinding(event: event))
        XCTAssertEqual(finding.signal.source, .endpointSecurity)
        XCTAssertEqual(finding.signal.severity, .critical)
        XCTAssertEqual(finding.signal.metadata["class"], "integrity")
        XCTAssertEqual(finding.signal.metadata["ruleTier"], "protected")
        XCTAssertTrue(finding.signal.description.contains("refused"))
    }

    func test_authorizationTamperCarriesObservedExpectedAndRepairEvidence() throws {
        let event = ESEvent(
            eventType: .notifyWrite,
            processPath: "/Library/SystemExtensions/com.ehsanazish.nick.NickExtension",
            pid: 0,
            parentPid: 0,
            decision: .notApplicable,
            threat: .init(
                threatName: "Nick authorization policy tampering detected",
                threatFamily: "tamper",
                metadata: [
                    "observedRule": "class=rule; rule=allow",
                    "expectedRule": ProtectionAuthorizationRightPolicy.expectedSummary,
                    "repairStatus": "restored"
                ]
            )
        )
        let finding = try XCTUnwrap(ExtensionFinding(event: event))
        XCTAssertFalse(finding.signal.processInfo?.name.isEmpty ?? true)
        XCTAssertEqual(finding.signal.metadata["repairStatus"], "restored")
        XCTAssertTrue(finding.signal.description.contains("observed rule"))
        XCTAssertTrue(finding.signal.description.contains("expected rule"))
    }

    func test_ransomwareRenameEventMapsToProtectedBehaviorWithValidatedActor() throws {
        let event = ESEvent(
            eventType: .notifyWrite,
            processPath: "/Applications/Example.app/Contents/MacOS/Example",
            pid: 55,
            parentPid: 1,
            filePath: "/Users/a/Documents/report.locked",
            decision: .notApplicable,
            threat: .init(
                threatName: "Rapid file-renaming behavior",
                threatFamily: "ransomware-behavior",
                isCodeSigned: true,
                teamID: "ABCDE12345",
                signingID: "com.example.app",
                metadata: [
                    "detectionKind": "ransomware-behavior",
                    "renameExtension": "locked",
                    "renameFileCount": "8",
                    "renameDirectoryCount": "2",
                    "renameWindowSeconds": "10"
                ]
            )
        )
        let finding = try XCTUnwrap(ExtensionFinding(event: event))
        XCTAssertEqual(finding.signal.metadata["class"], "behavior")
        XCTAssertEqual(finding.signal.metadata["ruleTier"], "protected")
        XCTAssertEqual(finding.signal.processInfo?.signingStatus, .signed(teamID: "ABCDE12345", signingID: "com.example.app"))
        XCTAssertEqual(finding.signal.description, "8 files in 2 folders were renamed to .locked within 10 seconds by Example.")
    }

    func test_validatedNickMaintenanceIsOneInformationalReviewRule() throws {
        let event = ESEvent(
            eventType: .notifyWrite,
            processPath: "/usr/libexec/installd",
            pid: 46,
            parentPid: 1,
            filePath: "/Applications/Nick.app/Contents/MacOS/Nick",
            decision: .allow,
            threat: .init(
                threatName: "Nick maintenance updated protected files",
                threatFamily: "nick-maintenance",
                isCodeSigned: true,
                signingID: "com.apple.installd"
            )
        )
        let finding = try XCTUnwrap(ExtensionFinding(event: event))
        XCTAssertEqual(finding.signal.severity, .info)
        XCTAssertEqual(finding.signal.metadata["class"], "audit")
        XCTAssertEqual(finding.signal.metadata["rule"], "nick_protected_path_maintenance")
        XCTAssertEqual(finding.signal.metadata["ruleTier"], "review")
    }

    func test_documentedFinderUninstallIsVisibleInformationalReviewRule() throws {
        let event = ESEvent(
            eventType: .notifyWrite,
            processPath: "/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder",
            pid: 47,
            parentPid: 1,
            filePath: "/Applications/Nick.app",
            decision: .allow,
            threat: .init(
                threatName: "Nick is being moved to the Trash",
                threatFamily: "nick-documented-uninstall",
                isCodeSigned: true,
                signingID: "com.apple.finder"
            )
        )
        let finding = try XCTUnwrap(ExtensionFinding(event: event))
        XCTAssertEqual(finding.signal.severity, .info)
        XCTAssertEqual(finding.signal.metadata["rule"], "nick_documented_uninstall")
        XCTAssertEqual(finding.signal.metadata["ruleTier"], "review")
        XCTAssertTrue(finding.signal.description.contains("Nick Uninstaller"))
    }

    func test_persistedFindingEnvelopeRoundTrips() throws {
        let payload = Data("finding".utf8)
        let original = PersistedExtensionFinding(
            id: UUID(uuidString: "22222222-2222-2222-2222-222222222222")!,
            kind: .integrityViolation,
            timestamp: Date(timeIntervalSince1970: 123),
            payload: payload
        )
        let decoded = try JSONDecoder().decode(
            PersistedExtensionFinding.self,
            from: JSONEncoder().encode(original)
        )
        XCTAssertEqual(decoded.id, original.id)
        XCTAssertEqual(decoded.kind, .integrityViolation)
        XCTAssertEqual(decoded.payload, payload)
    }

    func test_persistedThreatReplayRestoresUIStateAndDeliversEvidence() async throws {
        let event = ESEvent(
            eventType: .authExec,
            processPath: "/usr/bin/open",
            pid: 42,
            parentPid: 1,
            filePath: "/private/tmp/replayed",
            decision: .deny,
            threat: .init(threatName: "Replayed threat", threatFamily: "test")
        )
        let envelope = PersistedExtensionFinding(
            kind: .threat,
            timestamp: Date(timeIntervalSince1970: 123),
            payload: try JSONEncoder().encode(event)
        )
        let client = ExtensionXPCClient()
        client.incidentStoreReadyProvider = { true }
        var deliveredCount = 0
        client.findingHandler = { _ in
            deliveredCount += 1
            return .suppressedByPolicy("test fixture")
        }

        let acknowledgedID = await client.receivePersisted(envelope)

        XCTAssertEqual(client.events.map(\.id), [event.id])
        XCTAssertEqual(deliveredCount, 1)
        XCTAssertEqual(acknowledgedID, event.id)
    }

    func test_failedRootStoreWriteLeavesThreatUnacknowledgedForRedelivery() async throws {
        let event = ESEvent(
            eventType: .authOpen,
            processPath: "/bin/mv",
            pid: 42,
            parentPid: 1,
            filePath: "/Applications/Nick.app/Contents/Resources/test.txt",
            decision: .deny,
            threat: .init(threatName: "Protected path change", threatFamily: "tamper")
        )
        let envelope = PersistedExtensionFinding(
            kind: .threat,
            timestamp: event.timestamp,
            payload: try JSONEncoder().encode(event)
        )
        var journal = [envelope]
        let client = ExtensionXPCClient()
        client.incidentStoreReadyProvider = { true }
        let incidentStore = IncidentStore(persistOnInit: false)
        var deliveries = 0
        client.findingHandler = { finding in
            deliveries += 1
            let alert = ThreatAlert(
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
            _ = incidentStore.ingest([alert])
            return .failed // privileged root-store write rejected
        }

        let firstAcknowledgement = await client.receivePersisted(journal[0])
        if let firstAcknowledgement {
            journal.removeAll { $0.id == firstAcknowledgement }
        }
        XCTAssertNil(firstAcknowledgement)
        XCTAssertEqual(journal.count, 1)
        XCTAssertEqual(incidentStore.incidents.count, 1)

        let redeliveryAcknowledgement = await client.receivePersisted(journal[0])
        XCTAssertNil(redeliveryAcknowledgement)
        XCTAssertEqual(journal.count, 1)
        XCTAssertEqual(deliveries, 2)
        XCTAssertEqual(incidentStore.incidents.count, 1)
        XCTAssertEqual(incidentStore.incidents.first?.alert.occurrenceCount, 1)
    }

    func test_remediationReplayKeepsStableEvidenceID() {
        let report = RemediationReport(
            timestamp: Date(timeIntervalSince1970: 456),
            threatPath: "/private/tmp/eicar.com",
            threatName: "EICAR",
            quarantineRecord: nil,
            actions: []
        )
        XCTAssertEqual(
            ExtensionFinding(report: report).signal.id,
            ExtensionFinding(report: report).signal.id
        )
    }

    func test_extensionWiresGenealogyAndTamperProtection() throws {
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let source = try String(
            contentsOf: root.appendingPathComponent("NickExtension/main.swift"),
            encoding: .utf8
        )
        XCTAssertTrue(source.contains("eventHandler.processTree             = processTree"))
        XCTAssertTrue(source.contains("eventHandler.tamperProtection        = tamperProtection"))
        XCTAssertTrue(source.contains("tamperProtection.onTamperAttempt"))
        XCTAssertTrue(source.contains("processTree.pruneExited()"))

        let tamperSource = try String(
            contentsOf: root.appendingPathComponent(
                "NickExtension/TamperProtection/TamperProtection.swift"
            ),
            encoding: .utf8
        )
        XCTAssertTrue(tamperSource.contains("func shouldBlockRename("))
        XCTAssertTrue(tamperSource.contains("func shouldBlockUnlink("))
        XCTAssertTrue(tamperSource.contains("SecCodeCopyGuestWithAttributes"))
        XCTAssertTrue(tamperSource.contains("SecCodeCheckValidity"))
        XCTAssertTrue(tamperSource.contains("kSecCodeInfoUnique"))

        XCTAssertTrue(source.contains("ES_EVENT_TYPE_AUTH_TRUNCATE"))
        XCTAssertTrue(source.contains("ES_EVENT_TYPE_AUTH_LINK"))
        XCTAssertTrue(source.contains("ES_EVENT_TYPE_AUTH_CLONE"))
    }

    func test_tamperProtectionDoesNotWatchItsMutableEventStore() throws {
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let source = try String(
            contentsOf: root.appendingPathComponent(
                "NickExtension/TamperProtection/TamperProtection.swift"
            ),
            encoding: .utf8
        )

        XCTAssertTrue(source.contains("\"/Applications/Nick.app\""))
        XCTAssertFalse(source.contains(
            "\"/Library/Application Support/com.ehsanazish.nick\""
        ))
    }

    func test_networkFilterActivationDoesNotGateIncidentStoreBootstrap() throws {
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let source = try String(
            contentsOf: root.appendingPathComponent("Nick/App/AppDelegate.swift"),
            encoding: .utf8
        )
        let connectRange = try XCTUnwrap(
            source.range(of: "xpcClient.connect(legacyIncidentPayload:")
        )
        let networkActivationRange = try XCTUnwrap(
            source.range(of: "await NetworkFilterInstaller.shared.ensureBundledVersionIsActive()")
        )

        XCTAssertLessThan(connectRange.lowerBound, networkActivationRange.lowerBound)
        XCTAssertTrue(source.contains(
            "Task { @MainActor [weak self] in\n                guard let self else { return }\n                await NetworkFilterInstaller.shared.ensureBundledVersionIsActive()"
        ))
    }

    func test_viewsDoNotRaceAppDelegateIncidentBootstrap() throws {
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        for path in [
            "Nick/App/Onboarding/ProtectionSetupView.swift",
            "Nick/App/Dashboard/SmartScanSheetView.swift",
        ] {
            let source = try String(
                contentsOf: root.appendingPathComponent(path),
                encoding: .utf8
            )
            XCTAssertFalse(source.contains("xpcClient.connect()"), path)
        }
    }
}

final class ScamGuardianTests: XCTestCase {
    private let guardian = ScamGuardian()

    func test_exactAndSubdomainPhishingMatches() {
        XCTAssertTrue(guardian.isSuspicious(host: "nick-scam-test.invalid"))
        XCTAssertTrue(guardian.isSuspicious(host: "apple-id-login.com"))
        XCTAssertTrue(guardian.isSuspicious(host: "secure.apple-id-login.com"))
    }

    func test_everyCuratedExactDomainUsesExactVerdictAheadOfHeuristics() {
        for domain in guardian.exactBlocklist {
            XCTAssertTrue(guardian.isExactMatch(host: domain), domain)
            let verdict = NetworkProtectionPolicy(configuration: .init()).evaluate(
                host: domain,
                appIdentifier: nil,
                isBlocklisted: guardian.isExactMatch(host:),
                isScam: guardian.isHeuristicMatch(host:)
            )
            XCTAssertEqual(verdict, .observe(.knownThreat), domain)
        }
        XCTAssertFalse(guardian.isExactMatch(host: "paypa1.com"))
        XCTAssertTrue(guardian.isHeuristicMatch(host: "paypa1.com"))
    }

    func test_typosquatMatchesAcrossPublicSuffix() {
        XCTAssertTrue(guardian.isSuspicious(host: "login.paypa1.co.uk"))
        XCTAssertTrue(guardian.isSuspicious(host: "payapl.com"))
    }

    func test_highConfidenceCredentialLureIsBlockedOffline() {
        XCTAssertTrue(guardian.isSuspicious(host: "secure-login-paypal-update.xyz"))
    }

    func test_legitimateBrandAndIPAddressAreAllowed() {
        XCTAssertFalse(guardian.isSuspicious(host: "paypal.com"))
        XCTAssertFalse(guardian.isSuspicious(host: "support.apple.com"))
        XCTAssertFalse(guardian.isSuspicious(host: "example-login.com"))
        XCTAssertFalse(guardian.isSuspicious(host: "192.0.2.1"))
        XCTAssertFalse(guardian.isSuspicious(host: "2001:db8::1"))
    }

    func test_malformedHostFailsOpen() {
        XCTAssertFalse(guardian.isSuspicious(host: "not/a/host"))
        XCTAssertFalse(guardian.isSuspicious(host: ""))
    }
}

@MainActor
final class Step9NetworkIncidentPolicyTests: XCTestCase {
    private func alert(reason: NetworkObservationReason, id: UUID = UUID(), timestamp: Date) -> ThreatAlert {
        let event = NetworkBlockEvent(
            id: id,
            timestamp: timestamp,
            host: reason == .knownThreat ? "nick-scam-test.invalid" : "paypa1.com",
            appIdentifier: "com.apple.curl",
            decision: .observed,
            reason: reason.rawValue,
            reasonTitle: reason.userTitle,
            port: 53
        )
        let finding = NetworkFinding(event: event)
        return ThreatAlert(
            id: id,
            score: finding.score,
            content: AlertContent(
                title: finding.signal.title,
                description: finding.signal.description,
                severity: finding.signal.severity,
                recommendedAction: finding.recommendedAction
            ),
            contributingSignals: [finding.signal],
            timestamp: timestamp
        )
    }

    func test_stalledEndpointActivationAttachesESHandlerButDoesNotIngestBeforeStoreReady() async throws {
        let delegate = AppDelegate()
        let activationStarted = expectation(description: "endpoint activation entered")
        let bootstrap = delegate.beginEndpointBootstrap {
            activationStarted.fulfill()
            while !Task.isCancelled {
                await Task.yield()
            }
        }
        defer { bootstrap.cancel() }
        await fulfillment(of: [activationStarted], timeout: 2)

        let networkEvent = NetworkBlockEvent(
            id: UUID(uuidString: "DDDDDDDD-DDDD-DDDD-DDDD-DDDDDDDDDDDD")!,
            timestamp: Date(timeIntervalSince1970: 100_000),
            host: "nick-scam-test.invalid",
            appIdentifier: "com.apple.curl",
            decision: .observed,
            reason: NetworkObservationReason.knownThreat.rawValue,
            reasonTitle: NetworkObservationReason.knownThreat.userTitle,
            port: 53
        )
        delegate.networkProtection.ingestEvents([networkEvent])
        XCTAssertNotNil(delegate.networkProtection.findingHandler)
        XCTAssertTrue(delegate.engine.incidentStore.incidents.isEmpty)

        let esEvent = ESEvent(
            eventType: .authExec,
            processPath: "/usr/bin/open",
            pid: 42,
            parentPid: 1,
            filePath: "/private/tmp/stalled-activation-eicar.com",
            decision: .deny,
            threat: .init(
                sha256: "stalled-activation",
                threatName: "Stalled Activation Test Threat",
                threatFamily: "test",
                isCodeSigned: true
            )
        )
        let persisted = PersistedExtensionFinding(
            kind: .threat,
            payload: try JSONEncoder().encode(esEvent)
        )
        let beforeReady = await delegate.xpcClient.receivePersisted(persisted)
        XCTAssertNil(beforeReady)
        XCTAssertTrue(delegate.engine.incidentStore.incidents.isEmpty)
        XCTAssertEqual(delegate.xpcClient.ackWithoutPersistenceCount, 0)
        XCTAssertNotNil(delegate.xpcClient.integrityAcknowledgementHandler)
    }

    func test_networkIncidentDeliveryIsEnabledWhileActivityCopyRemainsHonest() {
        XCTAssertTrue(AppDelegate.networkIncidentIngestionEnabled)
        let event = NetworkBlockEvent(
            host: "nick-scam-test.invalid",
            appIdentifier: "com.apple.curl",
            decision: .observed,
            reason: NetworkObservationReason.knownThreat.rawValue,
            reasonTitle: NetworkObservationReason.knownThreat.userTitle,
            port: 53
        )
        let context = NetworkEventContext(event: event)
        XCTAssertEqual(event.reasonTitle, "Known dangerous destination")
        XCTAssertEqual(event.decision, .observed)
        XCTAssertTrue(context.explanation.contains("tried to connect"))
        XCTAssertTrue(context.explanation.contains("recorded the attempt"))
        XCTAssertTrue(context.explanation.contains("did not block it"))
        XCTAssertFalse(context.explanation.contains("connected to"))
        XCTAssertEqual(context.destinationActionLabel, "Allow This Website")
    }

    func test_exactKnownThreatUsesDedicatedTitleHonestWordingAndCoalescedNotification() {
        var clock = Date(timeIntervalSince1970: 50_000)
        let store = IncidentStore(persistOnInit: false, now: { clock })
        let first = alert(reason: .knownThreat, timestamp: clock)
        let firstResult = store.ingest([first])
        let copy = UserFacingAlertBuilder.shared.build(from: first)

        XCTAssertEqual(copy.headline, "Known dangerous destination")
        XCTAssertTrue(copy.explanation.contains("tried to connect"))
        XCTAssertFalse(copy.explanation.contains("connected to"))
        XCTAssertEqual(firstResult.newlyActionable.count, 1)

        clock.addTimeInterval(599)
        let repeated = store.ingest([alert(reason: .knownThreat, timestamp: clock)])
        XCTAssertTrue(repeated.newlyActionable.isEmpty)
        XCTAssertEqual(store.incidents.first?.alert.occurrenceCount, 2)
    }

    func test_filterPayloadUsesLiveAppEntryPointAndStagesOneKnownThreatNotification() async throws {
        let now = Date(timeIntervalSince1970: 70_000)
        let firstEvent = NetworkBlockEvent(
            id: UUID(uuidString: "AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA")!,
            timestamp: now,
            host: "nick-scam-test.invalid",
            appIdentifier: "com.apple.curl",
            decision: .observed,
            reason: NetworkObservationReason.knownThreat.rawValue,
            reasonTitle: NetworkObservationReason.knownThreat.userTitle,
            port: 53
        )
        let repeatedEvent = NetworkBlockEvent(
            id: UUID(uuidString: "BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB")!,
            timestamp: now.addingTimeInterval(599),
            host: "nick-scam-test.invalid",
            appIdentifier: "com.apple.curl",
            decision: .observed,
            reason: NetworkObservationReason.knownThreat.rawValue,
            reasonTitle: NetworkObservationReason.knownThreat.userTitle,
            port: 53
        )
        let payload = try JSONEncoder().encode([firstEvent, repeatedEvent])
        let decoded = try XCTUnwrap(NetworkProtectionManager.decodeEvents(payload))
        let manager = NetworkProtectionManager(eventsURLProvider: { nil })
        let store = IncidentStore(persistOnInit: false, now: { now })
        let delivered = expectation(description: "filter payload reached incident policy")
        delivered.expectedFulfillmentCount = 2
        var notificationCandidates: [ThreatAlert] = []

        manager.incidentPersistenceHandler = { generation in (generation, true) }
        manager.activateDurableCursor(deliveredEventIDs: [])
        manager.findingHandler = { finding in
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
            let result = store.ingest([alert])
            notificationCandidates.append(contentsOf: result.newlyActionable)
            delivered.fulfill()
            return result.outcomes[0]
        }
        manager.ingestEvents(decoded.sorted { $0.timestamp < $1.timestamp })
        await fulfillment(of: [delivered], timeout: 2)

        let incident = try XCTUnwrap(store.incidents.first)
        let signal = try XCTUnwrap(incident.alert.contributingSignals.first)
        let copy = UserFacingAlertBuilder.shared.build(from: incident.alert)
        XCTAssertEqual(store.incidents.count, 1)
        XCTAssertEqual(incident.alert.occurrenceCount, 2)
        XCTAssertEqual(notificationCandidates.count, 1)
        XCTAssertEqual(copy.headline, "Known dangerous destination")
        XCTAssertEqual(signal.metadata["reason"], "network_extension_knownThreat")
        XCTAssertEqual(signal.metadata["rule"], "network_knownThreat")
        XCTAssertEqual(signal.metadata["ruleTier"], "review")
    }

    func test_firstSuccessfulStoreReadCreatesBaselineWithoutReplayingHistory() async {
        let event = NetworkBlockEvent(
            host: "nick-scam-test.invalid",
            appIdentifier: "com.apple.curl",
            decision: .observed,
            reason: NetworkObservationReason.knownThreat.rawValue,
            reasonTitle: NetworkObservationReason.knownThreat.userTitle,
            port: 53
        )
        let manager = NetworkProtectionManager(eventsURLProvider: { nil })
        let baselinePersisted = expectation(description: "startup baseline persisted")
        var deliveryCount = 0
        manager.cursorBootstrapHandler = { eventIDs in
            XCTAssertEqual(eventIDs, [event.id])
            baselinePersisted.fulfill()
            return eventIDs
        }
        manager.incidentPersistenceHandler = { generation in (generation, true) }
        manager.findingHandler = { finding in
            XCTAssertEqual(finding.signal.id, event.id)
            deliveryCount += 1
            return .persisted(1)
        }
        manager.ingestEvents([event])
        await fulfillment(of: [baselinePersisted], timeout: 2)

        manager.ingestEvents([event])
        try? await Task.sleep(for: .milliseconds(100))
        XCTAssertEqual(deliveryCount, 0)
    }

    @MainActor
    func test_sharedStoreWatcherDeliversKnownThreatThroughIncidentAndDurableNotificationOnce() async throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: true
        )
        defer { try? FileManager.default.removeItem(at: directory) }
        let eventsURL = directory.appendingPathComponent("network-block-events.json")
        let now = Date(timeIntervalSince1970: 90_000)
        let event = NetworkBlockEvent(
            id: UUID(uuidString: "CCCCCCCC-CCCC-CCCC-CCCC-CCCCCCCCCCCC")!,
            timestamp: now,
            host: "nick-scam-test.invalid",
            appIdentifier: "com.apple.curl",
            decision: .observed,
            reason: NetworkObservationReason.knownThreat.rawValue,
            reasonTitle: NetworkObservationReason.knownThreat.userTitle,
            port: 53
        )
        let manager = NetworkProtectionManager(eventsURLProvider: { eventsURL })
        let store = IncidentStore(persistOnInit: false, now: { now })
        let notifications = DurableIncidentNotificationQueue()
        let delivered = expectation(description: "filesystem change reached the incident boundary")
        delivered.assertForOverFulfill = true
        var deliveryCount = 0
        var persistedGeneration: UInt64?

        manager.incidentPersistenceHandler = { generation in (generation, true) }
        manager.activateDurableCursor(deliveredEventIDs: [])
        manager.findingHandler = { finding in
            deliveryCount += 1
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
            let result = store.ingest([alert])
            guard let outcome = result.outcomes.first else {
                XCTFail("Expected an ingest outcome")
                return .failed
            }
            guard let generation = outcome.generation else {
                XCTFail("Expected a durable generation")
                return .failed
            }
            notifications.stage(result.newlyActionable, for: generation)
            persistedGeneration = generation
            delivered.fulfill()
            return outcome
        }

        let payload = try JSONEncoder().encode([event])
        try payload.write(to: eventsURL, options: .atomic)
        await fulfillment(of: [delivered], timeout: 2)

        let incident = try XCTUnwrap(store.incidents.first)
        let signal = try XCTUnwrap(incident.alert.contributingSignals.first)
        XCTAssertEqual(store.incidents.count, 1)
        XCTAssertFalse(incident.alert.hasProtectedEvidence)
        XCTAssertEqual(
            UserFacingAlertBuilder.shared.build(from: incident.alert).headline,
            "Known dangerous destination"
        )
        XCTAssertEqual(signal.metadata["ruleTier"], "review")
        let confirmed = notifications.confirm(generation: try XCTUnwrap(persistedGeneration))
        XCTAssertEqual(confirmed.count, 1)
        XCTAssertEqual(confirmed.first?.id, incident.alert.id)

        // A later reload of the exact same filter event must not traverse the
        // handler or stage another notification.
        try payload.write(to: eventsURL, options: .atomic)
        try await Task.sleep(for: .milliseconds(250))
        XCTAssertEqual(deliveryCount, 1)
        XCTAssertEqual(store.incidents.count, 1)
        XCTAssertTrue(
            notifications.confirm(generation: try XCTUnwrap(persistedGeneration)).isEmpty
        )
    }

    func test_failedDurableWriteIsNotClaimedAndNextReloadDeliversOnce() async {
        let event = NetworkBlockEvent(
            host: "nick-scam-test.invalid",
            appIdentifier: "com.apple.curl",
            decision: .observed,
            reason: NetworkObservationReason.knownThreat.rawValue,
            reasonTitle: NetworkObservationReason.knownThreat.userTitle,
            port: 53
        )
        let manager = NetworkProtectionManager()
        manager.activateDurableCursor(deliveredEventIDs: [])
        let submitted = expectation(description: "failed event retried")
        submitted.expectedFulfillmentCount = 2
        var submissionCount = 0
        var persistenceAttempt = 0
        manager.findingHandler = { _ in
            submissionCount += 1
            submitted.fulfill()
            return .persisted(UInt64(submissionCount))
        }
        manager.incidentPersistenceHandler = { generation in
            persistenceAttempt += 1
            return (generation, persistenceAttempt > 1)
        }

        manager.ingestEvents([event])
        while persistenceAttempt < 1 { await Task.yield() }
        while manager.inFlightEventCount > 0 { await Task.yield() }
        manager.ingestEvents([event])
        await fulfillment(of: [submitted], timeout: 2)
        while persistenceAttempt < 2 { await Task.yield() }
        while manager.inFlightEventCount > 0 { await Task.yield() }

        manager.ingestEvents([event])
        try? await Task.sleep(for: .milliseconds(50))
        XCTAssertEqual(submissionCount, 2)
    }

    func test_suppressedNetworkEventIsClaimedAndNotResubmitted() async {
        let event = NetworkBlockEvent(
            host: "review-only.example",
            appIdentifier: "com.example.browser",
            decision: .observed,
            reason: NetworkObservationReason.scamGuardian.rawValue,
            reasonTitle: NetworkObservationReason.scamGuardian.userTitle
        )
        let manager = NetworkProtectionManager()
        manager.activateDurableCursor(deliveredEventIDs: [])
        let submitted = expectation(description: "policy suppression submitted once")
        var submissionCount = 0
        manager.findingHandler = { _ in
            submissionCount += 1
            submitted.fulfill()
            return .suppressedByPolicy("suppression rule")
        }

        manager.ingestEvents([event])
        await fulfillment(of: [submitted], timeout: 2)
        await Task.yield()
        manager.ingestEvents([event])
        try? await Task.sleep(for: .milliseconds(50))
        XCTAssertEqual(submissionCount, 1)
    }

    func test_concurrentReloadWhileNetworkEventIsInFlightSubmitsOnce() async {
        let event = NetworkBlockEvent(
            host: "nick-scam-test.invalid",
            appIdentifier: "com.apple.curl",
            decision: .observed,
            reason: NetworkObservationReason.knownThreat.rawValue,
            reasonTitle: NetworkObservationReason.knownThreat.userTitle
        )
        // This test exercises only explicitly injected events. A production
        // store watcher can otherwise reload another test's 500-event fixture
        // while this handler is suspended, over-fulfilling the submission
        // count in order-dependent full-suite runs.
        let manager = NetworkProtectionManager(eventsURLProvider: { nil })
        manager.activateDurableCursor(deliveredEventIDs: [])
        let submissions = NetworkSubmissionCounter()
        manager.findingHandler = { _ in
            await submissions.increment()
            try? await Task.sleep(for: .milliseconds(100))
            return .persisted(1)
        }
        manager.incidentPersistenceHandler = { generation in (generation, true) }

        manager.ingestEvents([event])
        manager.ingestEvents([event])
        manager.ingestEvents([event])
        for _ in 0..<200 {
            if await submissions.value() > 0 { break }
            try? await Task.sleep(for: .milliseconds(10))
        }
        try? await Task.sleep(for: .milliseconds(150))
        let submissionCount = await submissions.value()
        XCTAssertEqual(submissionCount, 1)
    }

    func test_reloadingFiveHundredDeliveredEventsOneHundredTimesEmitsOneSummaryPerReload() async {
        let events = (0..<500).map { index in
            NetworkBlockEvent(
                timestamp: Date(timeIntervalSince1970: TimeInterval(index)),
                host: "host-\(index).example",
                appIdentifier: "com.example.browser",
                decision: .observed,
                reason: NetworkObservationReason.scamGuardian.rawValue,
                reasonTitle: NetworkObservationReason.scamGuardian.userTitle
            )
        }
        let manager = NetworkProtectionManager()
        manager.activateDurableCursor(deliveredEventIDs: [])
        manager.findingHandler = { _ in .suppressedByPolicy("review-tier") }
        manager.ingestEvents(events)
        while manager.deliveredEventCount < events.count { await Task.yield() }
        let baseline = manager.reloadSummaryCount

        for _ in 0..<100 { manager.ingestEvents(events) }

        XCTAssertEqual(manager.reloadSummaryCount - baseline, 100)
    }

    func test_heuristicScamGuardianIsReviewTierAndSilent() {
        let now = Date(timeIntervalSince1970: 60_000)
        let candidate = alert(reason: .scamGuardian, timestamp: now)
        let store = IncidentStore(persistOnInit: false, now: { now })
        let result = store.ingest([candidate])

        XCTAssertFalse(candidate.hasProtectedEvidence)
        XCTAssertTrue(result.newlyActionable.isEmpty)
        XCTAssertEqual(store.incidents.count, 1)
        XCTAssertTrue(candidate.description.contains("tried to connect"))
        XCTAssertFalse(candidate.description.contains("connected to"))
    }

    func test_knownThreatAndHeuristicUseDifferentIncidentKeys() {
        let now = Date(timeIntervalSince1970: 80_000)
        let known = alert(reason: .knownThreat, timestamp: now)
        let heuristic = alert(reason: .scamGuardian, timestamp: now)

        XCTAssertNotEqual(
            IncidentStore.incidentKey(for: known),
            IncidentStore.incidentKey(for: heuristic)
        )
    }
}
