import XCTest
@testable import Nick

final class NetworkProtectionPolicyTests: XCTestCase {

    @MainActor
    func test_allDeniedTamperOperationsMapThroughXPCFindingAndIncidentStore() throws {
        let store = IncidentStore(persistOnInit: false)
        let target = "/Applications/Nick.app/Contents/Resources/test.txt"

        for (index, operation) in TamperProtectedOperation.allCases.enumerated() {
            let event = tamperEvent(operation: operation, target: target)
            let payload = try JSONEncoder().encode(event)
            let decoded = try JSONDecoder().decode(ESEvent.self, from: payload)
            let finding = try XCTUnwrap(ExtensionFinding(event: decoded))
            let result = store.ingest([tamperAlert(from: finding)])

            XCTAssertEqual(result.newlyActionable.count, 1, operation.rawValue)
            XCTAssertEqual(store.incidents.count, index + 1, operation.rawValue)
            XCTAssertTrue(store.incidents.contains { incident in
                incident.alert.contributingSignals.contains {
                    $0.metadata["tamperOperation"] == operation.rawValue
                }
            }, operation.rawValue)
        }
    }

    @MainActor
    func test_identicalDeniedTamperAttemptsIncrementOccurrenceWithoutDropping() throws {
        let store = IncidentStore(persistOnInit: false)
        let target = "/Applications/Nick.app/Contents/Resources/test.txt"

        for _ in 0..<50 {
            let finding = try XCTUnwrap(ExtensionFinding(
                event: tamperEvent(operation: .openWrite, target: target)
            ))
            _ = store.ingest([tamperAlert(from: finding)])
        }

        XCTAssertEqual(store.incidents.count, 1)
        XCTAssertEqual(store.incidents.first?.alert.occurrenceCount, 50)
    }

    @MainActor
    func test_tamperIncidentIdentityIncludesOperationAndTarget() throws {
        let store = IncidentStore(persistOnInit: false)
        let firstTarget = "/Applications/Nick.app/Contents/Resources/one.txt"
        let secondTarget = "/Applications/Nick.app/Contents/Resources/two.txt"
        let attempts: [(TamperProtectedOperation, String)] = [
            (.create, firstTarget),
            (.truncate, firstTarget),
            (.create, secondTarget),
        ]

        for attempt in attempts {
            let finding = try XCTUnwrap(ExtensionFinding(
                event: tamperEvent(operation: attempt.0, target: attempt.1)
            ))
            _ = store.ingest([tamperAlert(from: finding)])
        }

        XCTAssertEqual(store.incidents.count, 3)
        XCTAssertEqual(Set(store.incidents.map(\.alert.occurrenceCount)), [1])
    }

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

    private func tamperEvent(
        operation: TamperProtectedOperation,
        target: String
    ) -> ESEvent {
        ESEvent(
            eventType: .notifyWrite,
            processPath: "/usr/bin/test-actor",
            pid: 123,
            parentPid: 1,
            filePath: target,
            decision: .deny,
            threat: .init(
                threatName: "Nick protected path change blocked",
                threatFamily: "tamper",
                metadata: [
                    "tamperOperation": operation.rawValue,
                    "tamperTarget": target,
                ]
            )
        )
    }

    private func tamperAlert(from finding: ExtensionFinding) -> ThreatAlert {
        ThreatAlert(
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
        XCTAssertTrue(context.explanation.contains("No connection was blocked"))
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
        XCTAssertEqual(finding.signal.processInfo?.signingStatus, .unknown)
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

    func test_persistedEndpointReplayRestoresUIStateWithoutRedeliveringAlert() async throws {
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
        var deliveredCount = 0
        client.findingHandler = { _ in deliveredCount += 1 }

        await client.receivePersisted(envelope)

        XCTAssertEqual(client.events.map(\.id), [event.id])
        XCTAssertEqual(deliveredCount, 0)
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
