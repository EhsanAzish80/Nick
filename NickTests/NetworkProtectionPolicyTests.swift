import XCTest
@testable import Nick

final class NetworkProtectionPolicyTests: XCTestCase {
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
            threat: .init(sha256: "abc", threatName: "EICAR", threatFamily: "test")
        )
        let finding = try XCTUnwrap(ExtensionFinding(event: event))
        XCTAssertEqual(finding.signal.id, event.id)
        XCTAssertEqual(finding.signal.severity, .critical)
        XCTAssertEqual(finding.signal.metadata["ruleTier"], "protected")
        XCTAssertEqual(finding.signal.fileInfo?.path, "/private/tmp/eicar.com")
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
