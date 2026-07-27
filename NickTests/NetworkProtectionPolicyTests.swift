import XCTest
@testable import Nick

final class NetworkProtectionPolicyTests: XCTestCase {
    func test_systemExtensionDeclaresFilterDataProvider() throws {
        let repositoryRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
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

    func test_blocklistAndScamReasons_areDistinct() {
        let policy = NetworkProtectionPolicy(configuration: .init())
        XCTAssertEqual(
            policy.evaluate(
                host: "malware.example",
                appIdentifier: nil,
                isBlocklisted: { _ in true },
                isScam: { _ in false }
            ),
            .block(.blocklist)
        )
        XCTAssertEqual(
            policy.evaluate(
                host: "paypa1.com",
                appIdentifier: nil,
                isBlocklisted: { _ in false },
                isScam: { _ in true }
            ),
            .block(.scamGuardian)
        )
    }

    func test_unicodeDomain_normalizesToASCII() {
        let normalized = NetworkProtectionConfiguration.normalizedDomain("bücher.de")
        XCTAssertEqual(normalized, "xn--bcher-kva.de")
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
