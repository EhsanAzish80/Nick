import CryptoKit
import XCTest
@testable import Nick

final class SignedThreatIntelligenceBundleTests: XCTestCase {
    func test_validBundlePromotesAndReportsProvenance() throws {
        let fixture = try Fixture()
        let store = fixture.store(enabled: true)
        let provenance = try store.stageAndPromote(fixture.data(version: 1)) { payload in
            payload.hashes.count == 1 && payload.domains.count == 1
        }
        XCTAssertEqual(provenance.version, 1)
        XCTAssertEqual(provenance.source, "Nick test intelligence")
        XCTAssertFalse(provenance.usingLastKnownGood)
        XCTAssertEqual(store.loadBestAvailable()?.0.version, 1)
    }

    func test_invalidSignatureMalformedExpiryAndRollbackLeaveCurrentUntouched() throws {
        let fixture = try Fixture()
        let store = fixture.store(enabled: true)
        _ = try store.stageAndPromote(fixture.data(version: 2)) { _ in true }

        XCTAssertThrowsError(try store.stageAndPromote(Data("{".utf8)) { _ in true })
        XCTAssertThrowsError(try store.stageAndPromote(fixture.data(version: 3, tamper: true)) { _ in true })
        XCTAssertThrowsError(try store.stageAndPromote(fixture.data(version: 3, expired: true)) { _ in true })
        XCTAssertThrowsError(try store.stageAndPromote(fixture.data(version: 1)) { _ in true })
        XCTAssertEqual(store.loadBestAvailable()?.0.version, 2)
    }

    func test_publishGateRejectsCandidateWithoutReplacingCurrent() throws {
        let fixture = try Fixture()
        let store = fixture.store(enabled: true)
        _ = try store.stageAndPromote(fixture.data(version: 1)) { _ in true }
        XCTAssertThrowsError(try store.stageAndPromote(fixture.data(version: 2)) { _ in false })
        XCTAssertEqual(store.loadBestAvailable()?.0.version, 1)
    }

    func test_corruptCurrentFallsBackToLastKnownGood() throws {
        let fixture = try Fixture()
        let store = fixture.store(enabled: true)
        _ = try store.stageAndPromote(fixture.data(version: 1)) { _ in true }
        _ = try store.stageAndPromote(fixture.data(version: 2)) { _ in true }
        try Data("corrupt".utf8).write(
            to: fixture.directory.appendingPathComponent("current.json"),
            options: .atomic
        )
        let loaded = try XCTUnwrap(store.loadBestAvailable())
        XCTAssertEqual(loaded.0.version, 1)
        XCTAssertTrue(loaded.1.usingLastKnownGood)
    }

    func test_updatesRemainOffWithoutExplicitFeatureFlag() throws {
        let fixture = try Fixture()
        let store = fixture.store(enabled: false)
        XCTAssertThrowsError(try store.stageAndPromote(fixture.data(version: 1)) { _ in true }) { error in
            XCTAssertEqual(error as? ThreatIntelligenceBundleValidationError, .updatesDisabled)
        }
    }

    func test_blockableRuleRequiresSignedHighConfidenceClassification() throws {
        let fixture = try Fixture()
        let store = fixture.store(enabled: true)
        XCTAssertThrowsError(
            try store.stageAndPromote(fixture.data(version: 1, invalidBlockableRule: true)) { _ in true }
        ) { error in
            XCTAssertEqual(error as? ThreatIntelligenceBundleValidationError, .invalidEntry)
        }
    }

    func test_updateEndpointIsPinnedToExpectedHTTPSLocation() {
        XCTAssertTrue(ThreatBundleUpdateEndpointPolicy.allows(
            URL(string: "https://3nsofts.com/nick/threat-intelligence/current.json")!
        ))
        XCTAssertFalse(ThreatBundleUpdateEndpointPolicy.allows(
            URL(string: "http://3nsofts.com/nick/threat-intelligence/current.json")!
        ))
        XCTAssertFalse(ThreatBundleUpdateEndpointPolicy.allows(
            URL(string: "https://example.com/nick/threat-intelligence/current.json")!
        ))
        XCTAssertFalse(ThreatBundleUpdateEndpointPolicy.allows(
            URL(string: "https://3nsofts.com/nick/threat-intelligence/other.json")!
        ))
    }
}

private extension SignedThreatIntelligenceBundleTests {
    final class Fixture {
        let privateKey = Curve25519.Signing.PrivateKey()
        let directory: URL
        let clock = Date(timeIntervalSince1970: 1_800_000_000)

        init() throws {
            directory = FileManager.default.temporaryDirectory
                .appendingPathComponent("nick-intelligence-\(UUID().uuidString)", isDirectory: true)
        }

        deinit { try? FileManager.default.removeItem(at: directory) }

        func store(enabled: Bool) -> SignedThreatIntelligenceBundleStore {
            SignedThreatIntelligenceBundleStore(
                directory: directory,
                publicKey: privateKey.publicKey.rawRepresentation,
                updatesEnabled: enabled,
                now: { [clock] in clock }
            )
        }

        func data(
            version: Int,
            expired: Bool = false,
            tamper: Bool = false,
            invalidBlockableRule: Bool = false
        ) -> Data {
            var payload = ThreatIntelligenceBundlePayload(
                schemaVersion: 1,
                version: version,
                issuedAt: clock.addingTimeInterval(-60),
                expiresAt: expired ? clock.addingTimeInterval(-1) : clock.addingTimeInterval(86_400),
                source: "Nick test intelligence",
                hashes: [.init(
                    sha256: String(repeating: "a", count: 64),
                    name: "Safe fixture",
                    family: "Test",
                    severity: "high"
                )],
                domains: ["example.test"],
                ipAddresses: [],
                rules: [.init(
                    identifier: "test_rule",
                    confidence: invalidBlockableRule ? .review : .high,
                    blockable: true
                )]
            )
            let signature = try! privateKey.signature(
                for: SignedThreatIntelligenceBundle.canonicalEncoder.encode(payload)
            )
            if tamper {
                payload = ThreatIntelligenceBundlePayload(
                    schemaVersion: payload.schemaVersion,
                    version: payload.version + 100,
                    issuedAt: payload.issuedAt,
                    expiresAt: payload.expiresAt,
                    source: payload.source,
                    hashes: payload.hashes,
                    domains: payload.domains,
                    ipAddresses: payload.ipAddresses,
                    rules: payload.rules
                )
            }
            let envelope = SignedThreatIntelligenceBundle(payload: payload, signature: signature)
            return try! SignedThreatIntelligenceBundle.canonicalEncoder.encode(envelope)
        }
    }
}
