import CryptoKit
import XCTest
@testable import Nick

final class SignedThreatIntelligenceBundleTests: XCTestCase {
    func test_productionUpdateCapabilityIsSharedAcrossExecutableBundles() {
        XCTAssertTrue(ThreatIntelligenceBundleTrustAnchor.updatesEnabled)
    }

    func test_validBundlePromotesAndReportsProvenance() throws {
        let fixture = try Fixture()
        let store = fixture.store(enabled: true)
        let provenance = try store.stageAndPromote(try fixture.data(version: 1)) { payload in
            payload.hashes.count == 1 && payload.domains.count == 1
        }
        XCTAssertEqual(provenance.version, 1)
        XCTAssertEqual(provenance.source, "Nick test intelligence")
        XCTAssertFalse(provenance.usingLastKnownGood)
        XCTAssertEqual(store.loadBestAvailable()?.0.version, 1)
        let attributes = try FileManager.default.attributesOfItem(
            atPath: fixture.directory.appendingPathComponent("current.json").path
        )
        XCTAssertEqual((attributes[.posixPermissions] as? NSNumber)?.intValue, 0o600)
    }

    func test_invalidSignatureMalformedExpiryAndRollbackLeaveCurrentUntouched() throws {
        let fixture = try Fixture()
        let store = fixture.store(enabled: true)
        _ = try store.stageAndPromote(try fixture.data(version: 2)) { _ in true }

        XCTAssertThrowsError(try store.stageAndPromote(Data("{".utf8)) { _ in true })
        XCTAssertThrowsError(try store.stageAndPromote(try fixture.data(version: 3, tamper: true)) { _ in true })
        XCTAssertThrowsError(try store.stageAndPromote(try fixture.data(version: 3, expired: true)) { _ in true })
        XCTAssertThrowsError(try store.stageAndPromote(try fixture.data(version: 1)) { _ in true })
        XCTAssertEqual(store.loadBestAvailable()?.0.version, 2)
    }

    func test_installFailuresHaveStablePlainReasonCodes() {
        XCTAssertEqual(
            ThreatBundleInstallResultCode(error: ThreatIntelligenceBundleValidationError.rollback),
            .olderThanInstalled
        )
        XCTAssertEqual(
            ThreatBundleInstallResultCode(error: ThreatIntelligenceBundleValidationError.invalidSignature),
            .invalidSignature
        )
        XCTAssertEqual(
            ThreatBundleInstallResultCode(error: ThreatIntelligenceBundleValidationError.expired),
            .expired
        )
        XCTAssertEqual(ThreatBundleInstallResultCode.expired.plainDescription, "Protection updates expired")
    }

    func test_refreshPolicySkipsUnchangedETagResponseAndInstallsNewPayload() {
        XCTAssertEqual(
            ThreatBundleRefreshPolicy.decision(statusCode: 304, byteCount: 0),
            .notModified
        )
        XCTAssertEqual(
            ThreatBundleRefreshPolicy.decision(statusCode: 200, byteCount: 1_024),
            .install
        )
        XCTAssertEqual(
            ThreatBundleRefreshPolicy.decision(
                statusCode: 200,
                byteCount: ThreatBundleUpdateEndpointPolicy.maximumDownloadBytes + 1
            ),
            .tooLarge
        )
    }

    func test_offlineFailuresUseBoundedExponentialBackoff() {
        XCTAssertEqual(ThreatBundleRefreshPolicy.nextDelay(consecutiveFailures: 0), 6 * 60 * 60)
        XCTAssertEqual(ThreatBundleRefreshPolicy.nextDelay(consecutiveFailures: 1), 15 * 60)
        XCTAssertEqual(ThreatBundleRefreshPolicy.nextDelay(consecutiveFailures: 2), 30 * 60)
        XCTAssertEqual(ThreatBundleRefreshPolicy.nextDelay(consecutiveFailures: 20), 6 * 60 * 60)
    }

    func test_publishGateRejectsCandidateWithoutReplacingCurrent() throws {
        let fixture = try Fixture()
        let store = fixture.store(enabled: true)
        _ = try store.stageAndPromote(try fixture.data(version: 1)) { _ in true }
        XCTAssertThrowsError(try store.stageAndPromote(try fixture.data(version: 2)) { _ in false })
        XCTAssertEqual(store.loadBestAvailable()?.0.version, 1)
    }

    func test_corruptCurrentFallsBackToLastKnownGood() throws {
        let fixture = try Fixture()
        let store = fixture.store(enabled: true)
        _ = try store.stageAndPromote(try fixture.data(version: 1)) { _ in true }
        _ = try store.stageAndPromote(try fixture.data(version: 2)) { _ in true }
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
        XCTAssertThrowsError(try store.stageAndPromote(try fixture.data(version: 1)) { _ in true }) { error in
            XCTAssertEqual(error as? ThreatIntelligenceBundleValidationError, .updatesDisabled)
        }
    }

    func test_blockableRuleRequiresSignedHighConfidenceClassification() throws {
        let fixture = try Fixture()
        let store = fixture.store(enabled: true)
        XCTAssertThrowsError(
            try store.stageAndPromote(try fixture.data(version: 1, invalidBlockableRule: true)) { _ in true }
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

    func test_pythonPublisherBytesVerifyInSwiftAndTamperingIsRejected() throws {
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent()
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("nick-python-bundle-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }

        let privateKey = directory.appendingPathComponent("test-private.pem")
        let publicKey = directory.appendingPathComponent("test-public.pem")
        let publicDER = directory.appendingPathComponent("test-public.der")
        let output = directory.appendingPathComponent("bundle.json")
        let openssl = try openssl3Path()
        try run(openssl, ["genpkey", "-algorithm", "ED25519", "-out", privateKey.path])
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: privateKey.path)
        try run(openssl, ["pkey", "-in", privateKey.path, "-pubout", "-out", publicKey.path])
        try run(openssl, [
            "pkey", "-in", privateKey.path, "-pubout", "-outform", "DER", "-out", publicDER.path,
        ])
        try run("/usr/bin/python3", [
            root.appendingPathComponent("Scripts/build-first-threat-bundle.py").path,
            "--private-key", privateKey.path,
            "--openssl", openssl,
            "--verification-public-key", publicKey.path,
            "--output", output.path,
            "--version", "1",
        ], environment: ["NICK_BUNDLE_TEST": "1"])

        let der = try Data(contentsOf: publicDER)
        XCTAssertGreaterThanOrEqual(der.count, 32)
        let rawPublicKey = Data(der.suffix(32))
        let bundleData = try Data(contentsOf: output)
        let bundle = try JSONDecoder().decode(SignedThreatIntelligenceBundle.self, from: bundleData)
        let validator = ThreatIntelligenceBundleValidator(publicKey: rawPublicKey)
        XCTAssertNoThrow(try validator.validate(bundle, now: Date(), highestAcceptedVersion: nil))

        var tampered = bundle.payloadData
        tampered[0] ^= 0x01
        let altered = SignedThreatIntelligenceBundle(
            payloadData: tampered,
            signature: bundle.signature
        )
        XCTAssertThrowsError(try validator.validate(altered, now: Date(), highestAcceptedVersion: nil)) {
            XCTAssertEqual($0 as? ThreatIntelligenceBundleValidationError, .invalidSignature)
        }
    }
}

private extension SignedThreatIntelligenceBundleTests {
    func openssl3Path() throws -> String {
        let candidates = [
            "/opt/homebrew/opt/openssl@3/bin/openssl",
            "/usr/local/opt/openssl@3/bin/openssl",
            "/opt/homebrew/bin/openssl",
            "/usr/local/bin/openssl",
        ]
        return try XCTUnwrap(candidates.first(where: { FileManager.default.isExecutableFile(atPath: $0) }))
    }

    func run(
        _ executable: String,
        _ arguments: [String],
        environment: [String: String] = [:]
    ) throws {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        process.environment = ProcessInfo.processInfo.environment.merging(environment) { _, new in new }
        let error = Pipe()
        process.standardError = error
        try process.run()
        process.waitUntilExit()
        if process.terminationStatus != 0 {
            let message = String(data: error.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
            XCTFail("\(executable) failed: \(message)")
        }
    }

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
        ) throws -> Data {
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
            let signature = try privateKey.signature(
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
            return try SignedThreatIntelligenceBundle.canonicalEncoder.encode(envelope)
        }
    }
}
