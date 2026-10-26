import Foundation
import XCTest
@testable import Nick

@MainActor
final class ReplayHarnessTests: XCTestCase {
    private struct TechniqueManifest: Decodable {
        struct Technique: Decodable {
            let id: String
            let name: String
            let category: String
            let mandatory: Bool
            let fixture: String
        }

        let schemaVersion: Int
        let attackVersion: String
        let platform: String
        let techniques: [Technique]
    }

    private struct EndpointFixture: Decodable {
        let schemaVersion: Int
        let eventType: ESEventType
        let processPath: String
        let pid: Int32
        let parentPid: Int32
        let filePath: String?
        let decision: ESDecision
        let threatName: String
        let threatFamily: String
        let metadata: [String: String]
    }

    private struct NetworkFixture: Decodable {
        let schemaVersion: Int
        let host: String
        let appIdentifier: String?
        let decision: NetworkEventDecision
        let reason: String
        let reasonTitle: String
        let port: Int?
    }

    func test_manifestPinsTwentyFourUniqueMacOSTechniques() throws {
        let manifest: TechniqueManifest = try decode("attack-techniques.json")

        XCTAssertEqual(manifest.schemaVersion, 1)
        XCTAssertEqual(manifest.attackVersion, "20.0")
        XCTAssertEqual(manifest.platform, "macOS")
        XCTAssertEqual(manifest.techniques.count, 24)
        XCTAssertEqual(Set(manifest.techniques.map(\.id)).count, 24)
        XCTAssertEqual(Set(manifest.techniques.map(\.fixture)).count, 24)
        XCTAssertTrue(manifest.techniques.allSatisfy {
            !$0.name.isEmpty && !$0.category.isEmpty && !$0.fixture.isEmpty
        })
        XCTAssertEqual(
            Set(manifest.techniques.filter(\.mandatory).map(\.fixture)),
            ["launch-agent-add", "download-to-shell", "keychain-dump-pattern", "nick-tamper"]
        )
    }

    func test_recordedEndpointFixtureUsesRealFindingAndIncidentEntryPoints() async throws {
        let fixture: EndpointFixture = try decode("Fixtures/endpoint-download-to-shell.json")
        XCTAssertEqual(fixture.schemaVersion, 1)
        let event = ESEvent(
            eventType: fixture.eventType,
            processPath: fixture.processPath,
            pid: fixture.pid,
            parentPid: fixture.parentPid,
            filePath: fixture.filePath,
            decision: fixture.decision,
            threat: .init(
                threatName: fixture.threatName,
                threatFamily: fixture.threatFamily,
                metadata: fixture.metadata
            )
        )
        let finding = try XCTUnwrap(ExtensionFinding(event: event))
        let engine = try readyEngine()

        let outcome = await engine.ingestLiveFinding(
            finding.signal,
            score: finding.score,
            recommendedAction: finding.recommendedAction
        )

        guard case .persisted = outcome else {
            return XCTFail("Recorded endpoint fixture was not persisted: \(outcome)")
        }
        let alert = try XCTUnwrap(engine.alerts.first)
        XCTAssertEqual(engine.displayStatus(for: alert), .needsReview)
        XCTAssertEqual(alert.contributingSignals.first?.metadata["matchedCommand"], fixture.metadata["matchedCommand"])
        XCTAssertEqual(alert.contributingSignals.first?.metadata["responsibleChain"], "ChatGPT → Codex CLI → zsh")
    }

    func test_recordedNetworkFixtureUsesRealFindingAndIncidentEntryPoints() async throws {
        let fixture: NetworkFixture = try decode("Fixtures/network-known-threat.json")
        XCTAssertEqual(fixture.schemaVersion, 1)
        let event = NetworkBlockEvent(
            host: fixture.host,
            appIdentifier: fixture.appIdentifier,
            decision: fixture.decision,
            reason: fixture.reason,
            reasonTitle: fixture.reasonTitle,
            port: fixture.port
        )
        let finding = NetworkFinding(event: event)
        let engine = try readyEngine()

        let outcome = await engine.ingestLiveFinding(
            finding.signal,
            score: finding.score,
            recommendedAction: finding.recommendedAction
        )

        guard case .persisted = outcome else {
            return XCTFail("Recorded network fixture was not persisted: \(outcome)")
        }
        let alert = try XCTUnwrap(engine.alerts.first)
        XCTAssertEqual(alert.contributingSignals.first?.metadata["destination"], fixture.host)
        XCTAssertEqual(alert.contributingSignals.first?.metadata["ruleTier"], "protected")
    }

    private func readyEngine() throws -> SecurityEngine {
        let engine = SecurityEngine()
        let payload = try JSONEncoder().encode(IncidentStoreSnapshot(
            incidents: [],
            dismissalTombstones: [],
            expectedCooldowns: [:]
        ))
        try engine.installPrivilegedIncidentStore(
            payload: payload,
            persistence: { _, _, _ in },
            authorizer: { _, _ in .approved(IncidentActionApproval(authorizationExternalForm: nil)) },
            removeLegacyState: false
        )
        return engine
    }

    private func decode<Value: Decodable>(_ relativePath: String) throws -> Value {
        let testFile = URL(fileURLWithPath: #filePath)
        let root = testFile.deletingLastPathComponent().deletingLastPathComponent()
        let url = root.appendingPathComponent("Validation/Replay/\(relativePath)")
        return try JSONDecoder().decode(Value.self, from: Data(contentsOf: url))
    }
}
