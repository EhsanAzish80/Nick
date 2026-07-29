// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import XCTest
@testable import Nick

// MARK: - ThreatCorrelatorTests

/// Unit tests for `ThreatCorrelator`, `CorrelationRule`, and `ThreatAlert`.
final class ThreatCorrelatorTests: XCTestCase {

    private var correlator: ThreatCorrelator!

    override func setUp() async throws {
        try await super.setUp()
        correlator = ThreatCorrelator(windowDuration: 30)
    }

    override func tearDown() async throws {
        await correlator.flush()
        correlator = nil
        try await super.tearDown()
    }

    // MARK: - Ingestion

    func test_ingest_buffersSignals() async {
        let signal = makeSignal(source: .process, severity: .medium)
        await correlator.ingest([signal])
        let count = await correlator.bufferedSignalCount
        XCTAssertEqual(count, 1)
    }

    func test_ingest_prunesExpiredSignals() async {
        let old = makeSignal(timestamp: Date(timeIntervalSinceNow: -60))
        await correlator.ingest([old])
        let count = await correlator.bufferedSignalCount
        XCTAssertEqual(count, 0)
    }

    func test_ingest_retainsSignalInsideWindow() async {
        let recent = makeSignal(timestamp: Date(timeIntervalSinceNow: -5))
        await correlator.ingest([recent])
        let count = await correlator.bufferedSignalCount
        XCTAssertEqual(count, 1)
    }

    func test_ingest_enforcesBufferCap_andRetainsCriticalSignal() async {
        let lowSignals = (0...ThreatCorrelator.maxBufferSize).map { _ in
            makeSignal(severity: .low)
        }
        let critical = makeSignal(
            source: .systemAudit,
            severity: .critical,
            title: "SIP Disabled"
        )

        await correlator.ingest(lowSignals + [critical])

        let count = await correlator.bufferedSignalCount
        let alerts = await correlator.correlate()
        XCTAssertEqual(count, ThreatCorrelator.maxBufferSize)
        XCTAssertTrue(alerts.contains { alert in
            alert.contributingSignals.contains { $0.id == critical.id }
        })
    }

    func test_flush_clearsBuffer() async {
        await correlator.ingest([makeSignal(source: .process, severity: .high)])
        await correlator.flush()
        let count = await correlator.bufferedSignalCount
        XCTAssertEqual(count, 0)
    }

    // MARK: - Correlation Rules

    func test_correlate_emptyBuffer_returnsNoAlerts() async {
        let alerts = await correlator.correlate()
        XCTAssertTrue(alerts.isEmpty)
    }

    func test_correlate_criticalSIPSignal_returnsCriticalAlert() async {
        let sipSignal = makeSignal(source: .systemAudit, severity: .critical, title: "SIP Disabled")
        await correlator.ingest([sipSignal])
        let alerts = await correlator.correlate()
        let criticalAlerts = alerts.filter { $0.severity == .critical }
        XCTAssertFalse(criticalAlerts.isEmpty)
    }

    func test_correlate_reverseShellSignal_returnsCriticalAlert() async {
        let signal = makeSignal(
            source: .network,
            severity: .high,
            metadata: ["reason": "reverse_shell", "process": "bash"]
        )
        await correlator.ingest([signal])
        let alerts = await correlator.correlate()
        let reverseShellAlerts = alerts.filter { $0.score >= 0.9 }
        XCTAssertFalse(reverseShellAlerts.isEmpty)
        XCTAssertEqual(reverseShellAlerts.first?.severity, .critical)
    }

    func test_correlate_unsignedTmpBinarySignal_returnsHighAlert() async {
        let signal = makeSignal(
            source: .process,
            severity: .high,
            metadata: ["reason": "unsigned_temp_path"]
        )
        await correlator.ingest([signal])
        let alerts = await correlator.correlate()
        let highAlerts = alerts.filter { $0.score >= 0.8 }
        XCTAssertFalse(highAlerts.isEmpty)
    }

    func test_correlate_unsignedLaunchAgentSignal_returnsHighAlert() async {
        let signal = makeSignal(source: .persistence, severity: .high, title: "Unsigned launch agent")
        await correlator.ingest([signal])
        let alerts = await correlator.correlate()
        let persistenceAlerts = alerts.filter { $0.contributingSignals.contains { $0.source == .persistence } }
        XCTAssertFalse(persistenceAlerts.isEmpty)
    }

    func test_correlate_threeMediumSignals_returnsHighAlert() async {
        let signals = (0..<3).map { _ in makeSignal(source: .process, severity: .medium) }
        await correlator.ingest(signals)
        let alerts = await correlator.correlate()
        let multipleSignalsAlerts = alerts.filter { $0.contributingSignals.count >= 3 }
        XCTAssertFalse(multipleSignalsAlerts.isEmpty)
    }

    func test_correlate_twoMediumSignals_noMultipleSignalsAlert() async {
        let signals = (0..<2).map { _ in makeSignal(source: .process, severity: .medium) }
        await correlator.ingest(signals)
        let alerts = await correlator.correlate()
        // Should not produce the "multiple signals" alert since threshold is 3
        let multipleAlerts = alerts.filter {
            $0.contributingSignals.count >= 3 && $0.score == 0.75
        }
        XCTAssertTrue(multipleAlerts.isEmpty)
    }

    func test_correlateNew_emitsRuleOnlyOnce_untilReset() async {
        await correlator.ingest([
            makeSignal(source: .network, severity: .high, metadata: ["reason": "reverse_shell"])
        ])

        let first = await correlator.correlateNew()
        let second = await correlator.correlateNew()
        await correlator.resetEmittedRules()
        let afterReset = await correlator.correlateNew()

        XCTAssertFalse(first.isEmpty)
        XCTAssertTrue(second.isEmpty)
        XCTAssertEqual(afterReset.map(\.title), first.map(\.title))
    }

    func test_learnedApproval_suppressesOnlySameSignedBehavior() async {
        let rule = passthroughRule()
        let localCorrelator = ThreatCorrelator(rules: [rule])
        let approved = makeSignedSignal(reason: "expected_action")
        let approvedAlert = rule.evaluate([approved])!
        await localCorrelator.updateSuppressionRules([
            SuppressionRule(
                type: .signedProcess,
                value: "TEAM123|/Applications/Editor.app/Contents/MacOS/Editor",
                behaviorContext: SuppressionRule.contextFingerprint(for: approvedAlert),
                expiresAt: Date().addingTimeInterval(3_600)
            )
        ])

        await localCorrelator.ingest([approved])
        let approvedResult = await localCorrelator.correlateNew()
        XCTAssertTrue(approvedResult.isEmpty)

        await localCorrelator.flush()
        await localCorrelator.resetEmittedRules()
        await localCorrelator.ingest([makeSignedSignal(reason: "new_unusual_action")])
        let changedResult = await localCorrelator.correlateNew()
        XCTAssertFalse(changedResult.isEmpty)
    }

    func test_learnedApproval_neverSuppressesPersistence() async {
        let rule = passthroughRule()
        let localCorrelator = ThreatCorrelator(rules: [rule])
        let persistence = makeSignedSignal(
            source: .persistence,
            severity: .high,
            reason: "launch_agent_added"
        )
        let alert = rule.evaluate([persistence])!
        await localCorrelator.updateSuppressionRules([
            SuppressionRule(
                type: .signedProcess,
                value: "TEAM123|/Applications/Editor.app/Contents/MacOS/Editor",
                behaviorContext: SuppressionRule.contextFingerprint(for: alert),
                expiresAt: Date().addingTimeInterval(3_600)
            )
        ])

        await localCorrelator.ingest([persistence])
        let result = await localCorrelator.correlateNew()
        XCTAssertFalse(result.isEmpty)
    }

    // MARK: - ThreatAlert

    func test_threatAlert_scoreIsClamped_belowZero() {
        let alert = ThreatAlert(
            score: -0.5,
            content: AlertContent(title: "T", description: "D", severity: .low, recommendedAction: "R"),
            contributingSignals: []
        )
        XCTAssertEqual(alert.score, 0.0)
    }

    func test_threatAlert_scoreIsClamped_aboveOne() {
        let alert = ThreatAlert(
            score: 1.5,
            content: AlertContent(title: "T", description: "D", severity: .low, recommendedAction: "R"),
            contributingSignals: []
        )
        XCTAssertEqual(alert.score, 1.0)
    }

    func test_threatAlert_codable_roundTrip() throws {
        let alert = ThreatAlert(
            id: UUID(),
            score: 0.85,
            content: AlertContent(
                title: "Test Alert",
                description: "Test",
                severity: .high,
                recommendedAction: "Do something"
            ),
            contributingSignals: [],
            timestamp: Date(timeIntervalSince1970: 0)
        )
        let data = try JSONEncoder().encode(alert)
        let decoded = try JSONDecoder().decode(ThreatAlert.self, from: data)
        XCTAssertEqual(decoded.id, alert.id)
        XCTAssertEqual(decoded.score, alert.score)
        XCTAssertEqual(decoded.severity, alert.severity)
    }

    // MARK: - Helpers

    private func makeSignal(
        source: MonitorType = .process,
        severity: SignalSeverity = .medium,
        timestamp: Date = Date(),
        title: String = "Test Signal",
        metadata: [String: String] = [:]
    ) -> ThreatSignal {
        ThreatSignal(
            source: source,
            severity: severity,
            timestamp: timestamp,
            title: title,
            description: "Test signal for \(source.rawValue)",
            context: ThreatSignalContext(metadata: metadata)
        )
    }

    private func makeSignedSignal(
        source: MonitorType = .process,
        severity: SignalSeverity = .medium,
        reason: String
    ) -> ThreatSignal {
        let process = NickProcessInfo(
            pid: 42,
            path: "/Applications/Editor.app/Contents/MacOS/Editor",
            name: "Editor",
            parentPID: 1,
            parentName: "launchd",
            signingStatus: .signed(teamID: "TEAM123")
        )
        return ThreatSignal(
            source: source,
            severity: severity,
            title: "Editor behavior",
            description: "Test signed editor behavior",
            context: ThreatSignalContext(
                processInfo: process,
                metadata: ["reason": reason]
            )
        )
    }

    private func passthroughRule() -> CorrelationRule {
        CorrelationRule(
            name: "approval_test",
            score: 0.6,
            severity: .medium
        ) { signals in
            guard !signals.isEmpty else { return nil }
            return ThreatAlert(
                score: 0.6,
                content: AlertContent(
                    title: "Editor behavior",
                    description: "Test",
                    severity: signals.map(\.severity).max() ?? .medium,
                    recommendedAction: "Review"
                ),
                contributingSignals: signals
            )
        }
    }
}
