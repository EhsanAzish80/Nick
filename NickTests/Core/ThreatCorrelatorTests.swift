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
        // Create a correlator with a tiny window so signals expire instantly
        let tiny = ThreatCorrelator(windowDuration: 0.0001)
        let old = makeStaleSigal()
        await tiny.ingest([old])
        // After ingest, the stale signal should be pruned
        // (pruning is on ingest + correlate)
        try? await Task.sleep(nanoseconds: 1_000_000) // 1ms
        await tiny.ingest([]) // triggers prune
        let count = await tiny.bufferedSignalCount
        XCTAssertEqual(count, 0)
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

    // MARK: - ThreatAlert

    func test_threatAlert_scoreIsClamped_belowZero() {
        let alert = ThreatAlert(
            score: -0.5,
            title: "T", description: "D", severity: .low,
            contributingSignals: [], recommendedAction: "R"
        )
        XCTAssertEqual(alert.score, 0.0)
    }

    func test_threatAlert_scoreIsClamped_aboveOne() {
        let alert = ThreatAlert(
            score: 1.5,
            title: "T", description: "D", severity: .low,
            contributingSignals: [], recommendedAction: "R"
        )
        XCTAssertEqual(alert.score, 1.0)
    }

    func test_threatAlert_codable_roundTrip() throws {
        let alert = ThreatAlert(
            id: UUID(),
            score: 0.85,
            title: "Test Alert",
            description: "Test",
            severity: .high,
            contributingSignals: [],
            timestamp: Date(timeIntervalSince1970: 0),
            recommendedAction: "Do something"
        )
        let data = try JSONEncoder().encode(alert)
        let decoded = try JSONDecoder().decode(ThreatAlert.self, from: data)
        XCTAssertEqual(decoded.id, alert.id)
        XCTAssertEqual(decoded.score, alert.score)
        XCTAssertEqual(decoded.severity, alert.severity)
    }

    // MARK: - Helpers

    private func makeSignal(
        source: MonitorType,
        severity: SignalSeverity,
        title: String = "Test Signal",
        metadata: [String: String] = [:]
    ) -> ThreatSignal {
        ThreatSignal(
            source: source,
            severity: severity,
            title: title,
            description: "Test signal for \(source.rawValue)",
            metadata: metadata
        )
    }

    private func makeStaleSigal() -> ThreatSignal {
        ThreatSignal(
            id: UUID(),
            source: .process,
            severity: .low,
            timestamp: Date(timeIntervalSinceNow: -3600), // 1 hour ago
            title: "Old Signal",
            description: "Should be pruned"
        )
    }
}
