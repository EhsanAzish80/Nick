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

    func test_correlate_shellNetworkObservation_returnsNoAlert() async {
        let signal = makeSignal(source: .network, severity: .medium, metadata: ["reason": "shell_network_observation", "process": "zsh"])
        await correlator.ingest([signal])
        let alerts = await correlator.correlate()
        XCTAssertTrue(alerts.isEmpty)
    }

    func test_correlate_invalidTmpBinarySignal_returnsHighAlert() async {
        let signal = makeSignal(
            source: .process,
            severity: .high,
            metadata: ["reason": "invalid_temp_signature"]
        )
        await correlator.ingest([signal])
        let alerts = await correlator.correlate()
        let highAlerts = alerts.filter { $0.score >= 0.8 }
        XCTAssertFalse(highAlerts.isEmpty)
    }

    func test_correlate_unsignedTmpBinarySignal_returnsNoStandaloneAlert() async {
        let signal = makeSignal(source: .process, severity: .medium, metadata: ["reason": "unsigned_temp_path"])
        await correlator.ingest([signal])
        let alerts = await correlator.correlate()
        XCTAssertTrue(alerts.isEmpty)
    }

    func test_correlate_unsignedLaunchAgentSignal_returnsHighAlert() async {
        let signal = makeSignal(source: .persistence, severity: .high, title: "Unsigned launch agent", metadata: ["reason": "unsigned_launch_agent"])
        await correlator.ingest([signal])
        let alerts = await correlator.correlate()
        let persistenceAlerts = alerts.filter { $0.contributingSignals.contains { $0.source == .persistence } }
        XCTAssertFalse(persistenceAlerts.isEmpty)
    }

    func test_correlate_missingPersistenceExecutable_returnsReviewAlert() async {
        let signal = makeSignal(
            source: .persistence,
            severity: .medium,
            title: "Launch item with missing executable",
            metadata: ["reason": "persist_executable_missing"]
        )
        await correlator.ingest([signal])
        let alerts = await correlator.correlate()
        XCTAssertTrue(alerts.contains {
            $0.title == "Startup item points to a missing file" && $0.severity == .medium
        })
    }

    func test_correlate_threeUnrelatedMediumSignals_returnsNoCombinedAlert() async {
        let signals = (0..<3).map { index in
            makeSignal(source: .process, severity: .medium, metadata: ["reason": "reason_\(index)"])
        }
        await correlator.ingest(signals)
        let alerts = await correlator.correlate()
        XCTAssertTrue(alerts.allSatisfy { $0.contributingSignals.count < 3 })
    }

    func test_correlate_threeDistinctSignalsForSameProcess_returnsHighAlert() async {
        let signals = ["unsigned_temp_path", "suspicious_parent_chain", "unusual_network"].map {
            makeSignedSignal(severity: .medium, reason: $0)
        }
        await correlator.ingest(signals)
        let alerts = await correlator.correlate()
        XCTAssertTrue(alerts.contains { $0.contributingSignals.count >= 3 && $0.score == 0.75 })
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

    func test_threatAlert_deduplicationKey_ignoresSeverityAndUUID() {
        let signal = makeProcessSignal(reason: "unsigned_temp_path")
        let low = makeAlert(signal: signal, severity: .medium)
        let high = makeAlert(signal: signal, severity: .high)

        XCTAssertNotEqual(low.id, high.id)
        XCTAssertEqual(low.deduplicationKey, high.deduplicationKey)
    }

    func test_threatAlert_deduplicationKey_changesWithParentContext() {
        let terminal = makeProcessSignal(reason: "shell_child", parentName: "Terminal")
        let document = makeProcessSignal(reason: "shell_child", parentName: "Microsoft Word")

        XCTAssertNotEqual(
            makeAlert(signal: terminal).deduplicationKey,
            makeAlert(signal: document).deduplicationKey
        )
    }

    func test_threatAlert_mergingOccurrence_preservesIncidentAndCountsRepeats() {
        let firstDate = Date(timeIntervalSince1970: 100)
        let secondDate = Date(timeIntervalSince1970: 200)
        let signal = makeProcessSignal(reason: "developer_command")
        let first = makeAlert(signal: signal, severity: .medium, timestamp: firstDate)
        let second = makeAlert(signal: signal, severity: .high, timestamp: secondDate)

        let merged = first.mergingOccurrence(second)

        XCTAssertEqual(merged.id, first.id)
        XCTAssertEqual(merged.firstSeen, firstDate)
        XCTAssertEqual(merged.lastSeen, secondDate)
        XCTAssertEqual(merged.occurrenceCount, 2)
        XCTAssertEqual(merged.severity, .high)
    }

    func test_threatAlert_decodesPersistedAlertWithoutOccurrenceFields() throws {
        let original = makeAlert(signal: makeProcessSignal(reason: "legacy"))
        let encoded = try JSONEncoder().encode(original)
        var object = try XCTUnwrap(JSONSerialization.jsonObject(with: encoded) as? [String: Any])
        object.removeValue(forKey: "firstSeen")
        object.removeValue(forKey: "lastSeen")
        object.removeValue(forKey: "occurrenceCount")
        let legacyData = try JSONSerialization.data(withJSONObject: object)

        let decoded = try JSONDecoder().decode(ThreatAlert.self, from: legacyData)

        XCTAssertEqual(decoded.firstSeen, decoded.timestamp)
        XCTAssertEqual(decoded.lastSeen, decoded.timestamp)
        XCTAssertEqual(decoded.occurrenceCount, 1)
    }

    func test_threatAlert_evidenceState_marksMissingFileResolved() {
        let fileSignal = ThreatSignal(
            source: .filesystem,
            severity: .high,
            title: "Temporary VM artifact",
            description: "Test",
            context: ThreatSignalContext(
                fileInfo: FileInfo(
                    path: "/private/tmp/deleted-vm-artifact",
                    sha256Hash: nil,
                    entropy: nil,
                    signingStatus: nil,
                    sizeBytes: nil
                )
            )
        )
        let alert = makeAlert(signal: fileSignal)

        XCTAssertEqual(
            alert.evidenceState(fileExists: { _ in false }, processIsRunning: { _ in false }),
            .fileNoLongerExists("/private/tmp/deleted-vm-artifact")
        )
        XCTAssertFalse(alert.hasActionableEvidence)
    }

    func test_threatAlert_evidenceState_rejectsReusedPIDIdentity() {
        let alert = makeAlert(signal: makeProcessSignal(reason: "pid_reuse"))

        XCTAssertEqual(
            alert.evidenceState(fileExists: { _ in false }, processIsRunning: { process in
                process.name == "different-process"
            }),
            .processEnded
        )
    }

    func test_menuBarAttentionState_isProtectedWithoutActionableAlerts() {
        let trusted = makeAlert(
            signal: makeSignal(severity: .info),
            severity: .info
        )

        XCTAssertEqual(MenuBarAttentionState.evaluate([]), .protected)
        XCTAssertEqual(MenuBarAttentionState.evaluate([trusted]), .protected)
    }

    func test_menuBarAttentionState_requestsReviewForMediumAlert() {
        let alert = makeAlert(signal: makeSignal(), severity: .medium)

        XCTAssertEqual(MenuBarAttentionState.evaluate([alert]), .review)
    }

    func test_menuBarAttentionState_isUrgentForHighAlert() {
        let alert = makeAlert(signal: makeSignal(severity: .high), severity: .high)

        XCTAssertEqual(MenuBarAttentionState.evaluate([alert]), .urgent)
    }

    func test_menuBarAttentionState_ignoresAlertWhoseFileIsGone() {
        let path = "/private/tmp/nick-menu-bar-test-\(UUID().uuidString)"
        let fileSignal = ThreatSignal(
            source: .filesystem,
            severity: .critical,
            title: "Removed temporary artifact",
            description: "Test",
            context: ThreatSignalContext(
                fileInfo: FileInfo(
                    path: path,
                    sha256Hash: nil,
                    entropy: nil,
                    signingStatus: nil,
                    sizeBytes: nil
                )
            )
        )
        let alert = makeAlert(signal: fileSignal, severity: .critical)

        XCTAssertEqual(MenuBarAttentionState.evaluate([alert]), .protected)
        XCTAssertFalse(alert.hasActionableEvidence)
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

    private func makeProcessSignal(
        reason: String,
        parentName: String = "Xcode"
    ) -> ThreatSignal {
        let process = NickProcessInfo(
            pid: 42,
            path: "/usr/bin/curl",
            name: "curl",
            parentPID: 41,
            parentName: parentName,
            signingStatus: .signed(teamID: "APPLE"),
            metadata: ProcessMetadata(startTime: Date(timeIntervalSince1970: 50))
        )
        return ThreatSignal(
            source: .process,
            severity: .medium,
            title: "curl behavior",
            description: "Test process behavior",
            context: ThreatSignalContext(
                processInfo: process,
                metadata: ["reason": reason]
            )
        )
    }

    private func makeAlert(
        signal: ThreatSignal,
        severity: SignalSeverity = .medium,
        timestamp: Date = Date(timeIntervalSince1970: 100)
    ) -> ThreatAlert {
        ThreatAlert(
            score: severity == .high ? 0.85 : 0.6,
            content: AlertContent(
                title: "Command needs review",
                description: "Test",
                severity: severity,
                recommendedAction: "Review"
            ),
            contributingSignals: [signal],
            timestamp: timestamp
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
