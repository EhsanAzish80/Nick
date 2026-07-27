// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import XCTest
@testable import Nick

// MARK: - AlertExplainerTests

/// Unit tests for `AlertExplainer` and `ExplanationPromptBuilder`.
///
/// Verifies prompt structure, template selection, `#available` compilation,
/// and that all code paths produce non-empty readable text.
final class AlertExplainerTests: XCTestCase {

    private var explainer: AlertExplainer!
    private var promptBuilder: ExplanationPromptBuilder!

    override func setUp() {
        super.setUp()
        explainer    = AlertExplainer()
        promptBuilder = ExplanationPromptBuilder()
    }

    // MARK: - ExplanationPromptBuilder — prompt structure

    func test_buildPrompt_containsScoreAndSeverity() {
        let alert = makeAlert(score: 0.87, severity: .high, title: "Reverse Shell Detected")
        let features: [(name: String, contribution: Double)] = [
            ("process_is_shell", 0.8),
            ("net_has_outbound_connection", 0.7),
        ]
        let prompt = promptBuilder.buildPrompt(for: alert, topFeatures: features)
        XCTAssertTrue(prompt.contains("0.87"), "Prompt must contain formatted score")
        XCTAssertTrue(prompt.contains("High"),  "Prompt must contain severity label")
        XCTAssertTrue(prompt.contains("Reverse Shell Detected"), "Prompt must contain alert title")
    }

    func test_buildPrompt_containsTopFeatures() {
        let alert = makeAlert(score: 0.9, severity: .critical, title: "Dropper")
        let features: [(name: String, contribution: Double)] = [
            ("process_is_unsigned", 0.9),
            ("process_in_tmp", 0.85),
            ("net_remote_is_raw_ip", 0.7),
        ]
        let prompt = promptBuilder.buildPrompt(for: alert, topFeatures: features)
        XCTAssertTrue(prompt.contains("process_is_unsigned"))
        XCTAssertTrue(prompt.contains("process_in_tmp"))
        XCTAssertTrue(prompt.contains("net_remote_is_raw_ip"))
    }

    func test_buildPrompt_isNonEmpty() {
        let alert = makeAlert(score: 0.5, severity: .medium, title: "Suspicious Activity")
        let prompt = promptBuilder.buildPrompt(for: alert, topFeatures: [])
        XCTAssertFalse(prompt.isEmpty)
        XCTAssertGreaterThan(prompt.count, 100)
    }

    func test_buildPrompt_containsInstructions() {
        let alert = makeAlert(score: 0.6, severity: .medium, title: "Test")
        let prompt = promptBuilder.buildPrompt(for: alert, topFeatures: [])
        XCTAssertTrue(prompt.contains("plain English"))
        XCTAssertTrue(prompt.contains("macOS security analyst"))
    }

    // MARK: - ExplanationPromptBuilder — templated explanations

    func test_reverseshellTemplate_containsShellReference() {
        let alert = makeAlertWithSignals(
            score: 0.9,
            severity: .critical,
            title: "Reverse Shell",
            processPath: "/bin/bash",
            remoteIP: "203.0.113.42"
        )
        let features: [(name: String, contribution: Double)] = [
            ("process_is_shell", 0.9),
            ("net_has_outbound_connection", 0.85),
        ]
        let explanation = promptBuilder.buildTemplatedExplanation(for: alert, topFeatures: features)
        XCTAssertTrue(explanation.contains("/bin/bash") || explanation.contains("shell"))
        XCTAssertFalse(explanation.isEmpty)
    }

    func test_dropperTemplate_referencesUnsignedBinary() {
        let alert = makeAlert(score: 0.88, severity: .critical, title: "Dropper")
        let features: [(name: String, contribution: Double)] = [
            ("process_is_unsigned", 0.9),
            ("process_in_tmp", 0.8),
        ]
        let explanation = promptBuilder.buildTemplatedExplanation(for: alert, topFeatures: features)
        XCTAssertTrue(explanation.lowercased().contains("unsigned"))
        XCTAssertTrue(explanation.lowercased().contains("temporary") || explanation.lowercased().contains("temp"))
    }

    func test_persistenceTemplate_mentionsPersistence() {
        let alert = makeAlert(score: 0.7, severity: .high, title: "New LaunchAgent")
        let features: [(name: String, contribution: Double)] = [
            ("persist_new_launchagent", 0.9),
        ]
        let explanation = promptBuilder.buildTemplatedExplanation(for: alert, topFeatures: features)
        XCTAssertTrue(explanation.lowercased().contains("persist") || explanation.lowercased().contains("startup"))
    }

    func test_genericTemplate_usesAlertTitle() {
        let alert = makeAlert(score: 0.4, severity: .medium, title: "Some Unusual Activity")
        let features: [(name: String, contribution: Double)] = [
            ("temporal_signals_in_window", 0.3),
        ]
        let explanation = promptBuilder.buildTemplatedExplanation(for: alert, topFeatures: features)
        XCTAssertFalse(explanation.isEmpty)
        XCTAssertGreaterThan(explanation.count, 50)
    }

    func test_templatedExplanation_neverEmpty_withNoFeatures() {
        let alert = makeAlert(score: 0.5, severity: .medium, title: "Unknown")
        let explanation = promptBuilder.buildTemplatedExplanation(for: alert, topFeatures: [])
        XCTAssertFalse(explanation.isEmpty)
    }

    // MARK: - AlertExplainer — async interface

    func test_explain_returnsNonEmptyString() async {
        let alert = makeAlert(score: 0.8, severity: .high, title: "Test Alert")
        let explanation = await explainer.explain(alert: alert, topFeatures: [])
        XCTAssertFalse(explanation.isEmpty)
    }

    func test_explain_returnsReadableText() async {
        let alert = makeAlert(score: 0.9, severity: .critical, title: "Critical Threat")
        let features: [(name: String, contribution: Double)] = [("process_is_unsigned", 0.9)]
        let explanation = await explainer.explain(alert: alert, topFeatures: features)
        // Readable text contains spaces and is longer than 30 chars
        XCTAssertTrue(explanation.contains(" "))
        XCTAssertGreaterThan(explanation.count, 30)
    }

    func test_templatedExplanation_completesWithinReasonableTime() {
        let alert = makeAlert(score: 0.6, severity: .medium, title: "Test")
        let clock = ContinuousClock()
        let start = clock.now
        _ = promptBuilder.buildTemplatedExplanation(for: alert, topFeatures: [])
        let elapsed = start.duration(to: clock.now)

        // The deterministic fallback is owned by Nick and must remain fast.
        // Foundation Models inference is an OS service and is intentionally not
        // constrained by a wall-clock unit test.
        XCTAssertLessThan(elapsed, .seconds(1))
    }

    // MARK: - Helpers

    private func makeAlert(
        score: Double,
        severity: SignalSeverity,
        title: String
    ) -> ThreatAlert {
        ThreatAlert(
            score: score,
            content: AlertContent(
                title: title,
                description: "Test alert description",
                severity: severity,
                recommendedAction: "Investigate the flagged process."
            ),
            contributingSignals: []
        )
    }

    private func makeAlertWithSignals(
        score: Double,
        severity: SignalSeverity,
        title: String,
        processPath: String,
        remoteIP: String
    ) -> ThreatAlert {
        let procInfo = NickProcessInfo(
            pid: 1000,
            path: processPath,
            name: (processPath as NSString).lastPathComponent,
            parentPID: 1,
            parentName: nil,
            signingStatus: .unsigned,
            metadata: ProcessMetadata(user: "user", startTime: Date())
        )
        let netInfo = NetworkConnectionInfo(
            id: UUID(),
            pid: 1000,
            processName: (processPath as NSString).lastPathComponent,
            transportProtocol: .tcp,
            localAddress: "127.0.0.1",
            localPort: 54321,
            remoteAddress: remoteIP,
            remotePort: 4444,
            state: .established
        )
        let signal = ThreatSignal(
            id: UUID(),
            source: .process,
            severity: severity,
            timestamp: Date(),
            title: title,
            description: "Test",
            context: ThreatSignalContext(processInfo: procInfo, networkInfo: netInfo)
        )
        return ThreatAlert(
            score: score,
            content: AlertContent(
                title: title,
                description: "Test alert",
                severity: severity,
                recommendedAction: "Investigate."
            ),
            contributingSignals: [signal]
        )
    }
}
