// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import XCTest
@testable import Nick

// MARK: - ThreatCorrelatorTests

/// Unit tests for `ThreatCorrelator`, `CorrelationRule`, and `ThreatAlert`.
@MainActor
final class ThreatCorrelatorTests: XCTestCase {

    func test_legacySignedSuppressionMigratesFromPathToIdentity() {
        let original = SuppressionRule(
            type: .signedProcess,
            value: "TEAM123|/Applications/Tool.app/Contents/MacOS/Tool"
        )
        let result = SuppressionRule.migrateLegacySignedProcessRules([original]) { _ in
            .signed(teamID: "TEAM123", signingID: "com.example.tool")
        }

        XCTAssertTrue(result.changed)
        XCTAssertEqual(result.rules.first?.value, "TEAM123|com.example.tool")
        XCTAssertTrue(result.notices.isEmpty)
    }

    func test_unresolvedLegacySignedSuppressionIsDroppedAndReported() {
        let value = "TEAM123|/Applications/Missing.app/Contents/MacOS/Missing"
        let original = SuppressionRule(type: .signedProcess, value: value)
        let result = SuppressionRule.migrateLegacySignedProcessRules([original]) { _ in .unknown }

        XCTAssertTrue(result.changed)
        XCTAssertTrue(result.rules.isEmpty)
        XCTAssertEqual(result.notices.count, 1)
    }

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

    func test_incidentStoreDeduplicatesRepeatedCorrelation() async {
        await correlator.ingest([
            makeSignal(source: .network, severity: .high, metadata: ["reason": "reverse_shell"])
        ])

        let defaults = isolatedDefaults()
        let store = IncidentStore(defaults: defaults)
        let first = store.ingest(await correlator.correlateNew())
        let second = store.ingest(await correlator.correlateNew())

        XCTAssertFalse(first.newlyActionable.isEmpty)
        XCTAssertTrue(second.newlyActionable.isEmpty)
        XCTAssertEqual(second.visibleAlerts.count, first.visibleAlerts.count)
    }

    func test_simultaneousFullAndQuickIngest_emitOneAlert() async {
        let sharedSignal = makeSignal(
            source: .network,
            severity: .high,
            title: "Concurrent reverse shell evidence",
            metadata: ["reason": "reverse_shell"]
        )

        let batches = await withTaskGroup(
            of: [ThreatAlert].self,
            returning: [[ThreatAlert]].self
        ) { group in
            // Models the full-scan and quick-tick paths arriving together.
            group.addTask { [correlator] in
                await correlator!.ingestAndCorrelateNew([sharedSignal])
            }
            group.addTask { [correlator] in
                await correlator!.ingestAndCorrelateNew([sharedSignal])
            }

            var result: [[ThreatAlert]] = []
            for await alerts in group { result.append(alerts) }
            return result
        }

        let defaults = isolatedDefaults()
        let store = IncidentStore(defaults: defaults)
        let results = batches.map(store.ingest)
        XCTAssertEqual(results.flatMap(\.newlyActionable).count, 1)
        XCTAssertEqual(store.visibleAlerts.count, 1)
    }

    func test_correlateNew_alertsAgainForADifferentSubject() async {
        await correlator.ingest([
            makeSignal(source: .yara, severity: .high, metadata: ["path": "/private/tmp/first", "rule": "fam"])
        ])
        let defaults = isolatedDefaults()
        let store = IncidentStore(defaults: defaults)
        let first = store.ingest(await correlator.correlateNew())
        let repeated = store.ingest(await correlator.correlateNew())

        await correlator.ingest([
            makeSignal(source: .yara, severity: .high, metadata: ["path": "/private/tmp/second", "rule": "fam"])
        ])
        let second = store.ingest(await correlator.correlateNew())

        XCTAssertFalse(first.newlyActionable.isEmpty)
        XCTAssertTrue(repeated.newlyActionable.isEmpty)
        XCTAssertFalse(second.newlyActionable.isEmpty, "A second file matching the same rule must still alert")
    }

    func test_pathApprovalIsPrefixOnly() async {
        let rule = passthroughRule()
        let signal = makeSignal(
            source: .yara,
            severity: .medium,
            metadata: ["path": "/private/tmp/x/Users/me/Projects/payload", "rule": "macos_keychain_access", "suppressible": "true"]
        )
        let store = IncidentStore(defaults: isolatedDefaults(), suppressionRules: [
            SuppressionRule(type: .path, value: "/Users/me/Projects", expiresAt: Date().addingTimeInterval(3_600))
        ])
        let result = store.ingest([rule.evaluate([signal])!])
        XCTAssertFalse(result.visibleAlerts.isEmpty)
    }

    func test_pathApprovalRequiresComponentBoundary() {
        let signal = makeSignal(
            metadata: ["path": "/Applications/dev-evil/payload", "reason": "system_hardening"]
        )
        let store = IncidentStore(defaults: isolatedDefaults(), suppressionRules: [
            SuppressionRule(type: .path, value: "/Applications/dev", expiresAt: Date().addingTimeInterval(3_600))
        ])
        XCTAssertEqual(store.ingest([makeAlert(signal: signal)]).visibleAlerts.count, 1)
    }

    func test_ruleNameSuppressionRequiresExactRuleID() {
        let signal = makeSignal(metadata: ["reason": "system_hardening"])
        let store = IncidentStore(defaults: isolatedDefaults(), suppressionRules: [
            SuppressionRule(type: .ruleName, value: "hardening", expiresAt: Date().addingTimeInterval(3_600))
        ])
        XCTAssertEqual(store.ingest([makeAlert(signal: signal)]).visibleAlerts.count, 1)
    }

    func test_processNameSuppressionDoesNotOverrideSignedIdentity() {
        let signal = makeSignedSignal(reason: "system_hardening")
        let store = IncidentStore(defaults: isolatedDefaults(), suppressionRules: [
            SuppressionRule(type: .processName, value: "Editor", expiresAt: Date().addingTimeInterval(3_600))
        ])
        XCTAssertEqual(store.ingest([makeAlert(signal: signal)]).visibleAlerts.count, 1)
    }

    func test_learnedApproval_suppressesOnlySameSignedBehavior() async {
        let rule = passthroughRule()
        let approved = makeSignedSignal(reason: "system_hardening")
        let approvedAlert = rule.evaluate([approved])!
        let store = IncidentStore(defaults: isolatedDefaults(), suppressionRules: [
            SuppressionRule(
                type: .signedProcess,
                value: "TEAM123|com.example.editor",
                behaviorContext: SuppressionRule.contextFingerprint(for: approvedAlert),
                expiresAt: Date().addingTimeInterval(3_600)
            )
        ])

        XCTAssertTrue(store.ingest([approvedAlert]).visibleAlerts.isEmpty)
        let changed = rule.evaluate([makeSignedSignal(reason: "new_unusual_action")])!
        XCTAssertFalse(store.ingest([changed]).visibleAlerts.isEmpty)
    }

    func test_learnedApproval_neverSuppressesPersistence() async {
        let rule = passthroughRule()
        let persistence = makeSignedSignal(
            source: .persistence,
            severity: .high,
            reason: "launch_agent_added"
        )
        let alert = rule.evaluate([persistence])!
        let store = IncidentStore(defaults: isolatedDefaults(), suppressionRules: [
            SuppressionRule(
                type: .signedProcess,
                value: "TEAM123|com.example.editor",
                behaviorContext: SuppressionRule.contextFingerprint(for: alert),
                expiresAt: Date().addingTimeInterval(3_600)
            )
        ])

        XCTAssertFalse(store.ingest([alert]).visibleAlerts.isEmpty)
    }

    func test_pathApprovalCannotSuppressAnyYARAMatch() async {
        let rule = passthroughRule()
        let path = "/private/tmp/known-wrapper"
        let signal = makeSignal(
            source: .yara,
            severity: .medium,
            metadata: ["path": path, "rule": "macos_keychain_access", "suppressible": "true"]
        )
        let store = IncidentStore(defaults: isolatedDefaults(), suppressionRules: [
            SuppressionRule(type: .path, value: path, expiresAt: Date().addingTimeInterval(3_600))
        ])

        XCTAssertFalse(store.ingest([rule.evaluate([signal])!]).visibleAlerts.isEmpty)
    }

    func test_pathApprovalCannotSuppressConcreteYARA() async {
        let rule = passthroughRule()
        let path = "/private/tmp/known-wrapper"
        let signal = makeSignal(
            source: .yara,
            severity: .high,
            metadata: ["path": path, "rule": "osx_known_malware_family", "suppressible": "false"]
        )
        let store = IncidentStore(defaults: isolatedDefaults(), suppressionRules: [
            SuppressionRule(type: .path, value: path, expiresAt: Date().addingTimeInterval(3_600))
        ])

        XCTAssertFalse(store.ingest([rule.evaluate([signal])!]).visibleAlerts.isEmpty)
    }

    func test_trustedProcessCannotDowngradeProtectedHashEvidence() throws {
        let process = NickProcessInfo(
            pid: 42,
            path: "/Applications/Safari.app/Contents/MacOS/Safari",
            name: "Safari",
            parentPID: 1,
            parentName: "launchd",
            signingStatus: .signed(teamID: "APPLE_PLATFORM", signingID: "com.apple.Safari")
        )
        let signal = ThreatSignal(
            source: .filesystem,
            severity: .high,
            title: "Known malicious hash",
            description: "Test protected hash evidence",
            context: ThreatSignalContext(
                processInfo: process,
                fileInfo: FileInfo(
                    path: "/Users/test/Downloads/payload",
                    sha256Hash: String(repeating: "a", count: 64),
                    entropy: nil,
                    signingStatus: nil,
                    sizeBytes: 128
                ),
                metadata: ["reason": "hash_match"]
            )
        )
        let trusted = TrustedProcessList(userEntries: [
            .init(
                displayName: "Safari",
                identity: SigningIdentity(teamID: "APPLE_PLATFORM", signingID: "com.apple.Safari")
            )
        ])
        let store = IncidentStore(defaults: isolatedDefaults(), trustedProcessList: trusted)

        let result = store.ingest([makeAlert(signal: signal, severity: .high)])

        XCTAssertEqual(try XCTUnwrap(result.visibleAlerts.first).severity, .high)
        XCTAssertEqual(result.newlyActionable.count, 1)
    }

    func test_pathRuleCannotSuppressProtectedIntegrityEvidence() {
        let path = "/Users/test/Library/LaunchAgents/com.example.payload.plist"
        let signal = makeSignal(
            source: .filesystem,
            severity: .medium,
            metadata: ["reason": "integrity_change", "class": "integrity", "path": path]
        )
        let store = IncidentStore(defaults: isolatedDefaults(), suppressionRules: [
            SuppressionRule(type: .path, value: path, expiresAt: Date().addingTimeInterval(3_600))
        ])

        XCTAssertEqual(store.ingest([makeAlert(signal: signal)]).visibleAlerts.count, 1)
    }

    func test_retentionKeepsUnresolvedCriticalIncidentAcrossNoiseAndRestart() throws {
        let suite = "IncidentPriorityRetentionTests.\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        defaults.removePersistentDomain(forName: suite)
        let store = IncidentStore(defaults: defaults)
        let critical = makeAlert(
            signal: makeSignal(
                severity: .critical,
                title: "Critical evidence",
                metadata: ["reason": "critical_evidence", "path": "/private/tmp/critical"]
            ),
            severity: .critical
        )
        _ = store.ingest([critical])

        for index in 0..<150 {
            let noise = makeSignal(
                severity: .info,
                title: "Noise \(index)",
                metadata: ["reason": "noise_\(index)", "path": "/private/tmp/noise-\(index)"]
            )
            _ = store.ingest([makeAlert(signal: noise, severity: .info)])
        }

        let restored = IncidentStore(defaults: defaults)
        XCTAssertEqual(restored.incidents.count, IncidentStore.maximumPersistedIncidents)
        XCTAssertTrue(restored.incidents.contains { $0.alert.severity == .critical })
    }

    func test_dismissalTombstoneSurvivesIncidentRetentionNoise() throws {
        let suite = "IncidentDismissalRetentionTests.\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        defaults.removePersistentDomain(forName: suite)
        let dismissedAlert = makeAlert(signal: makeSignal(
            metadata: ["reason": "dismissed_behavior", "path": "/Users/test/dismissed"]
        ))
        let store = IncidentStore(defaults: defaults)
        _ = store.ingest([dismissedAlert])
        store.performAuthenticatedUserAction(.dismissed, alertID: try XCTUnwrap(store.visibleAlerts.first?.id))

        for index in 0..<150 {
            let noise = makeSignal(
                severity: .info,
                title: "Noise \(index)",
                metadata: ["reason": "noise_\(index)", "path": "/private/tmp/noise-\(index)"]
            )
            _ = store.ingest([makeAlert(signal: noise, severity: .info)])
        }

        let restored = IncidentStore(defaults: defaults)
        let result = restored.ingest([dismissedAlert])
        XCTAssertTrue(result.visibleAlerts.allSatisfy { $0.deduplicationKey != dismissedAlert.deduplicationKey })
        XCTAssertTrue(restored.dismissedAlertDeduplicationKeys.contains(dismissedAlert.deduplicationKey))
    }

    func test_fileFloodCoalescesByRuleAndSignedActorIdentity() throws {
        let store = IncidentStore(defaults: isolatedDefaults())
        for index in 0..<50 {
            let process = NickProcessInfo(
                pid: Int32(index + 100),
                path: "/usr/libexec/installd",
                name: "installd",
                parentPID: 1,
                parentName: "launchd",
                signingStatus: .signed(teamID: "APPLE", signingID: "com.apple.installd")
            )
            let signal = ThreatSignal(
                source: .endpointSecurity,
                severity: .info,
                title: "Nick maintenance updated protected files",
                description: "Validated maintenance",
                context: ThreatSignalContext(
                    processInfo: process,
                    fileInfo: FileInfo(
                        path: "/Applications/Nick.app/file-\(index)",
                        sha256Hash: nil,
                        entropy: nil,
                        signingStatus: nil,
                        sizeBytes: nil
                    ),
                    metadata: ["rule": "nick_protected_path_maintenance", "class": "audit"]
                )
            )
            _ = store.ingest([makeAlert(signal: signal, severity: .info)])
        }

        XCTAssertEqual(store.incidents.count, 1)
        XCTAssertEqual(store.incidents.first?.alert.occurrenceCount, 50)
        XCTAssertEqual(store.evictedIncidentCount, 0)
    }

    func test_documentedUninstallInfoIncidentRequestsOneVisibleNotification() {
        let store = IncidentStore(defaults: isolatedDefaults())
        let signal = makeSignal(
            severity: .info,
            title: "Nick is being moved to the Trash",
            metadata: ["rule": "nick_documented_uninstall", "class": "audit"]
        )
        let alert = makeAlert(signal: signal, severity: .info)

        let first = store.ingest([alert])
        let repeated = store.ingest([alert])

        XCTAssertEqual(first.newlyActionable.count, 1)
        XCTAssertTrue(IncidentStore.requiresVisibleNotification(alert))
        XCTAssertTrue(repeated.newlyActionable.isEmpty)
    }

    func test_perRuleShareCapCannotEvictCriticalIncident() {
        let store = IncidentStore(defaults: isolatedDefaults())
        let critical = makeAlert(
            signal: makeSignal(
                severity: .critical,
                title: "Critical evidence",
                metadata: ["reason": "critical_rule", "path": "/private/tmp/critical"]
            ),
            severity: .critical
        )
        _ = store.ingest([critical])

        for index in 0..<(IncidentStore.maximumIncidentsPerRule + 15) {
            let process = NickProcessInfo(
                pid: Int32(index + 200),
                path: "/Applications/Noise\(index).app/Contents/MacOS/Noise",
                name: "Noise\(index)",
                parentPID: 1,
                parentName: "launchd",
                signingStatus: .signed(teamID: "TEAM\(index)", signingID: "com.example.noise.\(index)")
            )
            let signal = ThreatSignal(
                source: .process,
                severity: .info,
                title: "Repeated noisy rule",
                description: "Noise",
                context: ThreatSignalContext(
                    processInfo: process,
                    metadata: ["rule": "one_noisy_rule"]
                )
            )
            _ = store.ingest([makeAlert(signal: signal, severity: .info)])
        }

        XCTAssertEqual(
            store.incidents.filter { $0.evidence.first?.ruleID == "one_noisy_rule" }.count,
            IncidentStore.maximumIncidentsPerRule
        )
        XCTAssertTrue(store.incidents.contains { $0.alert.severity == .critical })
        XCTAssertEqual(store.evictedIncidentCount, 15)
    }

    func test_evictedCountPersistsAndLegacySnapshotDefaultsToZero() throws {
        let current = IncidentStoreSnapshot(
            incidents: [],
            dismissalTombstones: [],
            expectedCooldowns: [:],
            evictedIncidentCount: 17
        )
        XCTAssertEqual(
            try JSONDecoder().decode(
                IncidentStoreSnapshot.self,
                from: JSONEncoder().encode(current)
            ).evictedIncidentCount,
            17
        )

        let legacy = Data(#"{"schemaVersion":1,"incidents":[],"dismissalTombstones":[],"expectedCooldowns":{}}"#.utf8)
        XCTAssertEqual(
            try JSONDecoder().decode(IncidentStoreSnapshot.self, from: legacy).evictedIncidentCount,
            0
        )
    }

    func test_repeatSameSubjectPreservesReviewUntilSeverityEscalates() throws {
        let store = IncidentStore(defaults: isolatedDefaults())
        let first = makeAlert(signal: makeSignal(
            metadata: ["reason": "repeat_behavior", "path": "/Users/test/repeated"]
        ))
        _ = store.ingest([first])
        store.performAuthenticatedUserAction(.reviewed, alertID: try XCTUnwrap(store.visibleAlerts.first?.id))

        let repeated = makeAlert(signal: makeSignal(
            metadata: ["reason": "repeat_behavior", "path": "/Users/test/repeated"]
        ))
        _ = store.ingest([repeated])

        var incident = try XCTUnwrap(store.incidents.first)
        XCTAssertEqual(incident.state, .reviewed)
        XCTAssertEqual(incident.alert.occurrenceCount, 2)
        XCTAssertEqual(incident.actions.first(where: { $0.action == .detected })?.count, 1)

        let escalated = makeAlert(
            signal: makeSignal(
                severity: .high,
                metadata: ["reason": "repeat_behavior", "path": "/Users/test/repeated"]
            ),
            severity: .high
        )
        let result = store.ingest([escalated])

        incident = try XCTUnwrap(store.incidents.first)
        XCTAssertEqual(incident.state, .new)
        XCTAssertEqual(incident.actions.first(where: { $0.action == .detected })?.count, 2)
        XCTAssertEqual(result.newlyActionable.count, 1)
    }

    func test_verdictLearningIsOffByDefaultAndDeprioritisesOnlyExactReviewMatch() throws {
        let alert = makeAlert(signal: makeSignedSignal(reason: "system_hardening"))
        let store = IncidentStore(defaults: isolatedDefaults(), identityValidator: { _, _, _ in true })
        _ = store.ingest([alert])
        store.performAuthenticatedUserAction(.alwaysAllowed, alertID: try XCTUnwrap(store.visibleAlerts.first?.id))
        XCTAssertTrue(store.learnedReviewEntries.isEmpty)

        store.configure(
            trustedProcessList: TrustedProcessList(),
            suppressionRules: [],
            verdictLearningEnabled: true
        )
        store.removeIncidents { _ in true }
        _ = store.ingest([alert])
        store.performAuthenticatedUserAction(.alwaysAllowed, alertID: try XCTUnwrap(store.visibleAlerts.first?.id))
        XCTAssertEqual(store.learnedReviewEntries.count, 1)
        XCTAssertEqual(store.learnedReviewEntries.first?.confirmationCount, 1)
        store.performAuthenticatedUserAction(.alwaysAllowed, alertID: alert.id)
        XCTAssertEqual(
            store.learnedReviewEntries.first?.confirmationCount,
            1,
            "Repeated actions on one incident must not activate learning"
        )

        store.removeIncidents { _ in true }
        XCTAssertEqual(store.ingest([alert]).visibleAlerts.first?.severity, .medium)
        store.performAuthenticatedUserAction(.alwaysAllowed, alertID: try XCTUnwrap(store.visibleAlerts.first?.id))
        XCTAssertEqual(store.learnedReviewEntries.first?.confirmationCount, 2)

        store.removeIncidents { _ in true }
        let result = store.ingest([alert])
        XCTAssertEqual(result.visibleAlerts.first?.severity, .info)
        XCTAssertEqual(result.visibleAlerts.count, 1, "Learning must remain visible, never suppress")
    }

    func test_verdictLearningRefusesAllowOnceProtectedUnsignedAndInterpreterEvidence() throws {
        let store = IncidentStore(defaults: isolatedDefaults(), identityValidator: { _, _, _ in true })
        store.configure(
            trustedProcessList: TrustedProcessList(),
            suppressionRules: [],
            verdictLearningEnabled: true
        )

        let allowOnce = makeAlert(signal: makeSignedSignal(reason: "system_hardening"))
        _ = store.ingest([allowOnce])
        store.performAuthenticatedUserAction(.allowedOnce, alertID: allowOnce.id)

        let protected = makeAlert(signal: makeSignedSignal(reason: "unknown_rule"))
        _ = store.ingest([protected])
        store.performAuthenticatedUserAction(.dismissed, alertID: protected.id)

        let unsignedProcess = NickProcessInfo(
            pid: 51, path: "/Applications/Tool.app/Contents/MacOS/Tool", name: "Tool",
            parentPID: 1, parentName: "launchd", signingStatus: .unsigned
        )
        let unsigned = ThreatSignal(
            source: .process, severity: .medium, title: "Unsigned review", description: "Test",
            context: ThreatSignalContext(processInfo: unsignedProcess, metadata: ["reason": "system_hardening"])
        )
        let unsignedAlert = makeAlert(signal: unsigned)
        _ = store.ingest([unsignedAlert])
        store.performAuthenticatedUserAction(.dismissed, alertID: unsignedAlert.id)

        let shellProcess = NickProcessInfo(
            pid: 52, path: "/bin/zsh", name: "zsh", parentPID: 1, parentName: "launchd",
            signingStatus: .signed(teamID: "APPLE_PLATFORM", signingID: "com.apple.zsh")
        )
        let shell = ThreatSignal(
            source: .process, severity: .medium, title: "Shell review", description: "Test",
            context: ThreatSignalContext(processInfo: shellProcess, metadata: ["reason": "system_hardening"])
        )
        let shellAlert = makeAlert(signal: shell)
        _ = store.ingest([shellAlert])
        store.performAuthenticatedUserAction(.dismissed, alertID: shellAlert.id)

        XCTAssertTrue(store.learnedReviewEntries.isEmpty)
    }

    func test_verdictLearningNeverDeprioritisesProtectedEvidence() throws {
        let store = IncidentStore(defaults: isolatedDefaults(), identityValidator: { _, _, _ in true })
        store.configure(
            trustedProcessList: TrustedProcessList(),
            suppressionRules: [],
            verdictLearningEnabled: true
        )

        let reviewAlert = makeAlert(signal: makeSignedSignal(reason: "system_hardening"))
        _ = store.ingest([reviewAlert])
        store.performAuthenticatedUserAction(.alwaysAllowed, alertID: reviewAlert.id)
        store.removeIncidents { _ in true }
        _ = store.ingest([reviewAlert])
        store.performAuthenticatedUserAction(.alwaysAllowed, alertID: reviewAlert.id)
        XCTAssertEqual(store.learnedReviewEntries.first?.confirmationCount, 2)

        store.removeIncidents { _ in true }
        let protectedSignal = makeSignedSignal(
            source: .yara,
            severity: .high,
            reason: "system_hardening"
        )
        let protectedAlert = makeAlert(signal: protectedSignal, severity: .high)
        let result = store.ingest([protectedAlert])

        XCTAssertEqual(result.visibleAlerts.first?.severity, .high)
        XCTAssertEqual(result.visibleAlerts.count, 1)
    }

    func test_verdictLearningRequiresExactContextMatch() throws {
        let store = IncidentStore(defaults: isolatedDefaults(), identityValidator: { _, _, _ in true })
        store.configure(
            trustedProcessList: TrustedProcessList(),
            suppressionRules: [],
            verdictLearningEnabled: true
        )

        let applicationAlert = makeAlert(signal: makeSignedSignal(reason: "system_hardening"))
        _ = store.ingest([applicationAlert])
        store.performAuthenticatedUserAction(.alwaysAllowed, alertID: applicationAlert.id)
        store.removeIncidents { _ in true }
        _ = store.ingest([applicationAlert])
        store.performAuthenticatedUserAction(.alwaysAllowed, alertID: applicationAlert.id)
        XCTAssertEqual(store.learnedReviewEntries.first?.confirmationCount, 2)

        store.removeIncidents { _ in true }
        let temporarySignal = makeSignedSignal(
            reason: "system_hardening",
            path: "/private/tmp/Editor"
        )
        let result = store.ingest([makeAlert(signal: temporarySignal)])

        XCTAssertEqual(result.visibleAlerts.first?.severity, .medium)
    }

    func test_verdictLearningExpiresResetsAndCapsPerIdentity() throws {
        var clock = Date(timeIntervalSince1970: 1_000)
        let store = IncidentStore(
            defaults: isolatedDefaults(),
            now: { clock },
            identityValidator: { _, _, _ in true }
        )
        store.configure(
            trustedProcessList: TrustedProcessList(), suppressionRules: [], verdictLearningEnabled: true
        )
        let alert = makeAlert(signal: makeSignedSignal(reason: "system_hardening"))
        _ = store.ingest([alert])
        store.performAuthenticatedUserAction(.alwaysAllowed, alertID: alert.id)
        let entryID = try XCTUnwrap(store.learnedReviewEntries.first?.id)
        store.resetLearnedEntry(id: entryID)
        XCTAssertTrue(store.learnedReviewEntries.isEmpty)

        _ = store.ingest([alert])
        store.performAuthenticatedUserAction(.alwaysAllowed, alertID: alert.id)
        store.removeIncidents { _ in true }
        _ = store.ingest([alert])
        store.performAuthenticatedUserAction(.alwaysAllowed, alertID: alert.id)
        XCTAssertEqual(store.learnedReviewEntries.first?.confirmationCount, 2)
        clock.addTimeInterval(IncidentStore.learnedEntryLifetime + 1)
        store.removeIncidents { _ in true }
        XCTAssertEqual(store.ingest([alert]).visibleAlerts.first?.severity, .medium)
        XCTAssertTrue(store.learnedReviewEntries.isEmpty)

        let entries = (0..<(IncidentStore.maximumLearnedEntriesPerIdentity + 5)).map { index in
            LearnedReviewEntry(
                id: UUID(), teamID: "TEAM123", signingIdentifier: "com.example.editor",
                ruleID: "system_hardening", contextKey: "context-\(index)", reason: "Test",
                createdAt: Date(timeIntervalSince1970: Double(index)),
                lastConfirmedAt: Date(timeIntervalSince1970: Double(index)),
                expiresAt: Date.distantFuture, confirmedIncidentIDs: [UUID()]
            )
        }
        let payload = try JSONEncoder().encode(IncidentStoreSnapshot(
            incidents: [], dismissalTombstones: [], expectedCooldowns: [:], learnedReviewEntries: entries
        ))
        try store.installPrivilegedSnapshot(payload) { _ in }
        XCTAssertEqual(store.learnedReviewEntries.count, IncidentStore.maximumLearnedEntriesPerIdentity)
        store.resetAllLearnedEntries()
        XCTAssertTrue(store.learnedReviewEntries.isEmpty)
    }

    func test_verdictLearningRequiresValidatedIdentityWhenRecordingAndApplying() throws {
        let alert = makeAlert(signal: makeSignedSignal(reason: "system_hardening"))
        let rejectingStore = IncidentStore(
            defaults: isolatedDefaults(),
            identityValidator: { _, _, _ in false }
        )
        rejectingStore.configure(
            trustedProcessList: TrustedProcessList(),
            suppressionRules: [],
            verdictLearningEnabled: true
        )
        _ = rejectingStore.ingest([alert])
        rejectingStore.performAuthenticatedUserAction(.alwaysAllowed, alertID: alert.id)
        XCTAssertTrue(rejectingStore.learnedReviewEntries.isEmpty)

        let evidence = Evidence(signal: alert.contributingSignals[0])
        let activeEntry = LearnedReviewEntry(
            id: UUID(),
            teamID: "TEAM123",
            signingIdentifier: "com.example.editor",
            ruleID: "system_hardening",
            contextKey: "parents=name:launchd;path=application;destination=unknown",
            reason: "Test",
            createdAt: .distantPast,
            lastConfirmedAt: .distantPast,
            expiresAt: .distantFuture,
            confirmedIncidentIDs: [UUID(), UUID()]
        )
        XCTAssertEqual(evidence.pathClass, .application)
        let payload = try JSONEncoder().encode(IncidentStoreSnapshot(
            incidents: [],
            dismissalTombstones: [],
            expectedCooldowns: [:],
            learnedReviewEntries: [activeEntry]
        ))
        try rejectingStore.installPrivilegedSnapshot(payload) { _ in }
        XCTAssertEqual(rejectingStore.ingest([alert]).visibleAlerts.first?.severity, .medium)
    }

    func test_userDefaultsCannotEnableVerdictLearning() throws {
        UserDefaults.standard.set(true, forKey: "verdictLearningEnabled")
        defer { UserDefaults.standard.removeObject(forKey: "verdictLearningEnabled") }
        let payload = try JSONSerialization.data(withJSONObject: [
            "schemaVersion": 1,
            "trustedNames": [],
            "trustedEntries": [],
            "suppressionRules": [],
            "ignoredPaths": [],
            "notificationThresholdRaw": SignalSeverity.high.rawValue,
            "verdictLearningEnabled": false
        ])
        let engine = SecurityEngine()
        try engine.installPrivilegedSecuritySettings(payload: payload) { _, _ in }

        XCTAssertFalse(engine.verdictLearningEnabled)
        XCTAssertNil(UserDefaults.standard.object(forKey: "verdictLearningEnabled"))
    }

    func test_incidentStoreDeduplicatesSameEvidenceRegardlessOfSource() {
        let store = IncidentStore(defaults: isolatedDefaults())
        let processSignal = makeSignal(
            source: .process,
            title: "Shared evidence",
            metadata: ["reason": "shared_rule", "path": "/Users/test/shared"]
        )
        let filesystemSignal = makeSignal(
            source: .filesystem,
            title: "Shared evidence",
            metadata: ["reason": "shared_rule", "path": "/Users/test/shared"]
        )

        _ = store.ingest([makeAlert(signal: processSignal)])
        _ = store.ingest([makeAlert(signal: filesystemSignal)])

        XCTAssertEqual(store.visibleAlerts.count, 1)
        XCTAssertEqual(store.visibleAlerts.first?.occurrenceCount, 2)
    }

    func test_incidentLifecycleAndL0EvidenceSurviveRestart() throws {
        let suite = "IncidentRestartTests.\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        defaults.removePersistentDomain(forName: suite)
        var alert = makeAlert(signal: makeSignedSignal(reason: "expected_action"))
        alert.explanation = "Stored explanation"

        let firstStore = IncidentStore(defaults: defaults)
        _ = firstStore.ingest([alert])
        firstStore.performAuthenticatedUserAction(.resolved, alertID: try XCTUnwrap(firstStore.visibleAlerts.first?.id))

        let restored = IncidentStore(defaults: defaults)
        let incident = try XCTUnwrap(restored.incidents.first)
        XCTAssertEqual(incident.state, .resolved)
        XCTAssertEqual(incident.actions.last?.action, .resolved)
        XCTAssertEqual(incident.actions.last?.actor, .user)
        XCTAssertEqual(incident.alert.explanation, "Stored explanation")
        XCTAssertEqual(incident.evidence.first?.schemaVersion, Evidence.currentSchemaVersion)
        XCTAssertEqual(incident.evidence.first?.ruleID, "expected_action")
        XCTAssertEqual(incident.evidence.first?.parentChainIsComplete, false)
        XCTAssertNotNil(incident.evidence.first?.signingIdentity)
        XCTAssertNotNil(incident.evidence.first?.lifecycle)
    }

    func test_privilegedMigrationPreservesIncidentAndDismissalTombstoneWithoutLoss() throws {
        let suite = "IncidentPrivilegedMigrationTests.\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        defaults.removePersistentDomain(forName: suite)
        let kept = makeAlert(signal: makeSignal(
            metadata: ["reason": "kept", "path": "/Users/test/kept"]
        ))
        let dismissed = makeAlert(signal: makeSignal(
            metadata: ["reason": "dismissed", "path": "/Users/test/dismissed"]
        ))
        let legacy = IncidentStore(defaults: defaults)
        _ = legacy.ingest([kept, dismissed])
        let dismissedID = try XCTUnwrap(
            legacy.visibleAlerts.first(where: { $0.deduplicationKey == dismissed.deduplicationKey })?.id
        )
        legacy.performAuthenticatedUserAction(.dismissed, alertID: dismissedID)

        let payload = try legacy.prepareLegacyMigration(defaults: defaults)
        let restored = IncidentStore()
        var writes: [Data] = []
        try restored.installPrivilegedSnapshot(payload) { writes.append($0) }

        XCTAssertEqual(restored.incidents.count, 1)
        XCTAssertEqual(restored.incidents.first?.alert.deduplicationKey, kept.deduplicationKey)
        XCTAssertTrue(restored.dismissedAlertDeduplicationKeys.contains(dismissed.deduplicationKey))
        XCTAssertTrue(writes.isEmpty, "Installing an unchanged snapshot must not rewrite it")

        restored.removeLegacyPersistence(defaults: defaults)
        XCTAssertNil(defaults.data(forKey: IncidentStore.persistenceKey))
        XCTAssertNil(defaults.data(forKey: IncidentStore.dismissalPersistenceKey))
        XCTAssertNil(defaults.data(forKey: "nickPersistedAlerts"))
    }

    func test_privilegedMigrationPreservesLegacy463DismissalKeyAndSuppressesRepeat() throws {
        let suite = "IncidentLegacy463DismissalMigrationTests.\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        defaults.removePersistentDomain(forName: suite)
        defer { defaults.removePersistentDomain(forName: suite) }

        let dismissed = makeAlert(signal: makeSignal(
            metadata: ["reason": "system_hardening", "path": "/Users/test/review-only-item"]
        ))
        defaults.set([dismissed.deduplicationKey], forKey: "nickDismissedAlertKeys")
        defaults.set(try JSONEncoder().encode([ThreatAlert]()), forKey: "nickPersistedAlerts")

        let source = IncidentStore(defaults: defaults, persistOnInit: false)
        let payload = try source.prepareLegacyMigration(defaults: defaults)
        let restored = IncidentStore()
        try restored.installPrivilegedSnapshot(payload) { _ in }

        XCTAssertEqual(restored.dismissedAlertDeduplicationKeys, Set([dismissed.deduplicationKey]))
        XCTAssertTrue(restored.ingest([dismissed]).newlyActionable.isEmpty)
        XCTAssertTrue(restored.incidents.isEmpty)
        XCTAssertNotNil(defaults.object(forKey: "nickDismissedAlertKeys"))

        restored.removeLegacyPersistence(defaults: defaults)
        XCTAssertNil(defaults.object(forKey: "nickDismissedAlertKeys"))
        XCTAssertNil(defaults.data(forKey: "nickPersistedAlerts"))
    }

    func test_currentTombstoneDoesNotSuppressSamePathWithNewHash() throws {
        let store = IncidentStore(defaults: isolatedDefaults())
        let original = makeFileAlert(
            reason: "hash_match",
            path: "/Users/test/download.bin",
            hash: String(repeating: "a", count: 64)
        )
        _ = store.ingest([original])
        store.performAuthenticatedUserAction(
            .dismissed,
            alertID: try XCTUnwrap(store.visibleAlerts.first?.id)
        )

        let replacement = makeFileAlert(
            reason: "hash_match",
            path: "/Users/test/download.bin",
            hash: String(repeating: "b", count: 64)
        )
        let result = store.ingest([replacement])

        XCTAssertEqual(result.newlyActionable.map(\.deduplicationKey), [replacement.deduplicationKey])
        XCTAssertEqual(store.visibleAlerts.map(\.deduplicationKey), [replacement.deduplicationKey])
    }

    func test_legacyTombstoneNeverSuppressesProtectedCandidate() throws {
        let suite = "IncidentLegacyProtectedDismissalTests.\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        defaults.removePersistentDomain(forName: suite)
        defer { defaults.removePersistentDomain(forName: suite) }
        let protected = makeFileAlert(
            reason: "hash_match",
            path: "/Users/test/protected.bin",
            hash: String(repeating: "c", count: 64)
        )
        defaults.set([protected.deduplicationKey], forKey: "nickDismissedAlertKeys")

        let source = IncidentStore(defaults: defaults, persistOnInit: false)
        let payload = try source.prepareLegacyMigration(defaults: defaults)
        let restored = IncidentStore()
        try restored.installPrivilegedSnapshot(payload) { _ in }
        let result = restored.ingest([protected])

        XCTAssertEqual(result.newlyActionable.map(\.deduplicationKey), [protected.deduplicationKey])
        XCTAssertEqual(restored.visibleAlerts.map(\.deduplicationKey), [protected.deduplicationKey])
    }

    func test_userVerdictIsRecordedOnlyAfterExtensionAcceptsTarget() async throws {
        let payload = try JSONEncoder().encode(IncidentStoreSnapshot(
            incidents: [],
            dismissalTombstones: [],
            expectedCooldowns: [:]
        ))
        let deniedEngine = SecurityEngine()
        deniedEngine.setVerdictLearningEnabled(true)
        defer { deniedEngine.setVerdictLearningEnabled(false) }
        try deniedEngine.installPrivilegedIncidentStore(
            payload: payload,
            persistence: { _, _ in },
            authorizer: { _, _ in .targetMissing },
            removeLegacyState: false
        )
        let deniedAlert = makeAlert(signal: makeSignal(
            metadata: ["reason": "denied_verdict", "path": "/Users/test/denied"]
        ))
        deniedEngine.addAlert(deniedAlert)
        deniedEngine.hideAlert(deniedAlert.id)
        try await Task.sleep(for: .milliseconds(50))

        XCTAssertEqual(deniedEngine.incidentStore.visibleAlerts.count, 1)
        XCTAssertFalse(deniedEngine.incidentStore.incidents.flatMap(\.actions).contains { $0.actor == .user })
        XCTAssertTrue(deniedEngine.learnedReviewEntries.isEmpty)
        XCTAssertEqual(
            deniedEngine.incidentActionRetryMessage,
            "This item is no longer in Nick's protected record. Refresh Activity and try again."
        )
        deniedEngine.cancelPendingIncidentAction()
        XCTAssertNil(deniedEngine.incidentActionRetryMessage)

        let allowedEngine = SecurityEngine()
        try allowedEngine.installPrivilegedIncidentStore(
            payload: payload,
            persistence: { _, _ in },
            authorizer: { _, action in
                action == .hidden
                    ? .approved(IncidentActionApproval(authorizationExternalForm: nil))
                    : .rejected
            },
            removeLegacyState: false
        )
        let allowedAlert = makeAlert(signal: makeSignal(
            metadata: ["reason": "allowed_verdict", "path": "/Users/test/allowed"]
        ))
        allowedEngine.addAlert(allowedAlert)
        allowedEngine.hideAlert(allowedAlert.id)
        try await Task.sleep(for: .milliseconds(50))

        XCTAssertTrue(allowedEngine.incidentStore.visibleAlerts.isEmpty)
        XCTAssertTrue(allowedEngine.incidentStore.incidents.flatMap(\.actions).contains {
            $0.action == .hidden && $0.actor == .user
        })
        XCTAssertNil(allowedEngine.incidentActionRetryMessage)
    }

    func test_failedVerdictCanBeRetriedWithoutLosingRequestedAction() async throws {
        let payload = try JSONEncoder().encode(IncidentStoreSnapshot(
            incidents: [],
            dismissalTombstones: [],
            expectedCooldowns: [:]
        ))
        var attempts = 0
        let engine = SecurityEngine()
        try engine.installPrivilegedIncidentStore(
            payload: payload,
            persistence: { _, _ in },
            authorizer: { _, _ in
                attempts += 1
                return attempts == 1
                    ? .protectionDisconnected
                    : .approved(IncidentActionApproval(authorizationExternalForm: nil))
            },
            removeLegacyState: false
        )
        let alert = makeAlert(signal: makeSignal(
            metadata: ["reason": "retry_verdict", "path": "/Users/test/retry"]
        ))
        engine.addAlert(alert)

        engine.hideAlert(alert.id)
        try await Task.sleep(for: .milliseconds(50))
        XCTAssertNotNil(engine.incidentActionRetryMessage)
        XCTAssertEqual(engine.incidentStore.visibleAlerts.count, 1)

        engine.retryPendingIncidentAction()
        try await Task.sleep(for: .milliseconds(50))
        XCTAssertNil(engine.incidentActionRetryMessage)
        XCTAssertTrue(engine.incidentStore.visibleAlerts.isEmpty)
        XCTAssertEqual(attempts, 2)
    }

    func test_incidentActionFailuresUseDistinctHonestMessages() async throws {
        let payload = try JSONEncoder().encode(IncidentStoreSnapshot(
            incidents: [],
            dismissalTombstones: [],
            expectedCooldowns: [:]
        ))
        let cases: [(IncidentActionAuthorizationResult, String)] = [
            (.approvalCancelled, "Approval was cancelled. Your action was not applied."),
            (.protectionDisconnected, "Protection is not connected. Your action was not applied."),
            (.versionMismatch(appBuild: "5017", extensionBuild: "5016"),
             "App and protection versions differ (app 5017, protection 5016). Nick may still be updating; reopen Nick after the update completes."),
            (.rejected, "Protection refused this action. Refresh Activity and try again.")
        ]

        for (result, expectedMessage) in cases {
            let engine = SecurityEngine()
            try engine.installPrivilegedIncidentStore(
                payload: payload,
                persistence: { _, _ in },
                authorizer: { _, _ in result },
                removeLegacyState: false
            )
            let alert = makeAlert(signal: makeSignal(
                metadata: ["reason": UUID().uuidString, "path": "/Users/test/failure"]
            ))
            engine.addAlert(alert)
            engine.hideAlert(alert.id)
            try await Task.sleep(for: .milliseconds(25))
            XCTAssertEqual(engine.incidentActionRetryMessage, expectedMessage)
        }
    }

    func test_blankLegacyActionActorDecodesAndDisplaysAsUnknown() throws {
        let timestamp = Date(timeIntervalSince1970: 123)
        let encoded = try JSONSerialization.data(withJSONObject: [
            "action": "reviewed",
            "actor": "   ",
            "firstTimestamp": timestamp.timeIntervalSinceReferenceDate,
            "lastTimestamp": timestamp.timeIntervalSinceReferenceDate,
            "count": 1
        ])
        let record = try JSONDecoder().decode(IncidentActionRecord.self, from: encoded)

        XCTAssertEqual(record.actor, .unknown)
        XCTAssertEqual(record.actor.displayName, "Unknown")
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
        let firstSignal = makeProcessSignal(reason: "developer_command", timestamp: firstDate)
        let secondSignal = makeProcessSignal(reason: "developer_command", timestamp: secondDate)
        let first = makeAlert(signal: firstSignal, severity: .medium, timestamp: firstDate)
        let second = makeAlert(signal: secondSignal, severity: .high, timestamp: secondDate)

        let merged = first.mergingOccurrence(second)

        XCTAssertEqual(merged.id, first.id)
        XCTAssertEqual(merged.firstSeen, firstDate)
        XCTAssertEqual(merged.lastSeen, secondDate)
        XCTAssertEqual(merged.occurrenceCount, 2)
        XCTAssertEqual(merged.severity, .high)
    }

    func test_threatAlert_firstSeenIncludesEarlierContributingEvidence() {
        let observed = Date(timeIntervalSince1970: 100)
        let correlated = Date(timeIntervalSince1970: 200)
        let signal = ThreatSignal(
            source: .network,
            severity: .medium,
            timestamp: observed,
            title: "Earlier signal",
            description: "Test"
        )

        let alert = makeAlert(signal: signal, timestamp: correlated)

        XCTAssertEqual(alert.firstSeen, observed)
        XCTAssertEqual(alert.lastSeen, correlated)
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

    private func isolatedDefaults() -> UserDefaults {
        let suite = "ThreatCorrelatorTests.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suite)!
        defaults.removePersistentDomain(forName: suite)
        return defaults
    }

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
        reason: String,
        path: String = "/Applications/Editor.app/Contents/MacOS/Editor"
    ) -> ThreatSignal {
        let process = NickProcessInfo(
            pid: 42,
            path: path,
            name: "Editor",
            parentPID: 1,
            parentName: "launchd",
            signingStatus: .signed(teamID: "TEAM123", signingID: "com.example.editor")
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
        parentName: String = "Xcode",
        timestamp: Date = Date()
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
            timestamp: timestamp,
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

    private func makeFileAlert(reason: String, path: String, hash: String) -> ThreatAlert {
        let signal = ThreatSignal(
            source: .filesystem,
            severity: .high,
            title: "Suspicious file",
            description: "Test file evidence",
            context: ThreatSignalContext(
                fileInfo: FileInfo(
                    path: path,
                    sha256Hash: hash,
                    entropy: nil,
                    signingStatus: nil,
                    sizeBytes: nil
                ),
                metadata: ["reason": reason]
            )
        )
        return makeAlert(signal: signal, severity: .high)
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
