// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import XCTest
@testable import Nick

final class SimpleActivityFeedTests: XCTestCase {

    private let now = Date(timeIntervalSince1970: 1_790_000_000)
    private var calendar: Calendar {
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = TimeZone(identifier: "UTC")!
        return calendar
    }

    private func record(_ name: String, hoursAgo: Double) -> QuarantineRecord {
        QuarantineRecord(
            id: UUID(),
            originalPath: "/Users/test/Downloads/\(name)",
            quarantinedPath: "/Library/Application Support/com.ehsanazish.nick/quarantine/x",
            hash: "abc",
            threatName: "YARA:osx_family",
            severity: "critical",
            quarantinedAt: now.addingTimeInterval(-hoursAgo * 3_600),
            processPath: "/Users/test/Downloads/\(name)",
            pid: 42
        )
    }

    private func alert(_ headline: String, level: SimpleActivityFeed.AlertInput.Level,
                       hoursAgo: Double, needsAction: Bool) -> SimpleActivityFeed.AlertInput {
        .init(id: UUID(), headline: headline, level: level,
              date: now.addingTimeInterval(-hoursAgo * 3_600), needsAction: needsAction)
    }

    private func protectedPersistenceAlert() -> ThreatAlert {
        let signal = ThreatSignal(
            source: .persistence,
            severity: .medium,
            title: "Launch item with missing executable",
            description: "A startup item references a missing executable.",
            context: ThreatSignalContext(metadata: [
                "reason": "persist_executable_missing",
            ])
        )
        return ThreatAlert(
            score: 0.45,
            content: AlertContent(
                title: "Startup item points to a missing file",
                description: "A startup configuration references a file that no longer exists.",
                severity: .medium,
                recommendedAction: "Review the startup item."
            ),
            contributingSignals: [signal],
            timestamp: now
        )
    }

    private func informationalManagementAlert() -> ThreatAlert {
        let signal = ThreatSignal(
            source: .endpointSecurity,
            severity: .info,
            title: "System extension management observed",
            description: "Nick observed routine use of Apple's system-extension management tool.",
            context: ThreatSignalContext(
                metadata: [
                    "class": "audit",
                    "reason": "endpoint_management_observed",
                    "rule": "endpoint_management_observed",
                    "ruleTier": "review",
                    "threatFamily": "endpoint-management",
                ]
            )
        )
        return ThreatAlert(
            score: 0.1,
            content: AlertContent(
                title: signal.title,
                description: signal.description,
                severity: .info,
                recommendedAction: "No action is needed if you ran this command."
            ),
            contributingSignals: [signal],
            timestamp: now
        )
    }

    private func sensitiveManagementAlert(command: String) throws -> ThreatAlert {
        XCTAssertTrue(TamperProtectionPolicy.isSensitiveSystemExtensionCommand(
            arguments: ["systemextensionsctl", command]
        ))
        let event = ESEvent(
            eventType: .authExec,
            processPath: "/usr/bin/systemextensionsctl",
            pid: 44,
            parentPid: 1,
            decision: .notApplicable,
            threat: .init(
                threatName: "System extension removal command observed",
                threatFamily: "tamper"
            )
        )
        let finding = try XCTUnwrap(ExtensionFinding(event: event))
        return ThreatAlert(
            score: finding.score,
            content: AlertContent(
                title: finding.signal.title,
                description: finding.signal.description,
                severity: .high,
                recommendedAction: finding.recommendedAction
            ),
            contributingSignals: [finding.signal],
            timestamp: now
        )
    }

    func test_mergesSourcesNewestFirst() {
        let items = SimpleActivityFeed.items(
            alerts: [alert("Unusual app behaviour", level: .warning, hoursAgo: 3, needsAction: false)],
            quarantine: [record("Bad.app", hoursAgo: 1)],
            blocked: [.init(name: "dropper", date: now.addingTimeInterval(-2 * 3_600), wasLaunch: true)],
            calendar: calendar
        )
        XCTAssertEqual(items.map(\.status), [.quarantined, .blocked, .warning])
        XCTAssertEqual(items[0].title, "Moved “Bad.app” to Quarantine")
        XCTAssertEqual(items[1].title, "Stopped “dropper” from running")
    }

    func test_actionableAlertsAreNeedsAction() {
        let items = SimpleActivityFeed.items(
            alerts: [
                alert("A", level: .critical, hoursAgo: 1, needsAction: true),
                alert("B", level: .critical, hoursAgo: 2, needsAction: false),
            ],
            quarantine: [], blocked: [], calendar: calendar
        )
        XCTAssertEqual(items.map(\.status), [.needsAction, .threat])
        XCTAssertEqual(SimpleActivityFeed.count(items, .needsAction), 1)
    }

    func test_mediumProtectedPersistenceFindingIsVisibleAndNeedsReview() {
        let alert = protectedPersistenceAlert()
        XCTAssertTrue(alert.hasProtectedEvidence)
        XCTAssertTrue(alert.isUserVisibleFinding)

        let inputs = SimpleActivityFeed.alertInputs(
            from: [alert],
            actionable: [alert.id]
        )
        XCTAssertEqual(inputs.count, 1)
        XCTAssertEqual(inputs.first?.level, .warning)
        XCTAssertEqual(inputs.first?.headline, "New startup item detected")
        XCTAssertEqual(inputs.first?.needsAction, true)
    }

    func test_informationalObservationHasAdvancedSimpleBadgeAndHomeParity() {
        let info = informationalManagementAlert()
        XCTAssertFalse(info.hasProtectedEvidence)
        XCTAssertFalse(info.isActionableUserFinding)
        XCTAssertFalse(info.isVisibleInActiveAlerts(showInformational: false))
        XCTAssertTrue(info.isVisibleInActiveAlerts(showInformational: true))

        // Even a stale caller-provided actionable ID cannot turn information
        // into a decision request in Simple mode.
        let inputs = SimpleActivityFeed.alertInputs(from: [info], actionable: [info.id])
        XCTAssertEqual(inputs.count, 1)
        XCTAssertEqual(inputs.first?.level, .informational)
        XCTAssertEqual(inputs.first?.needsAction, false)

        let items = SimpleActivityFeed.items(
            alerts: inputs, quarantine: [], blocked: [], calendar: calendar
        )
        XCTAssertEqual(items.map(\.status), [.informational])
        XCTAssertEqual(SimpleActivityFeed.count(items, .all), 1)
        XCTAssertEqual(SimpleActivityFeed.count(items, .needsAction), 0)

        let advancedActionable = [info].filter {
            $0.isVisibleInActiveAlerts(showInformational: false)
        }
        XCTAssertEqual(advancedActionable.count, 0)
        XCTAssertEqual(SimpleActivityFeed.count(items, .needsAction), advancedActionable.count)

        let issues = AttentionIssue.issues(
            endpointProtectionActive: true,
            auditIssues: 0,
            persistenceIssues: 0,
            processIssues: 0,
            networkIssues: 0,
            unreviewedFindings: advancedActionable.count
        )
        let hero = HomeHero.make(
            incident: nil,
            issues: issues,
            websitesProtected: true,
            lastCheck: now,
            hadRecentWarnings: true,
            now: now
        )
        XCTAssertEqual(hero.state, .protected)
        XCTAssertEqual(hero.title, "Your Mac is protected")
    }

    func test_sensitiveSystemExtensionCommandsRemainNeedsActionInBothModes() throws {
        for command in ["uninstall", "reset"] {
            let alert = try sensitiveManagementAlert(command: command)
            XCTAssertTrue(alert.hasProtectedEvidence, command)
            XCTAssertTrue(alert.isActionableUserFinding, command)

            let advancedActive = [alert].filter {
                $0.isVisibleInActiveAlerts(showInformational: false)
            }
            XCTAssertEqual(advancedActive.map(\.id), [alert.id], command)

            let inputs = SimpleActivityFeed.alertInputs(
                from: [alert], actionable: Set(advancedActive.map(\.id))
            )
            let items = SimpleActivityFeed.items(
                alerts: inputs, quarantine: [], blocked: [], calendar: calendar
            )
            XCTAssertEqual(SimpleActivityFeed.count(items, .needsAction), 1, command)
        }
    }

    func test_failedQuarantineIsNeedsActionInAdvancedAndSimpleModes() {
        let report = RemediationReport(
            timestamp: now,
            threatPath: "/private/tmp",
            threatName: "EICAR",
            quarantineRecord: nil,
            actions: [.init(
                type: .quarantineFile,
                target: "/private/tmp",
                success: false,
                detail: "Permission denied"
            )]
        )
        let finding = ExtensionFinding(report: report)
        let alert = ThreatAlert(
            score: finding.score,
            content: AlertContent(
                title: finding.signal.title,
                description: finding.signal.description,
                severity: finding.signal.severity,
                recommendedAction: finding.recommendedAction
            ),
            contributingSignals: [finding.signal],
            timestamp: finding.signal.timestamp
        )

        let advancedActionable = [alert].filter(\.isActionableUserFinding)
        XCTAssertEqual(advancedActionable.map(\.id), [alert.id])

        let inputs = SimpleActivityFeed.alertInputs(
            from: [alert], actionable: Set(advancedActionable.map(\.id))
        )
        let items = SimpleActivityFeed.items(
            alerts: inputs, quarantine: [], blocked: [], calendar: calendar
        )
        XCTAssertEqual(SimpleActivityFeed.count(items, .needsAction), 1)
        XCTAssertEqual(items.first?.title, "Quarantine failed — needs attention")
        let presented = UserFacingAlertBuilder.shared.build(from: alert)
        XCTAssertTrue(presented.explanation.contains("signature match"))
        XCTAssertTrue(presented.explanation.contains("still present"))
        XCTAssertTrue(presented.explanation.contains("Permission denied"))
    }

    func test_blockedTamperIsProtectedAndListedAsBlockedInSimple() throws {
        let event = ESEvent(
            eventType: .notifyWrite,
            processPath: "/bin/mv",
            pid: 42,
            parentPid: 1,
            filePath: "/Applications/Nick.app/Contents/Resources/test.txt",
            decision: .deny,
            threat: .init(
                threatName: "Nick protected path change blocked",
                threatFamily: "tamper",
                metadata: [
                    "tamperOperation": "rename-destination",
                    "tamperTarget": "/Applications/Nick.app/Contents/Resources/test.txt",
                ]
            )
        )
        let finding = try XCTUnwrap(ExtensionFinding(event: event))
        let alert = ThreatAlert(
            score: finding.score,
            content: AlertContent(
                title: finding.signal.title,
                description: finding.signal.description,
                severity: finding.signal.severity,
                recommendedAction: finding.recommendedAction
            ),
            contributingSignals: [finding.signal],
            timestamp: finding.signal.timestamp
        )

        XCTAssertTrue(alert.hasProtectedEvidence)
        XCTAssertTrue(alert.isVisibleInActiveAlerts(showInformational: false))
        let presented = UserFacingAlertBuilder.shared.build(from: alert)
        XCTAssertEqual(
            presented.headline,
            "Nick blocked an attempt to modify its files (rename-destination by mv)"
        )
        let inputs = SimpleActivityFeed.alertInputs(from: [alert], actionable: [alert.id])
        let items = SimpleActivityFeed.items(
            alerts: inputs, quarantine: [], blocked: [], calendar: calendar
        )
        XCTAssertEqual(items.first?.status, .blocked)
        XCTAssertEqual(SimpleActivityFeed.count(items, .blocked), 1)
    }

    func test_pendingFIMViolationIsNeedsActionInBothModes() {
        let violation = IntegrityViolation(
            path: "/Users/test/.zprofile",
            violationType: .modified,
            expectedHash: "expected",
            actualHash: "actual",
            timestamp: now
        )
        let finding = ExtensionFinding(violation: violation)
        let alert = ThreatAlert(
            score: finding.score,
            content: AlertContent(
                title: finding.signal.title,
                description: finding.signal.description,
                severity: finding.signal.severity,
                recommendedAction: finding.recommendedAction
            ),
            contributingSignals: [finding.signal],
            timestamp: finding.signal.timestamp
        )

        XCTAssertEqual(finding.signal.metadata["fimStatus"], "pending")
        XCTAssertTrue(alert.isVisibleInActiveAlerts(showInformational: false))
        let inputs = SimpleActivityFeed.alertInputs(from: [alert], actionable: [alert.id])
        let items = SimpleActivityFeed.items(
            alerts: inputs, quarantine: [], blocked: [], calendar: calendar
        )
        XCTAssertEqual(items.first?.title, "File integrity change needs review")
        XCTAssertEqual(SimpleActivityFeed.count(items, .needsAction), 1)
    }

    func test_informationalRowsNeverSayNeedsYourReview() {
        let input = SimpleActivityFeed.AlertInput(
            id: UUID(),
            headline: "mv needs your review",
            level: .informational,
            date: now,
            needsAction: false
        )
        // Direct inputs already carry final copy. Verify the production
        // projection normalises contradictory generic copy.
        let signal = ThreatSignal(
            source: .process,
            severity: .info,
            title: "mv",
            description: "Observed activity.",
            context: ThreatSignalContext(processInfo: NickProcessInfo(
                pid: 42,
                path: "/bin/mv",
                name: "mv",
                parentPID: 1,
                parentName: nil,
                signingStatus: .unknown
            ))
        )
        let alert = ThreatAlert(
            score: 0.1,
            content: AlertContent(
                title: "mv",
                description: "Observed activity.",
                severity: .info,
                recommendedAction: "No action needed."
            ),
            contributingSignals: [signal],
            timestamp: now
        )
        let projected = SimpleActivityFeed.alertInputs(from: [alert], actionable: [])
        XCTAssertEqual(projected.first?.headline, "mv activity observed")
        XCTAssertFalse(projected.first?.headline.contains("needs your review") ?? true)
        XCTAssertEqual(input.level, .informational)
    }

    func test_protectedFindingHasAdvancedSimpleBadgeAndHomeParity() {
        let protected = protectedPersistenceAlert()
        XCTAssertTrue(protected.isActionableUserFinding)

        let advancedActionable = [protected].filter {
            $0.isVisibleInActiveAlerts(showInformational: false)
        }
        let inputs = SimpleActivityFeed.alertInputs(
            from: [protected], actionable: Set(advancedActionable.map(\.id))
        )
        let items = SimpleActivityFeed.items(
            alerts: inputs, quarantine: [], blocked: [], calendar: calendar
        )
        XCTAssertEqual(advancedActionable.count, 1)
        XCTAssertEqual(SimpleActivityFeed.count(items, .needsAction), advancedActionable.count)

        let issues = AttentionIssue.issues(
            endpointProtectionActive: true,
            auditIssues: 0,
            persistenceIssues: 0,
            processIssues: 0,
            networkIssues: 0,
            unreviewedFindings: advancedActionable.count
        )
        let hero = HomeHero.make(
            incident: nil,
            issues: issues,
            websitesProtected: true,
            lastCheck: now,
            hadRecentWarnings: true,
            now: now
        )
        XCTAssertEqual(hero.state, .attention)
    }

    func test_filters() {
        let items = SimpleActivityFeed.items(
            alerts: [alert("A", level: .warning, hoursAgo: 1, needsAction: true)],
            quarantine: [record("Bad.app", hoursAgo: 2)],
            blocked: [.init(name: "x", date: now, wasLaunch: false)],
            calendar: calendar
        )
        XCTAssertEqual(SimpleActivityFeed.count(items, .all), 3)
        XCTAssertEqual(SimpleActivityFeed.count(items, .needsAction), 1)
        XCTAssertEqual(SimpleActivityFeed.count(items, .blocked), 2)
        XCTAssertEqual(SimpleActivityFeed.count(items, .quarantined), 1)
    }

    func test_repeatedBlocksCollapseAndSkipQuarantinedItems() {
        let blocked: [SimpleActivityFeed.BlockedInput] = [
            .init(name: "loop", date: now, wasLaunch: true),
            .init(name: "loop", date: now.addingTimeInterval(-60), wasLaunch: true),
            .init(name: "loop", date: now.addingTimeInterval(-120), wasLaunch: true),
            .init(name: "Bad.app", date: now, wasLaunch: true),
        ]
        let items = SimpleActivityFeed.items(
            alerts: [], quarantine: [record("Bad.app", hoursAgo: 0)], blocked: blocked, calendar: calendar
        )
        let blockedItems = items.filter { $0.source == .blocked }
        XCTAssertEqual(blockedItems.count, 1)
        XCTAssertTrue(blockedItems[0].detail.hasSuffix("(3 times)"))
    }

    func test_noPathsInTitlesOrDetails() {
        let items = SimpleActivityFeed.items(
            alerts: [], quarantine: [record("Bad.app", hoursAgo: 1)],
            blocked: [.init(name: "tool", date: now, wasLaunch: false)], calendar: calendar
        )
        for item in items {
            XCTAssertFalse(item.title.contains("/"), item.title)
            XCTAssertFalse(item.detail.contains("/"), item.detail)
        }
    }

    func test_groupsByDayNewestFirst() {
        let items = SimpleActivityFeed.items(
            alerts: [], quarantine: [record("A.app", hoursAgo: 1), record("B.app", hoursAgo: 49)],
            blocked: [], calendar: calendar
        )
        let days = SimpleActivityFeed.days(items, now: now, calendar: calendar)
        XCTAssertEqual(days.count, 2)
        XCTAssertEqual(days[0].title, "Today")
        XCTAssertGreaterThan(days[0].id, days[1].id)
    }
}

final class SimpleProtectionModelTests: XCTestCase {

    private func card(_ group: ProtectionCard.Group, _ status: ProtectionCard.Status) -> ProtectionCard {
        ProtectionCard(group: group, status: status, detail: "")
    }

    func test_subtitle() {
        let on = ProtectionCard.Group.allCases.map { card($0, .on) }
        XCTAssertEqual(SimpleProtectionCopy.subtitle(for: on), "Everything is on")
        var mixed = on
        mixed[0] = card(.appsAndDownloads, .paused)
        XCTAssertEqual(SimpleProtectionCopy.subtitle(for: mixed), "1 of 4 needs attention")
    }

    func test_explanationsDescribeImplementedBoundaries() {
        let apps = SimpleProtectionCopy.explanation(for: .appsAndDownloads)
        XCTAssertTrue(apps.contains("Known blocked files"))
        XCTAssertTrue(apps.contains("shown for review"))

        let web = SimpleProtectionCopy.explanation(for: .websitesAndEmail)
        XCTAssertTrue(web.contains("observes"))
        XCTAssertTrue(web.contains("for review"))

        let media = SimpleProtectionCopy.explanation(for: .cameraAndMicrophone)
        XCTAssertTrue(media.contains("activity changes"))
        XCTAssertTrue(media.contains("when macOS exposes them"))
        XCTAssertFalse(media.contains("continuously"))
    }

    func test_fixRows() {
        XCTAssertNil(ProtectionFix.fix(for: card(.appsAndDownloads, .on), networkState: .enabled))
        XCTAssertEqual(ProtectionFix.fix(for: card(.appsAndDownloads, .paused), networkState: .enabled)?.action,
                       .allowSecurityExtension)
        XCTAssertEqual(ProtectionFix.fix(for: card(.websitesAndEmail, .paused), networkState: .awaitingApproval)?.action,
                       .allowWebFilter)
        XCTAssertEqual(ProtectionFix.fix(for: card(.websitesAndEmail, .paused), networkState: .failed("x"))?.action,
                       .restartWebFilter)
        // Turned off on purpose: the switch is the fix, no extra row.
        XCTAssertNil(ProtectionFix.fix(for: card(.websitesAndEmail, .off), networkState: .disabled))
        XCTAssertEqual(ProtectionFix.fix(for: card(.filesAndRansomware, .off), networkState: .enabled)?.action,
                       .setUpRansomwareWatch)
        XCTAssertEqual(ProtectionFix.fix(for: card(.filesAndRansomware, .paused), networkState: .enabled)?.action,
                       .allowSecurityExtension)
    }

    private func result(_ check: SystemCheckType, _ status: CheckStatus) -> SystemCheckResult {
        SystemCheckResult(id: UUID(), check: check, status: status, currentValue: "",
                          expectedValue: "", description: "", recommendation: nil)
    }

    func test_macSettingsListProblemsFirstWithPlainWords() {
        let settings = SimpleMacSetting.settings(from: [
            result(.gatekeeper, .pass),
            result(.firewall, .fail),
            result(.fileVault, .warning),
        ])
        XCTAssertEqual(settings.map(\.check), [.fileVault, .firewall, .gatekeeper])
        XCTAssertEqual(settings.map(\.state.rawValue), ["Check", "Needs fixing", "OK"])
        XCTAssertEqual(settings[1].fix?.title, "Turn On Firewall")
        XCTAssertNil(settings[2].fix)
    }

    func test_sipHasNoSettingsButton() {
        let sip = SimpleMacSetting.settings(from: [result(.sip, .fail)])[0]
        XCTAssertNil(sip.fix)
        XCTAssertTrue(sip.explanation.contains("Recovery"))
    }
}
