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
