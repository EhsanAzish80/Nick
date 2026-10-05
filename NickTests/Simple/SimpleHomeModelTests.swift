// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import XCTest
@testable import Nick

final class SimpleHomeModelTests: XCTestCase {

    private let now = Date(timeIntervalSince1970: 1_790_000_000)

    private func quarantine(_ name: String, hoursAgo: Double) -> QuarantineRecord {
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

    // MARK: Hero

    func test_heroIsProtectedWithoutIssuesOrIncidents() {
        let hero = HomeHero.make(incident: nil, issues: [], websitesProtected: true,
                                 lastCheck: now.addingTimeInterval(-7_200), hadRecentWarnings: false, now: now)
        XCTAssertEqual(hero.state, .protected)
        XCTAssertEqual(hero.title, "Your Mac is protected")
        XCTAssertEqual(hero.primaryTitle, "Run Quick Check")
        XCTAssertTrue(hero.body.contains("websites"))
    }

    func test_heroExplainsTheFirstRootCauseAndCountsTheRest() {
        let issues = AttentionIssue.issues(
            endpointProtectionActive: false, auditIssues: 2,
            persistenceIssues: 0, processIssues: 1, networkIssues: 0
        )
        let hero = HomeHero.make(incident: nil, issues: issues, websitesProtected: true,
                                 lastCheck: nil, hadRecentWarnings: false, now: now)
        XCTAssertEqual(hero.state, .attention)
        XCTAssertEqual(hero.title, "Protection is paused")
        XCTAssertTrue(hero.body.hasSuffix("…and 2 more things."))
        XCTAssertEqual(hero.primaryTitle, "Fix It")
        XCTAssertEqual(issues.first?.simpleFix, .openURL("x-apple.systempreferences:com.apple.LoginItems-Settings.extension"))
    }

    func test_blockedOutranksAttention() {
        let record = quarantine("PDF Converter Pro.app", hoursAgo: 1)
        let incident = HomeIncident.latest(alerts: [], quarantine: [record], seen: [], now: now)
        let issues = [AttentionIssue(kind: .realTimeProtection, count: 1)]
        let hero = HomeHero.make(incident: incident, issues: issues, websitesProtected: true,
                                 lastCheck: nil, hadRecentWarnings: true, now: now)
        XCTAssertEqual(hero.state, .blocked)
        XCTAssertEqual(hero.title, "Nick stopped a harmful app")
        XCTAssertEqual(hero.secondaryTitle, "Delete It")
        XCTAssertTrue(hero.body.contains("PDF Converter Pro.app"))
    }

    func test_incidentsExpireAfterADayAndOnceSeen() {
        let old = quarantine("old.app", hoursAgo: 30)
        XCTAssertNil(HomeIncident.latest(alerts: [], quarantine: [old], seen: [], now: now))

        let fresh = quarantine("fresh.app", hoursAgo: 2)
        let incident = HomeIncident.latest(alerts: [], quarantine: [fresh], seen: [], now: now)
        XCTAssertNotNil(incident)
        XCTAssertNil(HomeIncident.latest(alerts: [], quarantine: [fresh], seen: [incident!.id], now: now))
    }

    // MARK: Plain language

    func test_simpleCopyNeverContainsTechnicalTerms() {
        let banned = ["PID", "Team ID", "YARA", "rule", "signature", "%", "/Users/", "persistence", "process"]
        for kind in [AttentionIssue.Kind.realTimeProtection, .systemAudit, .persistence, .processes, .network] {
            let issue = AttentionIssue(kind: kind, count: 3)
            for text in [issue.simpleTitle, issue.simpleBody, issue.whyItMatters] {
                for term in banned {
                    XCTAssertFalse(text.localizedCaseInsensitiveContains(term), "\(kind): “\(term)” in “\(text)”")
                }
            }
        }
    }

    func test_advancedCopyIsUnchanged() {
        let issue = AttentionIssue(kind: .systemAudit, count: 1)
        XCTAssertEqual(issue.advancedTitle, "System Security needs attention")
        XCTAssertEqual(issue.advancedDetail, "1 system setting did not pass the latest audit.")
        XCTAssertEqual(issue.advancedSection, .systemAudit)
    }

    // MARK: Cards

    func test_cardsAlwaysUseAWord() {
        let cards = ProtectionCard.cards(endpointActive: false, networkState: .disabled, ransomwareShieldActive: false)
        XCTAssertEqual(cards.map(\.title), ["Apps & Downloads", "Websites & Email", "Files & Ransomware", "Camera & Microphone"])
        XCTAssertEqual(cards.map(\.status), [.paused, .off, .paused, .paused])
        XCTAssertTrue(cards.allSatisfy { !$0.status.rawValue.isEmpty })
    }

    func test_attachmentChecksPausedIsCalledOutWhenDestinationChecksAreOn() {
        let cards = ProtectionCard.cards(endpointActive: false, networkState: .enabled, ransomwareShieldActive: false)
        XCTAssertEqual(cards[1].status, .on)
        XCTAssertEqual(cards[1].detail, "Destination checks are on. Attachment checks are paused.")
    }

    // MARK: Mac settings

    func test_macSettingsPicksTheMostImportantFix() {
        func result(_ check: SystemCheckType, _ status: CheckStatus) -> SystemCheckResult {
            SystemCheckResult(id: UUID(), check: check, status: status, currentValue: "",
                              expectedValue: "", description: "", recommendation: nil)
        }
        let summary = MacSettingsSummary.make(from: [
            result(.sip, .pass), result(.firewall, .fail), result(.fileVault, .pass),
            result(.gatekeeper, .pass), result(.automaticUpdates, .warning),
            result(.xprotect, .pass), result(.remoteLogin, .pass),
        ])
        XCTAssertEqual(summary.headline, "5 of 7 recommended settings are on")
        XCTAssertEqual(summary.segments.filter { $0 }.count, 5)
        XCTAssertEqual(summary.fix?.title, "Turn On Firewall")
    }

    // MARK: Activity

    func test_routineChecksAreSummarisedPerDay() {
        let today = now.addingTimeInterval(-600)
        let scans = [
            ActivityEvent(timestamp: today, icon: "shield.checkered", iconColor: "blue",
                          title: "Full system scan completed", subtitle: "120 items checked · 0 threats", repeatCount: 5),
            ActivityEvent(timestamp: today.addingTimeInterval(-60), icon: "checkmark.shield", iconColor: "green",
                          title: "System audit complete", subtitle: "8 checks · 8 passed"),
        ]
        let lines = HomeActivityLine.recent(
            alerts: [], quarantine: [quarantine("bad.app", hoursAgo: 3)], activity: scans,
            checkedFileDates: [today, today.addingTimeInterval(-30)], now: now
        )
        XCTAssertEqual(lines.count, 3)
        XCTAssertTrue(lines.contains { $0.text == "Checked your Mac 5 times and found nothing harmful" && $0.isSummary })
        XCTAssertTrue(lines.contains { $0.text == "Checked 2 new apps and files" })
        XCTAssertTrue(lines.contains { $0.text == "Moved “bad.app” to Quarantine" && !$0.isSummary })
        XCTAssertFalse(lines.contains { $0.text.contains("audit") })
    }

    func test_dayFormatting() {
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = TimeZone(identifier: "UTC")!
        XCTAssertEqual(HomeFormatting.day(now, now: now, calendar: calendar), "Today")
        XCTAssertEqual(HomeFormatting.day(now.addingTimeInterval(-86_400), now: now, calendar: calendar), "Yesterday")
    }
}
