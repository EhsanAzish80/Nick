// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation

// Pure presentation logic for Simple ▸ Home. Everything here turns engine
// state into plain-language copy; nothing reads or changes detection.

// MARK: - Endpoint health

@MainActor
enum EndpointHealth {
    static let path = "/Library/Application Support/com.ehsanazish.nick/extension_health.json"

    /// Reads the extension heartbeat off the main thread.
    static func load() async -> [String: Any]? {
        let path = Self.path
        let data = await Task.detached(priority: .utility) {
            FileManager.default.contents(atPath: path)
        }.value
        return data.flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] }
    }

    static func isProtectionActive(_ health: [String: Any]?, now: Date = Date()) -> Bool {
        SmartScanChecker.isEndpointSecurityActive(
            health,
            now: now.timeIntervalSince1970,
            bundledVersion: SmartScanChecker.bundledEndpointExtensionVersion
        )
    }

    static func isRansomwareShieldActive(_ health: [String: Any]?, now: Date = Date()) -> Bool {
        isProtectionActive(health, now: now) && (health?["canaryCount"] as? Int ?? 0) > 0
    }
}

// MARK: - Attention root causes

/// Root causes that need the user, shared by Advanced ▸ Overview and
/// Simple ▸ Home. Related symptoms share one issue (a stopped extension also
/// pauses Privacy Guard and Email Guard but is one cause, not three).
struct AttentionIssue: Identifiable, Equatable, Sendable {

    enum Kind: String, Sendable {
        case realTimeProtection = "real_time_protection"
        case systemAudit = "system_audit"
        case persistence
        case processes
        case network
    }

    /// What "Fix It" does in Simple mode.
    enum Fix: Equatable, Sendable {
        case openURL(String)
        case showActivity
        case showProtection
    }

    let kind: Kind
    let count: Int

    var id: String { kind.rawValue }

    // Advanced copy (unchanged from 4.6).

    var advancedTitle: String {
        switch kind {
        case .realTimeProtection: "Real-Time Protection needs attention"
        case .systemAudit:        "System Security needs attention"
        case .persistence:        "Persistence items need review"
        case .processes:          "Running processes need review"
        case .network:            "Network activity needs review"
        }
    }

    var advancedDetail: String {
        switch kind {
        case .realTimeProtection:
            "The security extension is not responding, so Privacy Guard and Email Guard are waiting."
        case .systemAudit:
            "\(count) system setting\(count == 1 ? "" : "s") did not pass the latest audit."
        case .persistence:
            "\(count) startup item\(count == 1 ? "" : "s") have suspicious signing evidence."
        case .processes:
            "\(count) process\(count == 1 ? " has" : "es have") unsigned or invalid signing evidence."
        case .network:
            "\(count) outbound shell connection\(count == 1 ? "" : "s") need context."
        }
    }

    // Simple copy: short, plain, no jargon.

    var simpleTitle: String {
        switch kind {
        case .realTimeProtection: "Protection is paused"
        case .systemAudit:        count == 1 ? "A Mac setting needs changing" : "Some Mac settings need changing"
        case .persistence:        count == 1 ? "An app set itself to start automatically" : "Some apps set themselves to start automatically"
        case .processes:          "An app is behaving unusually"
        case .network:            "An app is making unusual connections"
        }
    }

    var simpleBody: String {
        switch kind {
        case .realTimeProtection:
            "Nick can’t check new apps and downloads until you allow its security extension in System Settings. It takes about a minute."
        case .systemAudit:
            count == 1
                ? "One recommended security setting is off. Turning it on makes your Mac harder to attack."
                : "\(count) recommended security settings are off. Turning them on makes your Mac harder to attack."
        case .persistence:
            "Check that you recognise what starts when you log in. Remove anything you didn’t install."
        case .processes:
            "Nick couldn’t confirm who made an app that’s running. Take a look to make sure you trust it."
        case .network:
            "A command-line program is talking to the internet. That’s normal for some tools, but worth a look."
        }
    }

    var whyItMatters: String {
        switch kind {
        case .realTimeProtection:
            "The security extension is what lets Nick check apps and downloads before they open. While it’s paused, Nick can still scan when you ask, but it can’t stop something harmful as it starts."
        case .systemAudit:
            "Settings like the firewall, FileVault and automatic updates are your Mac’s own defences. Nick watches them so an app or a mistake can’t switch them off quietly."
        case .persistence:
            "Harmful apps often add themselves to your login items so they come back after a restart."
        case .processes:
            "Apps from real developers carry a digital stamp that proves who made them. Apps without one aren’t always harmful, but most malware has none."
        case .network:
            "Attackers sometimes use command-line tools to send data out of a Mac without an app window."
        }
    }

    var simpleFix: Fix {
        switch kind {
        case .realTimeProtection: .openURL("x-apple.systempreferences:com.apple.LoginItems-Settings.extension")
        case .systemAudit:        .showProtection
        case .persistence:        .openURL("x-apple.systempreferences:com.apple.LoginItems-Settings.extension")
        case .processes, .network: .showActivity
        }
    }

    var advancedSection: SidebarSection {
        switch kind {
        case .realTimeProtection: .smartScan
        case .systemAudit:        .systemAudit
        case .persistence:        .persistence
        case .processes:          .processes
        case .network:            .network
        }
    }

    static func issues(
        endpointProtectionActive: Bool,
        auditIssues: Int,
        persistenceIssues: Int,
        processIssues: Int,
        networkIssues: Int
    ) -> [AttentionIssue] {
        var issues: [AttentionIssue] = []
        if !endpointProtectionActive { issues.append(.init(kind: .realTimeProtection, count: 1)) }
        if auditIssues > 0 { issues.append(.init(kind: .systemAudit, count: auditIssues)) }
        if persistenceIssues > 0 { issues.append(.init(kind: .persistence, count: persistenceIssues)) }
        if processIssues > 0 { issues.append(.init(kind: .processes, count: processIssues)) }
        if networkIssues > 0 { issues.append(.init(kind: .network, count: networkIssues)) }
        return issues
    }
}

// MARK: - Incidents (the "blocked" hero)

/// Something harmful Nick acted on in the last 24 hours that the user has not
/// looked at yet.
struct HomeIncident: Identifiable, Equatable, Sendable {
    enum Source: Equatable, Sendable {
        case alert(UUID)
        case quarantine(UUID)
    }

    let source: Source
    let title: String
    let body: String
    let date: Date

    var id: String {
        switch source {
        case .alert(let id):      "alert-\(id.uuidString)"
        case .quarantine(let id): "quarantine-\(id.uuidString)"
        }
    }

    var wasQuarantined: Bool {
        if case .quarantine = source { return true }
        return false
    }

    static let window: TimeInterval = 24 * 60 * 60

    static func latest(
        alerts: [ThreatAlert],
        quarantine: [QuarantineRecord],
        seen: Set<String>,
        now: Date = Date(),
        builder: UserFacingAlertBuilder = .shared
    ) -> HomeIncident? {
        var candidates: [HomeIncident] = []
        for alert in alerts where now.timeIntervalSince(alert.lastSeen) <= window {
            let user = builder.build(from: alert)
            guard user.severity == .critical else { continue }
            candidates.append(HomeIncident(
                source: .alert(alert.id),
                title: "Nick found a threat",
                body: user.explanation.isEmpty ? user.headline : user.explanation,
                date: alert.lastSeen
            ))
        }
        for record in quarantine where now.timeIntervalSince(record.quarantinedAt) <= window {
            let name = (record.originalPath as NSString).lastPathComponent
            candidates.append(HomeIncident(
                source: .quarantine(record.id),
                title: "Nick stopped a harmful app",
                body: "“\(name)” looked harmful, so Nick moved it to Quarantine before it could do anything. It can’t run from there.",
                date: record.quarantinedAt
            ))
        }
        return candidates
            .filter { !seen.contains($0.id) }
            .max { $0.date < $1.date }
    }
}

// MARK: - Hero

struct HomeHero: Equatable {
    enum State: Equatable { case protected, attention, blocked }

    let state: State
    let eyebrow: String
    let title: String
    let body: String
    let primaryTitle: String
    let secondaryTitle: String
    let meta: String

    /// Priority: blocked > attention > protected.
    static func make(
        incident: HomeIncident?,
        issues: [AttentionIssue],
        websitesProtected: Bool,
        lastCheck: Date?,
        hadRecentWarnings: Bool,
        now: Date = Date()
    ) -> HomeHero {
        if let incident {
            return HomeHero(
                state: .blocked,
                eyebrow: incident.wasQuarantined ? "THREAT STOPPED" : "THREAT FOUND",
                title: incident.title,
                body: incident.body,
                primaryTitle: "See What Happened",
                secondaryTitle: incident.wasQuarantined ? "Delete It" : "View Activity",
                meta: HomeFormatting.dayAndTime(incident.date, now: now)
            )
        }
        if let first = issues.first {
            let others = issues.count - 1
            let more = others > 0 ? " …and \(others) more thing\(others == 1 ? "" : "s")." : ""
            return HomeHero(
                state: .attention,
                eyebrow: "NEEDS ATTENTION",
                title: first.simpleTitle,
                body: first.simpleBody + more,
                primaryTitle: "Fix It",
                secondaryTitle: "Why This Matters",
                meta: lastCheckText(lastCheck, now: now)
            )
        }
        let covered = websitesProtected
            ? "apps, downloads, websites and email"
            : "apps, downloads and email"
        let quiet = hadRecentWarnings
            ? "Everything Nick found recently has been handled."
            : "Nothing has needed your attention in the last 7 days."
        return HomeHero(
            state: .protected,
            eyebrow: "ALL GOOD",
            title: "Your Mac is protected",
            body: "Nick is checking \(covered) in the background. \(quiet)",
            primaryTitle: "Run Quick Check",
            secondaryTitle: "Scan a File…",
            meta: lastCheckText(lastCheck, now: now)
        )
    }

    static func lastCheckText(_ date: Date?, now: Date = Date()) -> String {
        guard let date else { return "No check has run yet" }
        let relative = RelativeDateTimeFormatter()
        relative.unitsStyle = .full
        return "Last check \(relative.localizedString(for: date, relativeTo: now))"
    }
}

// MARK: - Protection cards

struct ProtectionCard: Identifiable, Equatable {
    enum Group: String, CaseIterable, Sendable {
        case appsAndDownloads
        case websitesAndEmail
        case filesAndRansomware
        case cameraAndMicrophone
    }

    enum Status: String, Equatable, Sendable {
        case on = "On"
        case paused = "Paused"
        case off = "Off"
    }

    let group: Group
    let status: Status
    let detail: String

    var id: String { group.rawValue }

    var title: String {
        switch group {
        case .appsAndDownloads:     "Apps & Downloads"
        case .websitesAndEmail:     "Websites & Email"
        case .filesAndRansomware:   "Files & Ransomware"
        case .cameraAndMicrophone:  "Camera & Microphone"
        }
    }

    var icon: String {
        switch group {
        case .appsAndDownloads:     "app.badge.checkmark"
        case .websitesAndEmail:     "globe"
        case .filesAndRansomware:   "folder.badge.gearshape"
        case .cameraAndMicrophone:  "video"
        }
    }

    static func cards(
        endpointActive: Bool,
        networkState: NetworkProtectionManager.State,
        ransomwareShieldActive: Bool
    ) -> [ProtectionCard] {
        let paused = "Paused until the security extension is allowed."

        let websites: ProtectionCard
        switch networkState {
        case .enabled:
            websites = ProtectionCard(
                group: .websitesAndEmail, status: .on,
                detail: endpointActive
                    ? "Warns you about scam sites and risky attachments."
                    : "Scam site warnings are on. Email checks are paused."
            )
        case .disabled:
            websites = ProtectionCard(
                group: .websitesAndEmail, status: .off,
                detail: "Scam site warnings are off. Turn them on in Protection."
            )
        case .loading:
            websites = ProtectionCard(group: .websitesAndEmail, status: .paused, detail: "Checking…")
        case .awaitingApproval:
            websites = ProtectionCard(
                group: .websitesAndEmail, status: .paused,
                detail: "Waiting for you to allow the web filter in System Settings."
            )
        case .failed:
            websites = ProtectionCard(
                group: .websitesAndEmail, status: .paused,
                detail: "The web filter isn’t running. Open Protection to restart it."
            )
        }

        return [
            ProtectionCard(
                group: .appsAndDownloads,
                status: endpointActive ? .on : .paused,
                detail: endpointActive ? "Checks every new app and download before it opens." : paused
            ),
            websites,
            ProtectionCard(
                group: .filesAndRansomware,
                status: ransomwareShieldActive ? .on : (endpointActive ? .off : .paused),
                detail: ransomwareShieldActive
                    ? "Watches your documents for sudden mass changes."
                    : (endpointActive ? "Ransomware watch isn’t set up yet." : paused)
            ),
            ProtectionCard(
                group: .cameraAndMicrophone,
                status: endpointActive ? .on : .paused,
                detail: endpointActive ? "Tells you when an app starts using them." : paused
            ),
        ]
    }
}

// MARK: - Mac security settings

struct MacSettingsSummary: Equatable {
    struct Fix: Equatable {
        let title: String
        /// `nil` means "open Nick's Protection page" (no System Settings pane).
        let url: String?
    }

    let onCount: Int
    let total: Int
    /// One entry per check, `true` when on, ordered on-first for the bar.
    let segments: [Bool]
    let fix: Fix?

    var headline: String {
        total == 0
            ? "Nick hasn’t checked your Mac’s settings yet"
            : "\(onCount) of \(total) recommended settings are on"
    }

    static func make(from results: [SystemCheckResult]) -> MacSettingsSummary {
        let on = results.filter { $0.status == .pass }.count
        let failing = results.filter { $0.status == .fail || $0.status == .warning }
        let top = failing.min { priority($0.check) < priority($1.check) }
        return MacSettingsSummary(
            onCount: on,
            total: results.count,
            segments: Array(repeating: true, count: on) + Array(repeating: false, count: results.count - on),
            fix: top.map { fix(for: $0.check) }
        )
    }

    /// Lower is more important.
    static func priority(_ check: SystemCheckType) -> Int {
        switch check {
        case .fileVault:        0
        case .gatekeeper:       1
        case .sip:              2
        case .firewall:         3
        case .automaticUpdates: 4
        case .xprotect:         5
        case .remoteLogin:      6
        case .firewallStealth:  7
        }
    }

    static func fix(for check: SystemCheckType) -> Fix {
        switch check {
        case .fileVault:
            Fix(title: "Turn On FileVault", url: "x-apple.systempreferences:com.apple.preference.security?FDE")
        case .gatekeeper:
            Fix(title: "Turn On Gatekeeper", url: "x-apple.systempreferences:com.apple.preference.security")
        case .sip:
            Fix(title: "How to Fix", url: nil)
        case .firewall:
            Fix(title: "Turn On Firewall", url: "x-apple.systempreferences:com.apple.NetworkFirewall-Settings.extension")
        case .firewallStealth:
            Fix(title: "Turn On Stealth Mode", url: "x-apple.systempreferences:com.apple.NetworkFirewall-Settings.extension")
        case .automaticUpdates:
            Fix(title: "Turn On Updates", url: "x-apple.systempreferences:com.apple.preference.softwareupdate")
        case .xprotect:
            Fix(title: "Install Update", url: "x-apple.systempreferences:com.apple.preference.softwareupdate")
        case .remoteLogin:
            Fix(title: "Turn Off Remote Login", url: "x-apple.systempreferences:com.apple.preferences.sharing?Services_RemoteLogin")
        }
    }
}

// MARK: - "What Nick did lately"

struct HomeActivityLine: Identifiable, Equatable {
    enum Tone: Equatable { case good, warning, danger, neutral }

    let id: String
    let text: String
    let date: Date
    let tone: Tone
    let icon: String
    /// A per-day summary (shows the day only, not a time).
    var isSummary: Bool = false

    /// The last `limit` notable events in plain past tense. Routine work
    /// (background checks, checked files) is summarised as one line per day;
    /// raw events are never listed.
    static func recent(
        alerts: [ThreatAlert],
        quarantine: [QuarantineRecord],
        activity: [ActivityEvent],
        checkedFileDates: [Date],
        now: Date = Date(),
        calendar: Calendar = .current,
        builder: UserFacingAlertBuilder = .shared,
        limit: Int = 5
    ) -> [HomeActivityLine] {
        var lines: [HomeActivityLine] = []

        for record in quarantine {
            let name = (record.originalPath as NSString).lastPathComponent
            lines.append(HomeActivityLine(
                id: "q-\(record.id.uuidString)",
                text: "Moved “\(name)” to Quarantine",
                date: record.quarantinedAt, tone: .danger, icon: "archivebox"
            ))
        }

        for alert in alerts {
            let user = builder.build(from: alert)
            switch user.severity {
            case .safe:
                continue
            case .warning:
                lines.append(HomeActivityLine(
                    id: "a-\(alert.id.uuidString)",
                    text: "Warned you: \(user.headline)",
                    date: alert.lastSeen, tone: .warning, icon: "exclamationmark.triangle"
                ))
            case .critical:
                lines.append(HomeActivityLine(
                    id: "a-\(alert.id.uuidString)",
                    text: "Found a threat: \(user.headline)",
                    date: alert.lastSeen, tone: .danger, icon: "xmark.shield"
                ))
            }
        }

        // Background checks, one line per day.
        let scans = activity.filter { $0.title == "Full system scan completed" }
        let scansByDay = Dictionary(grouping: scans) { calendar.startOfDay(for: $0.timestamp) }
        for (day, events) in scansByDay {
            let runs = events.reduce(0) { $0 + max(1, $1.repeatCount) }
            let found = events.contains { !$0.subtitle.hasSuffix("· 0 threats") }
            let latest = events.map(\.timestamp).max() ?? day
            let text = found
                ? "Checked your Mac \(runs == 1 ? "once" : "\(runs) times") and flagged something to review"
                : "Checked your Mac \(runs == 1 ? "once" : "\(runs) times") and found nothing harmful"
            lines.append(HomeActivityLine(
                id: "scan-\(Int(day.timeIntervalSince1970))",
                text: text, date: latest, tone: found ? .warning : .good,
                icon: found ? "exclamationmark.magnifyingglass" : "checkmark",
                isSummary: true
            ))
        }

        // Apps and files checked by real-time protection, one line per day.
        let checksByDay = Dictionary(grouping: checkedFileDates) { calendar.startOfDay(for: $0) }
        for (day, dates) in checksByDay {
            lines.append(HomeActivityLine(
                id: "checked-\(Int(day.timeIntervalSince1970))",
                text: "Checked \(dates.count) new app\(dates.count == 1 ? "" : "s") and file\(dates.count == 1 ? "" : "s")",
                date: dates.max() ?? day, tone: .good, icon: "checkmark",
                isSummary: true
            ))
        }

        return Array(lines.sorted { $0.date > $1.date }.prefix(limit))
    }
}

// MARK: - Formatting

enum HomeFormatting {
    /// "Today at 14:32", "Yesterday at 09:10", "Monday at 18:05", "12 Sep at 11:00".
    static func dayAndTime(_ date: Date, now: Date = Date(), calendar: Calendar = .current) -> String {
        "\(day(date, now: now, calendar: calendar)) at \(date.formatted(date: .omitted, time: .shortened))"
    }

    /// "Today", "Yesterday", a weekday within the last week, else a short date.
    static func day(_ date: Date, now: Date = Date(), calendar: Calendar = .current) -> String {
        if calendar.isDate(date, inSameDayAs: now) { return "Today" }
        if let yesterday = calendar.date(byAdding: .day, value: -1, to: now),
           calendar.isDate(date, inSameDayAs: yesterday) { return "Yesterday" }
        if let days = calendar.dateComponents([.day], from: calendar.startOfDay(for: date), to: calendar.startOfDay(for: now)).day,
           days < 7 {
            return date.formatted(.dateTime.weekday(.wide))
        }
        return date.formatted(.dateTime.day().month(.abbreviated))
    }
}

// MARK: - Quick Check progress

/// Determinate progress for the hero ring, derived from the steps the engine
/// already logs while a check runs (no engine changes).
enum QuickCheckProgress {
    static let stepTitles: Set<String> = [
        "System audit complete",
        "Persistence check passed",
        "Network baseline updated",
    ]

    /// 0.08 at the start, +0.25 per finished step, never 1 until the check ends.
    static func fraction(events: [ActivityEvent], since start: Date) -> Double {
        let done = Set(
            events
                .filter { $0.timestamp >= start && stepTitles.contains($0.title) }
                .map(\.title)
        ).count
        return 0.08 + Double(done) / Double(stepTitles.count + 1)
    }
}
