// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation

// MARK: - SimpleActivityItem

/// One line on Simple ▸ Activity. Alerts, Quarantine and blocked launches
/// share one timeline. Titles use file names only — never paths, PIDs, rule
/// names, Team IDs or scores.
struct SimpleActivityItem: Identifiable, Equatable {

    enum Source: Equatable {
        case alert(UUID)
        case quarantine(UUID)
        /// Blocked launches or opens. Informational only.
        case blocked
    }

    enum Status: String, Equatable {
        case informational = "Observed"
        case needsAction = "Needs review"
        case blocked = "Blocked"
        case quarantined = "Quarantined"
    }

    let id: String
    let source: Source
    let title: String
    let detail: String
    let date: Date
    let status: Status
    let isHighRisk: Bool

    var icon: String {
        switch status {
        case .informational: "info.circle"
        case .needsAction: "exclamationmark.circle"
        case .blocked:     "hand.raised"
        case .quarantined: "archivebox"
        }
    }

    var isNeedsAction: Bool { status == .needsAction }
    var badgeText: String {
        status == .needsAction && isHighRisk ? "High risk" : status.rawValue
    }
    var isBlocked: Bool { status == .blocked }
    var isQuarantined: Bool { status == .quarantined }
    var opensDetail: Bool { source != .blocked }
}

// MARK: - Filter

enum SimpleActivityFilter: String, CaseIterable, Identifiable {
    case all = "All"
    case needsAction = "Needs action"
    case blocked = "Blocked"
    case quarantined = "Quarantined"

    var id: String { rawValue }

    func includes(_ item: SimpleActivityItem) -> Bool {
        switch self {
        case .all:         true
        case .needsAction: item.isNeedsAction
        case .blocked:     item.isBlocked
        case .quarantined: item.isQuarantined
        }
    }
}

// MARK: - Feed

enum SimpleActivityFeed {

    /// An alert reduced to what Simple mode may show.
    struct AlertInput: Equatable {
        enum Level: Equatable { case informational, warning, critical }
        let id: UUID
        let headline: String
        let level: Level
        let date: Date
        let displayStatus: IncidentDisplayStatus
        let isHighRisk: Bool

        init(
            id: UUID,
            headline: String,
            level: Level,
            date: Date,
            needsAction: Bool,
            isBlocked: Bool = false,
            displayStatus: IncidentDisplayStatus? = nil,
            isHighRisk: Bool = false
        ) {
            self.id = id
            self.headline = headline
            self.level = level
            self.date = date
            self.displayStatus = displayStatus
                ?? (isBlocked ? .blocked : (needsAction ? .needsReview : .observed))
            self.isHighRisk = isHighRisk
        }
    }

    /// A launch or open that real-time protection denied.
    struct BlockedInput: Equatable {
        let name: String
        let date: Date
        let wasLaunch: Bool
        let persistenceFailed: Bool

        init(name: String, date: Date, wasLaunch: Bool, persistenceFailed: Bool = false) {
            self.name = name
            self.date = date
            self.wasLaunch = wasLaunch
            self.persistenceFailed = persistenceFailed
        }
    }

    struct Day: Identifiable, Equatable {
        let id: Date
        let title: String
        let items: [SimpleActivityItem]
    }

    static func alertInputs(
        from alerts: [ThreatAlert],
        actionable: Set<UUID>,
        incidents: [SecurityIncident] = [],
        builder: UserFacingAlertBuilder = .shared
    ) -> [AlertInput] {
        let incidentsByAlertID = Dictionary(uniqueKeysWithValues: incidents.map { ($0.alert.id, $0) })
        return alerts.compactMap { alert in
            guard isVisibleInSimpleMode(alert) else { return nil }
            let user = builder.build(from: alert)
            let incident = incidentsByAlertID[alert.id]
            let displayStatus = incident?.displayStatus ?? IncidentDisplayStatus(alert: alert)
            let behavior = BehaviorIncidentPresentation(alert: alert, incident: incident)
            let level: AlertInput.Level
            if displayStatus == .needsReview && behavior.isBehavior {
                level = .critical
            } else if !alert.isActionableUserFinding {
                level = .informational
            } else {
                switch user.severity {
                case .safe:
                    // The only actionable safe-mapped case is protected evidence.
                    level = .warning
                case .warning:  level = .warning
                case .critical: level = .critical
                }
            }
            return AlertInput(
                id: alert.id,
                headline: level == .informational ? informationalHeadline(user.headline)
                    : user.headline,
                level: level,
                date: alert.lastSeen,
                needsAction: displayStatus == .needsReview && actionable.contains(alert.id),
                isBlocked: displayStatus == .blocked,
                displayStatus: displayStatus,
                isHighRisk: user.severity == .critical && alert.hasProtectedEvidence
            )
        }
    }

    /// Installer bookkeeping remains available in Advanced and Diagnostics,
    /// but it is not user activity. Require both the maintenance rule and a
    /// validated Apple installer identity so a process name cannot hide an
    /// unrelated finding from Simple mode.
    private static func isVisibleInSimpleMode(_ alert: ThreatAlert) -> Bool {
        !alert.contributingSignals.contains { signal in
            guard signal.metadata["reason"] == "nick_protected_path_maintenance"
                    || signal.metadata["rule"] == "nick_protected_path_maintenance",
                  let signing = signal.processInfo?.signingStatus,
                  case .signed(let teamID, let signingID?) = signing,
                  teamID == "APPLE_PLATFORM"
            else { return false }
            return TamperProtectionPolicy.isAppleInstallerSigningID(signingID)
        }
    }

    private static func informationalHeadline(_ headline: String) -> String {
        let lowercased = headline.lowercased()
        guard lowercased.contains("needs your review")
                || lowercased.contains("activity observed") else { return headline }
        return "Observed security activity"
    }

    static func blockedInputs(
        from events: [ESEvent],
        failedThreatEventIDs: Set<UUID> = []
    ) -> [BlockedInput] {
        events.compactMap { event in
            guard event.decision == .deny else { return nil }
            let isTamper = event.threatFamily == "tamper"
            guard !isTamper || failedThreatEventIDs.contains(event.id) else { return nil }
            let path = event.filePath ?? event.processPath
            let name = (path as NSString).lastPathComponent
            guard !name.isEmpty else { return nil }
            return BlockedInput(
                name: name,
                date: event.timestamp,
                wasLaunch: event.eventType == .authExec,
                persistenceFailed: failedThreatEventIDs.contains(event.id)
            )
        }
    }

    static func items(
        alerts: [AlertInput],
        quarantine: [QuarantineRecord],
        blocked: [BlockedInput],
        calendar: Calendar = .current
    ) -> [SimpleActivityItem] {
        var items: [SimpleActivityItem] = []

        for alert in alerts {
            let status: SimpleActivityItem.Status = switch alert.displayStatus {
            case .needsReview: .needsAction
            case .remediationNeeded: .needsAction
            case .blocked: .blocked
            case .quarantined: .quarantined
            case .resolved, .observed: .informational
            }
            items.append(SimpleActivityItem(
                id: "a-\(alert.id.uuidString)",
                source: .alert(alert.id),
                title: alert.headline,
                detail: alert.level == .critical ? "Nick detected activity"
                    : (alert.level == .warning ? "Nick warned you" : "Nick observed activity"),
                date: alert.date,
                status: status,
                isHighRisk: alert.isHighRisk
            ))
        }

        let quarantinedNames = Set(quarantine.map { ($0.originalPath as NSString).lastPathComponent })
        for record in quarantine {
            let name = (record.originalPath as NSString).lastPathComponent
            items.append(SimpleActivityItem(
                id: "q-\(record.id.uuidString)",
                source: .quarantine(record.id),
                title: "Moved “\(name)” to Quarantine",
                detail: "It can’t run from there",
                date: record.quarantinedAt,
                status: .quarantined,
                isHighRisk: false
            ))
        }

        // Repeated blocks of the same item on the same day collapse to one line.
        // A block of something already in Quarantine is covered by that line.
        struct Key: Hashable { let name: String; let day: Date; let launch: Bool; let failed: Bool }
        let groups = Dictionary(grouping: blocked.filter { !quarantinedNames.contains($0.name) }) {
            Key(
                name: $0.name,
                day: calendar.startOfDay(for: $0.date),
                launch: $0.wasLaunch,
                failed: $0.persistenceFailed
            )
        }
        for (key, group) in groups {
            let times = group.count == 1 ? "" : " (\(group.count) times)"
            items.append(SimpleActivityItem(
                id: "b-\(key.launch ? "x" : "o")-\(Int(key.day.timeIntervalSince1970))-\(key.name)",
                source: .blocked,
                title: key.failed
                    ? "Could not save blocked evidence for “\(key.name)”"
                    : (key.launch ? "Stopped “\(key.name)” from running" : "Stopped “\(key.name)” from opening"),
                detail: key.failed ? "Nick will retry from its protected journal" : "Blocked by real-time protection\(times)",
                date: group.map(\.date).max() ?? key.day,
                status: key.failed ? .needsAction : .blocked,
                isHighRisk: false
            ))
        }

        return items.sorted { $0.date > $1.date }
    }

    static func days(
        _ items: [SimpleActivityItem],
        now: Date = Date(),
        calendar: Calendar = .current
    ) -> [Day] {
        let grouped = Dictionary(grouping: items) { calendar.startOfDay(for: $0.date) }
        return grouped.keys.sorted(by: >).map { day in
            Day(
                id: day,
                title: HomeFormatting.day(day, now: now, calendar: calendar),
                items: (grouped[day] ?? []).sorted { $0.date > $1.date }
            )
        }
    }

    static func count(_ items: [SimpleActivityItem], _ filter: SimpleActivityFilter) -> Int {
        items.filter(filter.includes).count
    }
}
