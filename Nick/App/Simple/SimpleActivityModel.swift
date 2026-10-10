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
        case needsAction = "Needs action"
        case threat = "Threat"
        case warning = "Warning"
        case blocked = "Blocked"
        case quarantined = "Quarantined"
    }

    let id: String
    let source: Source
    let title: String
    let detail: String
    let date: Date
    let status: Status

    var icon: String {
        switch status {
        case .informational: "info.circle"
        case .needsAction: "exclamationmark.circle"
        case .threat:      "xmark.shield"
        case .warning:     "exclamationmark.triangle"
        case .blocked:     "hand.raised"
        case .quarantined: "archivebox"
        }
    }

    var isNeedsAction: Bool { status == .needsAction }
    var isBlocked: Bool { status == .blocked || status == .quarantined }
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
        let needsAction: Bool
        let isBlocked: Bool

        init(
            id: UUID,
            headline: String,
            level: Level,
            date: Date,
            needsAction: Bool,
            isBlocked: Bool = false
        ) {
            self.id = id
            self.headline = headline
            self.level = level
            self.date = date
            self.needsAction = needsAction
            self.isBlocked = isBlocked
        }
    }

    /// A launch or open that real-time protection denied.
    struct BlockedInput: Equatable {
        let name: String
        let date: Date
        let wasLaunch: Bool
    }

    struct Day: Identifiable, Equatable {
        let id: Date
        let title: String
        let items: [SimpleActivityItem]
    }

    static func alertInputs(
        from alerts: [ThreatAlert],
        actionable: Set<UUID>,
        builder: UserFacingAlertBuilder = .shared
    ) -> [AlertInput] {
        alerts.compactMap { alert in
            let user = builder.build(from: alert)
            let level: AlertInput.Level
            if !alert.isActionableUserFinding {
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
                    : (user.severity == .safe ? "Security finding needs review" : user.headline),
                level: level,
                date: alert.lastSeen,
                needsAction: alert.isActionableUserFinding && actionable.contains(alert.id),
                isBlocked: alert.contributingSignals.contains {
                    $0.metadata["reason"] == "endpoint_tamper_observed"
                        && $0.metadata["tamperDisposition"] == "blocked"
                }
            )
        }
    }

    private static func informationalHeadline(_ headline: String) -> String {
        let suffix = " needs your review"
        guard headline.lowercased().hasSuffix(suffix) else { return headline }
        return String(headline.dropLast(suffix.count)) + " activity observed"
    }

    static func blockedInputs(from events: [ESEvent]) -> [BlockedInput] {
        events.compactMap { event in
            guard event.decision == .deny else { return nil }
            let path = event.filePath ?? event.processPath
            let name = (path as NSString).lastPathComponent
            guard !name.isEmpty else { return nil }
            return BlockedInput(name: name, date: event.timestamp, wasLaunch: event.eventType == .authExec)
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
            let status: SimpleActivityItem.Status = alert.isBlocked
                ? .blocked
                : (alert.needsAction
                ? .needsAction
                : (alert.level == .critical ? .threat
                    : (alert.level == .warning ? .warning : .informational)))
            items.append(SimpleActivityItem(
                id: "a-\(alert.id.uuidString)",
                source: .alert(alert.id),
                title: alert.headline,
                detail: alert.level == .critical ? "Nick found a threat"
                    : (alert.level == .warning ? "Nick warned you" : "Nick observed activity"),
                date: alert.date,
                status: status
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
                status: .quarantined
            ))
        }

        // Repeated blocks of the same item on the same day collapse to one line.
        // A block of something already in Quarantine is covered by that line.
        struct Key: Hashable { let name: String; let day: Date; let launch: Bool }
        let groups = Dictionary(grouping: blocked.filter { !quarantinedNames.contains($0.name) }) {
            Key(name: $0.name, day: calendar.startOfDay(for: $0.date), launch: $0.wasLaunch)
        }
        for (key, group) in groups {
            let times = group.count == 1 ? "" : " (\(group.count) times)"
            items.append(SimpleActivityItem(
                id: "b-\(key.launch ? "x" : "o")-\(Int(key.day.timeIntervalSince1970))-\(key.name)",
                source: .blocked,
                title: key.launch ? "Stopped “\(key.name)” from running" : "Stopped “\(key.name)” from opening",
                detail: "Blocked by real-time protection\(times)",
                date: group.map(\.date).max() ?? key.day,
                status: .blocked
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
