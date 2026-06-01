// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation
import Observation

// MARK: - ActivityEvent

/// A single logged event displayed in the Overview's Recent Activity feed.
struct ActivityEvent: Identifiable, Codable {
    let id: UUID
    var timestamp: Date
    /// SF Symbol name for the row icon.
    let icon: String
    /// Semantic color string: "green" | "blue" | "yellow" | "red"
    let iconColor: String
    let title: String
    var subtitle: String
    /// How many consecutive identical events this entry represents.
    var repeatCount: Int

    init(id: UUID = UUID(), timestamp: Date = .now,
         icon: String, iconColor: String,
         title: String, subtitle: String,
         repeatCount: Int = 1) {
        self.id          = id
        self.timestamp   = timestamp
        self.icon        = icon
        self.iconColor   = iconColor
        self.title       = title
        self.subtitle    = subtitle
        self.repeatCount = repeatCount
    }

    // Backward-compatible decode: old entries lack `repeatCount`, default to 1.
    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id          = try c.decode(UUID.self,   forKey: .id)
        timestamp   = try c.decode(Date.self,   forKey: .timestamp)
        icon        = try c.decode(String.self, forKey: .icon)
        iconColor   = try c.decode(String.self, forKey: .iconColor)
        title       = try c.decode(String.self, forKey: .title)
        subtitle    = try c.decode(String.self, forKey: .subtitle)
        repeatCount = (try? c.decodeIfPresent(Int.self, forKey: .repeatCount)) ?? 1
    }
}

// MARK: - ActivityLog

/// Persisted newest-first ring-buffer of the last 50 activity events.
///
/// Lives as a property of `SecurityEngine`. Recording happens on `@MainActor`
/// after each scan phase and when new alerts fire.
@MainActor
@Observable
final class ActivityLog {

    // MARK: - State

    private(set) var events: [ActivityEvent] = []

    // MARK: - Private

    private let maxEvents = 50
    private let key = "com.3nsofts.nick.activityLog"

    // MARK: - Init

    init() { load() }

    // MARK: - Public API

    /// Prepends a new event, or increments an existing entry's `repeatCount`
    /// if a recent entry (within the last 8) has the same `title`.
    /// This prevents the 4-event scan cycle from repeating every minute.
    func log(icon: String, color: String, title: String, subtitle: String) {
        // Search the most recent entries for a match (covers the 4-event cycle pattern)
        let searchRange = min(events.count, 8)
        for i in 0..<searchRange {
            if events[i].title == title {
                events[i].timestamp   = Date()
                events[i].subtitle    = subtitle
                events[i].repeatCount += 1
                // Move it to the top so most recent activity is first
                let updated = events.remove(at: i)
                events.insert(updated, at: 0)
                save()
                return
            }
        }
        let event = ActivityEvent(icon: icon, iconColor: color, title: title, subtitle: subtitle)
        events.insert(event, at: 0)
        if events.count > maxEvents { events.removeLast() }
        save()
    }

    // MARK: - Persistence

    private func save() {
        guard let data = try? JSONEncoder().encode(events) else { return }
        UserDefaults.standard.set(data, forKey: key)
    }

    private func load() {
        guard
            let data = UserDefaults.standard.data(forKey: key),
            let decoded = try? JSONDecoder().decode([ActivityEvent].self, from: data)
        else { return }
        events = decoded
    }
}
