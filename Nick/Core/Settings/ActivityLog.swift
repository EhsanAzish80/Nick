// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation
import Observation

// MARK: - ActivityEvent

/// A single logged event displayed in the Overview's Recent Activity feed.
struct ActivityEvent: Identifiable, Codable {
    let id: UUID
    let timestamp: Date
    /// SF Symbol name for the row icon.
    let icon: String
    /// Semantic color string: "green" | "blue" | "yellow" | "red"
    let iconColor: String
    let title: String
    let subtitle: String
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

    /// Prepends a new event and trims the buffer to `maxEvents`.
    func log(icon: String, color: String, title: String, subtitle: String) {
        let event = ActivityEvent(
            id: UUID(),
            timestamp: Date(),
            icon: icon,
            iconColor: color,
            title: title,
            subtitle: subtitle
        )
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
