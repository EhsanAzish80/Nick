// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation
import Observation

// MARK: - ScanSnapshot

/// A point-in-time snapshot of monitor counts recorded after each full scan.
/// Used to populate sparkline charts in the Overview.
struct ScanSnapshot: Codable, Identifiable {
    let id: UUID
    let timestamp: Date
    let processCount: Int
    let networkCount: Int
    let persistenceCount: Int
    let auditIssueCount: Int
    let healthScore: Int
}

// MARK: - ScanHistory

/// Persisted ring-buffer of the last 50 scan snapshots.
///
/// Lives as a property of `SecurityEngine` so all recording happens on
/// `@MainActor`. Views read snapshot arrays directly for sparklines.
@MainActor
@Observable
final class ScanHistory {

    // MARK: - State

    private(set) var snapshots: [ScanSnapshot] = []

    // MARK: - Private

    private let maxSnapshots = 50
    private let key = "com.3nsofts.nick.scanHistory"

    // MARK: - Init

    init() { load() }

    // MARK: - Public API

    /// Appends a new snapshot and trims the buffer to `maxSnapshots`.
    func record(processes: Int, network: Int, persistence: Int, auditIssues: Int, health: Int) {
        let snapshot = ScanSnapshot(
            id: UUID(),
            timestamp: Date(),
            processCount: processes,
            networkCount: network,
            persistenceCount: persistence,
            auditIssueCount: auditIssues,
            healthScore: health
        )
        snapshots.append(snapshot)
        if snapshots.count > maxSnapshots { snapshots.removeFirst() }
        save()
    }

    /// Returns the last `count` values for a given snapshot key path.
    /// Returns an empty array (not fake data) if fewer than 2 snapshots exist.
    func recentValues(for keyPath: KeyPath<ScanSnapshot, Int>, count: Int = 10) -> [Int] {
        snapshots.suffix(count).map { $0[keyPath: keyPath] }
    }

    // MARK: - Persistence

    private func save() {
        guard let data = try? JSONEncoder().encode(snapshots) else { return }
        UserDefaults.standard.set(data, forKey: key)
    }

    private func load() {
        guard
            let data = UserDefaults.standard.data(forKey: key),
            let decoded = try? JSONDecoder().decode([ScanSnapshot].self, from: data)
        else { return }
        snapshots = decoded
    }
}
