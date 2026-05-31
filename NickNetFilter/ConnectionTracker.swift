// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation

// MARK: - ConnectionTracker

/// Tracks per-app outbound connection rates over a rolling 5-minute window
/// and flags applications that exhibit beaconing or data-exfiltration patterns.
///
/// **Thresholds (conservative — tuned to reduce false positives):**
/// - More than **50 unique remote hosts** in any 5-minute window → suspicious.
/// - More than **100 total outbound connections** in any 5-minute window → suspicious.
///
/// The tracker is not a blocker by itself; `FilterDataProvider` calls
/// `shouldBlock(appID:remoteHost:)` which returns `true` only when BOTH
/// thresholds are exceeded simultaneously.
final class ConnectionTracker: @unchecked Sendable {

    // MARK: - Types

    private struct Window {
        var connections: [(date: Date, host: String)] = []

        mutating func purgeExpired(windowSeconds: TimeInterval = 300) {
            let cutoff = Date().addingTimeInterval(-windowSeconds)
            connections.removeAll { $0.date < cutoff }
        }

        var totalCount: Int   { connections.count }
        var uniqueHosts: Int  { Set(connections.map(\.host)).count }
    }

    // MARK: - Private

    private var windows: [String: Window] = [:]
    private let lock    = NSLock()

    // Thresholds
    private let maxUniqueHosts:   Int = 50
    private let maxTotalConns:    Int = 100

    // MARK: - Public API

    /// Records a new connection attempt from `appID` to `remoteHost`.
    ///
    /// - Returns: `true` if the app should be blocked (both thresholds exceeded).
    func shouldBlock(appID: String, remoteHost: String) -> Bool {
        lock.withLock {
            var window = windows[appID, default: Window()]
            window.purgeExpired()
            window.connections.append((date: Date(), host: remoteHost))
            windows[appID] = window

            return window.uniqueHosts > maxUniqueHosts
                && window.totalCount  > maxTotalConns
        }
    }
}
