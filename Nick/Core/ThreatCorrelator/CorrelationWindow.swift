// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation
import os

// MARK: - CorrelationWindow

/// A rolling time-bounded buffer of `ThreatSignal` values.
///
/// `CorrelationWindow` maintains an ordered list of signals and discards any that
/// fall outside the configured `windowDuration`. It is an `actor` so the real-time
/// ingestion pipeline can feed signals concurrently without data races.
///
/// Typical window duration is 30 seconds — short enough to group related events
/// from a single attack sequence while avoiding false correlations from unrelated
/// background activity.
///
/// - Note: This type is purely a state container. Decision logic lives in `ThreatCorrelator`.
actor CorrelationWindow {

    // MARK: - Configuration

    /// Signals older than this interval are pruned.
    let windowDuration: TimeInterval

    // MARK: - Private State

    private var signals: [ThreatSignal] = []

    private static let logger = Logger(
        subsystem: "com.ehsanazish.nick",
        category: "CorrelationWindow"
    )

    // MARK: - Init

    /// Creates a window with the specified duration.
    /// - Parameter windowDuration: How long signals are retained. Default 30 seconds.
    init(windowDuration: TimeInterval = 30) {
        self.windowDuration = windowDuration
    }

    // MARK: - Public API

    /// Appends a signal to the window, then prunes expired entries.
    ///
    /// - Parameter signal: The signal to add.
    func add(_ signal: ThreatSignal) {
        signals.append(signal)
        pruneExpired()
        Self.logger.debug("Signal added — window size: \(self.signals.count)")
    }

    /// Appends multiple signals at once, then prunes expired entries.
    ///
    /// - Parameter newSignals: Signals to add in bulk.
    func addAll(_ newSignals: [ThreatSignal]) {
        signals.append(contentsOf: newSignals)
        pruneExpired()
        Self.logger.debug("Batch added \(newSignals.count) signals — window size: \(self.signals.count)")
    }

    /// Returns a snapshot of signals that fall within the current time window.
    ///
    /// - Returns: All non-expired signals in chronological order.
    func currentSignals() -> [ThreatSignal] {
        pruneExpired()
        return signals
    }

    /// Removes signals whose timestamp is older than `windowDuration`.
    ///
    /// Called automatically by `add(_:)`, `addAll(_:)`, and `currentSignals()`.
    /// Can also be called explicitly for periodic housekeeping.
    func pruneExpired() {
        let cutoff = Date(timeIntervalSinceNow: -windowDuration)
        let before = signals.count
        signals.removeAll { $0.timestamp < cutoff }
        let removed = before - signals.count
        if removed > 0 {
            Self.logger.debug("Pruned \(removed) expired signals — remaining: \(self.signals.count)")
        }
    }

    /// Removes all signals from the buffer.
    func flush() {
        signals.removeAll()
    }

    /// The number of signals currently retained in the window.
    var count: Int { signals.count }
}
