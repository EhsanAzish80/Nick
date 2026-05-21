// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation
import os

// MARK: - ThreatCorrelator

/// Consumes raw `ThreatSignal` values from all monitors and synthesises high-confidence
/// `ThreatAlert` events by applying a set of `CorrelationRule` instances.
///
/// `ThreatCorrelator` is an `actor` — all state mutations are serialised, making it
/// safe to feed signals from concurrent monitor tasks without data races.
///
/// **Correlation window**: signals older than `windowDuration` (default: 30 seconds)
/// are discarded before each rule evaluation. This prevents stale signals from
/// inflating the threat score.
///
/// Usage:
/// ```swift
/// let correlator = ThreatCorrelator()
/// await correlator.ingest([signal1, signal2])
/// let alerts = await correlator.correlate()
/// ```
actor ThreatCorrelator {

    // MARK: - Configuration

    /// Time span over which signals are correlated. Signals older than this are dropped.
    let windowDuration: TimeInterval

    // MARK: - Private State

    private var signalBuffer: [ThreatSignal] = []
    private var rules: [CorrelationRule]

    private static let logger = Logger(
        subsystem: "com.ehsanazish.nick",
        category: "ThreatCorrelator"
    )

    // MARK: - Init

    /// Creates a `ThreatCorrelator` with the given rule set and window duration.
    ///
    /// - Parameters:
    ///   - rules: The correlation rules to apply. Defaults to `CorrelationRule.standard`.
    ///   - windowDuration: How long to retain signals before discarding them.
    init(rules: [CorrelationRule] = CorrelationRule.standard, windowDuration: TimeInterval = 30) {
        self.rules = rules
        self.windowDuration = windowDuration
    }

    // MARK: - Public API

    /// Adds new signals to the correlation buffer.
    ///
    /// Old signals (older than `windowDuration`) are pruned after ingestion.
    ///
    /// - Parameter signals: Signals from any monitor.
    func ingest(_ signals: [ThreatSignal]) {
        signalBuffer.append(contentsOf: signals)
        pruneOldSignals()
        Self.logger.debug("Ingested \(signals.count) signals — buffer size: \(self.signalBuffer.count)")
    }

    /// Evaluates all rules against the current signal window and returns alerts.
    ///
    /// Each rule fires at most once per `correlate()` call; duplicate rule matches
    /// do not produce duplicate alerts. Rules are evaluated in priority order
    /// (highest score first).
    ///
    /// - Returns: All alerts produced by the current rule set and signal window.
    func correlate() -> [ThreatAlert] {
        pruneOldSignals()
        guard !signalBuffer.isEmpty else { return [] }

        let window = signalBuffer
        var alerts: [ThreatAlert] = []

        // Evaluate rules in descending confidence order
        let sortedRules = rules.sorted { $0.score > $1.score }
        for rule in sortedRules {
            if let alert = rule.evaluate(window) {
                alerts.append(alert)
                Self.logger.info("Rule '\(rule.name)' fired — score: \(alert.score)")
            }
        }

        return alerts
    }

    /// Removes all signals from the internal buffer.
    func flush() {
        signalBuffer.removeAll()
    }

    /// Returns the number of signals currently in the correlation window.
    var bufferedSignalCount: Int { signalBuffer.count }

    // MARK: - Private Helpers

    private func pruneOldSignals() {
        let cutoff = Date(timeIntervalSinceNow: -windowDuration)
        signalBuffer.removeAll { $0.timestamp < cutoff }
    }
}
