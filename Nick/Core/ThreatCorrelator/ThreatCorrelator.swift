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
/// **ML scoring path**: `BehavioralScorer`, `FeatureExtractor`, and `CorrelationWindow`
/// are implemented and tested but are **not yet wired into the live correlation path**.
/// v0.9-rc ships a 1-feature passthrough stub as `ThreatScorer.mlmodel`; the stub
/// produces scores that are architecturally correct but not meaningful. All production
/// detection in v0.9-rc runs through the rule-based path below. The ML path will be
/// connected once the model is trained on real signal telemetry collected post-launch.
/// Until then, do not describe the product as "AI-powered" in user-facing text.
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
    private var trustedProcessList: TrustedProcessList = TrustedProcessList()

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

    // MARK: - Configuration

    /// Hard cap on the number of signals retained in the correlation buffer.
    ///
    /// SECURITY: Without this limit a malware process emitting thousands of signals per
    /// second could exhaust memory. When the cap is reached, incoming `.low` and `.info`
    /// signals are discarded. Higher-severity signals always displace low-severity ones.
    static let maxBufferSize = 10_000

    // MARK: - Public API

    /// Updates the trusted process list used to filter signals during ingestion.
    ///
    /// - Parameter list: The current trusted process configuration from `SecurityEngine`.
    func updateTrustedProcessList(_ list: TrustedProcessList) {
        trustedProcessList = list
    }

    /// Adds new signals to the correlation buffer.
    ///
    /// All signals are accepted regardless of trusted-process status. Severity
    /// downgrade for trusted-process activity is applied post-correlation in
    /// `correlate()` rather than suppressing signals at ingestion time — this
    /// preserves observability while still reducing alert noise for trusted software.
    ///
    /// Old signals (older than `windowDuration`) are pruned after ingestion.
    /// If the buffer would exceed `maxBufferSize` after pruning, low-severity
    /// signals are evicted to make room for higher-severity incoming signals.
    ///
    /// - Parameter signals: Signals from any monitor.
    func ingest(_ signals: [ThreatSignal]) {
        signalBuffer.append(contentsOf: signals)
        pruneOldSignals()
        enforceBufferCap()
        let trustedCount = signals.filter { signal in
            guard let name = signal.processInfo?.name else { return false }
            return trustedProcessList.isTrusted(name)
        }.count
        Self.logger.debug("Ingested \(signals.count) signals (\(trustedCount) from trusted processes) — buffer: \(self.signalBuffer.count)")
    }

    /// Evaluates all rules against the current signal window and returns alerts.
    ///
    /// Each rule fires at most once per `correlate()` call; duplicate rule matches
    /// do not produce duplicate alerts. Rules are evaluated in priority order
    /// (highest score first).
    ///
    /// After rule evaluation, trusted-process severity downgrade is applied:
    /// - All contributing processes trusted → severity downgraded to `.info`
    /// - Some contributing processes trusted → severity downgraded by one level
    /// - No trusted processes involved → severity unchanged
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
                let adjusted = applyTrustedDowngrade(to: alert)
                alerts.append(adjusted)
                Self.logger.info("Rule '\(rule.name)' fired — score: \(adjusted.score), severity: \(adjusted.severity.displayName)")
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

    /// Enforces `maxBufferSize` by evicting the lowest-severity, oldest signals.
    ///
    /// SECURITY: Prevents unbounded memory growth under a sustained signal flood.
    private func enforceBufferCap() {
        guard signalBuffer.count > Self.maxBufferSize else { return }

        // Sort ascending by severity then timestamp so the weakest/oldest are first.
        signalBuffer.sort {
            if $0.severity == $1.severity { return $0.timestamp < $1.timestamp }
            return $0.severity.rawValue < $1.severity.rawValue
        }

        let excess = signalBuffer.count - Self.maxBufferSize
        signalBuffer.removeFirst(excess)
        Self.logger.notice("Signal buffer cap enforced — evicted \(excess) low-severity signals")
    }

    /// Applies trusted-process severity downgrade to a correlated alert.
    ///
    /// - All contributing signals from trusted processes → severity becomes `.info`
    /// - Some signals from trusted processes → severity downgraded by one level
    /// - No trusted signals → severity unchanged
    private func applyTrustedDowngrade(to alert: ThreatAlert) -> ThreatAlert {
        let signals = alert.contributingSignals
        guard !signals.isEmpty else { return alert }

        let trustedCount = signals.filter { signal in
            guard let name = signal.processInfo?.name else { return false }
            return trustedProcessList.isTrusted(name)
        }.count

        let fraction = Double(trustedCount) / Double(signals.count)
        if fraction == 1.0 {
            return alert.with(severity: .info)
        } else if fraction > 0 {
            return alert.with(severity: alert.severity.downgraded)
        }
        return alert
    }
}
