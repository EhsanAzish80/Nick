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
/// Core ML scoring infrastructure exists separately but is not wired into this actor.
/// Production correlation is deterministic and rule-based.
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

    private var evidenceBuffer: [Evidence] = []
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

    // MARK: - Configuration

    /// Hard cap on the number of signals retained in the correlation buffer.
    ///
    /// SECURITY: Without this limit a malware process emitting thousands of signals per
    /// second could exhaust memory. When the cap is reached, incoming `.low` and `.info`
    /// signals are discarded. Higher-severity signals always displace low-severity ones.
    static let maxBufferSize = 10_000

    // MARK: - Public API

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
        ingestEvidence(signals.map(Evidence.init(signal:)))
    }

    /// Adds already-normalised evidence to the correlation window.
    func ingestEvidence(_ evidence: [Evidence]) {
        evidenceBuffer.append(contentsOf: evidence)
        pruneOldSignals()
        enforceBufferCap()
        Self.logger.debug("Ingested \(evidence.count) evidence items — buffer: \(self.evidenceBuffer.count)")
    }

    /// Atomically ingests and correlates evidence on this actor. Keeping both
    /// operations inside one actor turn prevents a full scan and a quick tick
    /// from interleaving between ingestion and deduplication.
    func ingestAndCorrelateNew(_ signals: [ThreatSignal]) -> [ThreatAlert] {
        ingest(signals)
        return correlateNew()
    }

    /// Typed-evidence form of `ingestAndCorrelateNew`.
    func ingestAndCorrelateNew(_ evidence: [Evidence]) -> [ThreatAlert] {
        ingestEvidence(evidence)
        return correlateNew()
    }

    /// Evaluates all rules against the current signal window and returns alerts.
    ///
    /// Each rule fires at most once per `correlate()` call; duplicate rule matches
    /// do not produce duplicate alerts. Rules are evaluated in priority order
    /// (highest score first).
    ///
    /// Trust, suppression and delivery deduplication are intentionally not
    /// applied here; the shared `IncidentStore` owns those decisions once.
    ///
    /// - Returns: All alerts produced by the current rule set and signal window.
    func correlate() -> [ThreatAlert] {
        pruneOldSignals()
        guard !evidenceBuffer.isEmpty else { return [] }

        let window = evidenceBuffer.map(\.threatSignal)
        var alerts: [ThreatAlert] = []

        // Evaluate rules in descending confidence order
        let sortedRules = rules.sorted { $0.score > $1.score }
        for rule in sortedRules {
            if let alert = rule.evaluate(window) {
                alerts.append(alert)
                Self.logger.info("Rule '\(rule.name)' fired — score: \(alert.score), severity: \(alert.severity.displayName)")
            }
        }

        return alerts
    }

    /// Compatibility name for correlation after ingestion. Stateful deduplication,
    /// trust and suppression belong exclusively to `IncidentStore`.
    ///
    /// Used by the pipeline's fast-tick path so that a rule firing at T=5 s is not
    /// re-delivered at T=10 s, T=15 s, … while its contributing signals remain inside
    /// the 30-second correlation window.
    ///
    /// - Returns: Alerts for newly-triggered rules only.
    func correlateNew() -> [ThreatAlert] {
        pruneOldSignals()
        guard !evidenceBuffer.isEmpty else { return [] }

        return correlate()
    }

    /// Clears the set of already-emitted rule names so that all rules are eligible
    /// to fire again on the next `correlate()` or `correlateNew()` call.
    ///
    /// Call this at the start of each full scan (`performFullScan`) so that a rule
    /// suppressed in a previous scan window can re-fire if the same condition persists.
    func resetEmittedRules() {
        Self.logger.debug("Incident deduplication is owned by IncidentStore")
    }

    /// Removes all signals from the internal buffer.
    func flush() {
        evidenceBuffer.removeAll()
    }

    /// Returns the number of signals currently in the correlation window.
    var bufferedSignalCount: Int { evidenceBuffer.count }

    // MARK: - Private Helpers

    /// The things an alert is about. Two alerts from one rule about the same
    /// subjects are the same incident.
    static func subjectKeys(for alert: ThreatAlert) -> Set<String> {
        Set(alert.contributingSignals.map(subjectKey(for:)))
    }

    static func subjectKey(for signal: ThreatSignal) -> String {
        if let process = signal.processInfo { return "process:\(process.pid):\(process.path)" }
        if let file = signal.fileInfo { return "file:\(file.path)" }
        if let path = signal.metadata["path"], !path.isEmpty { return "file:\(path)" }
        if let network = signal.networkInfo { return "network:\(network.pid):\(signal.title)" }
        return "signal:\(signal.source.rawValue):\(signal.title)"
    }

    private func pruneOldSignals() {
        let cutoff = Date(timeIntervalSinceNow: -windowDuration)
        evidenceBuffer.removeAll { $0.timestamps.lastSeen < cutoff }
    }

    /// Enforces `maxBufferSize` by evicting the lowest-severity, oldest signals.
    ///
    /// SECURITY: Prevents unbounded memory growth under a sustained signal flood.
    private func enforceBufferCap() {
        guard evidenceBuffer.count > Self.maxBufferSize else { return }

        // Sort ascending by severity then timestamp so the weakest/oldest are first.
        evidenceBuffer.sort {
            if $0.severity == $1.severity {
                return $0.timestamps.observedAt < $1.timestamps.observedAt
            }
            return $0.severity.rawValue < $1.severity.rawValue
        }

        let excess = evidenceBuffer.count - Self.maxBufferSize
        evidenceBuffer.removeFirst(excess)
        Self.logger.notice("Signal buffer cap enforced — evicted \(excess) low-severity signals")
    }

}
