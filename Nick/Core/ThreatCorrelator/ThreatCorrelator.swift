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
    private var suppressionRules: [SuppressionRule] = []

    /// Tracks which rule names have already fired since the last `resetEmittedRules()` call.
    /// Prevents the same rule from re-firing every 5-second tick while its contributing
    /// signals remain in the 30-second correlation window.
    private var emittedRuleNames: Set<String> = []

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

    /// Replaces the active suppression rules.
    ///
    /// Called by `SecurityEngine` whenever the user edits the suppression list.
    func updateSuppressionRules(_ rules: [SuppressionRule]) {
        suppressionRules = rules
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
    /// Fired rule names are recorded in `emittedRuleNames` so that a subsequent
    /// `correlateNew()` call in the same session does not re-deliver the same alerts.
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
                emittedRuleNames.insert(rule.name)
                Self.logger.info("Rule '\(rule.name)' fired — score: \(adjusted.score), severity: \(adjusted.severity.displayName)")
            }
        }

        return alerts
    }

    /// Like `correlate()` but only returns alerts for rules that have **not** fired
    /// since the last `resetEmittedRules()` call.
    ///
    /// Used by the pipeline's fast-tick path so that a rule firing at T=5 s is not
    /// re-delivered at T=10 s, T=15 s, … while its contributing signals remain inside
    /// the 30-second correlation window.
    ///
    /// - Returns: Alerts for newly-triggered rules only.
    func correlateNew() -> [ThreatAlert] {
        pruneOldSignals()
        guard !signalBuffer.isEmpty else { return [] }

        let window = signalBuffer
        var alerts: [ThreatAlert] = []

        let sortedRules = rules.sorted { $0.score > $1.score }
        for rule in sortedRules {
            guard !emittedRuleNames.contains(rule.name) else { continue }
            if let alert = rule.evaluate(window) {
                let adjusted = applyTrustedDowngrade(to: alert)
                if isSuppressed(adjusted) {
                    Self.logger.info("Rule '\(rule.name)' suppressed by active suppression rule")
                    emittedRuleNames.insert(rule.name)
                    continue
                }
                alerts.append(adjusted)
                emittedRuleNames.insert(rule.name)
                Self.logger.info("Rule '\(rule.name)' fired (new) — score: \(adjusted.score), severity: \(adjusted.severity.displayName)")
            }
        }

        return alerts
    }

    /// Clears the set of already-emitted rule names so that all rules are eligible
    /// to fire again on the next `correlate()` or `correlateNew()` call.
    ///
    /// Call this at the start of each full scan (`performFullScan`) so that a rule
    /// suppressed in a previous scan window can re-fire if the same condition persists.
    func resetEmittedRules() {
        emittedRuleNames.removeAll()
        Self.logger.debug("Emitted-rule history reset — all rules eligible to fire")
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
    ///
    /// **Persistence signals are never downgraded**, regardless of what other processes
    /// are in the correlation window. This prevents the supply-chain attack scenario where
    /// a signed, trusted app (e.g. VS Code compromised via a malicious extension) installs
    /// a LaunchAgent for persistence. Even if VS Code process signals are in the same
    /// 30-second window, the persistence alert must fire at full severity.
    private func applyTrustedDowngrade(to alert: ThreatAlert) -> ThreatAlert {
        let signals = alert.contributingSignals
        guard !signals.isEmpty else { return alert }

        // NEVER downgrade alerts that include persistence signals (LaunchAgent/Daemon,
        // shell profile, SSH keys). Trusted process status is irrelevant to persistence
        // detection — a trusted app installing an unsigned LaunchAgent is exactly the
        // supply-chain compromise scenario this detector exists to catch.
        if signals.contains(where: { $0.source == .persistence }) {
            return alert
        }

        let trustedCount = signals.filter { signal in
            // Check the signal's own process (leaf) — use PID-aware check when available
            // to prevent impersonation attacks where a malicious process uses a trusted name.
            if let proc = signal.processInfo,
               trustedProcessList.isTrusted(proc.name, pid: proc.pid) { return true }
            // Check parent process from metadata (stored by ProcessScanner for LOLBin signals)
            if let parent = signal.metadata["parent"], !parent.isEmpty,
               trustedProcessList.isTrusted(parent) { return true }
            // Check full chain from metadata (stored by ParentChainAnalyzer)
            if let chain = signal.metadata["chain"] {
                let names = chain.components(separatedBy: " → ")
                if names.contains(where: { trustedProcessList.isTrusted($0) }) { return true }
            }
            return false
        }.count

        let fraction = Double(trustedCount) / Double(signals.count)
        if fraction == 1.0 {
            return alert.with(severity: .info)
        } else if fraction > 0 {
            return alert.with(severity: alert.severity.downgraded)
        }
        return alert
    }

    // MARK: - Suppression

    /// Returns `true` if any active suppression rule matches the given alert.
    private func isSuppressed(_ alert: ThreatAlert) -> Bool {
        guard !suppressionRules.isEmpty else { return false }
        // Trust never overrides strong or materially different evidence. This
        // protects against a trusted editor, browser, or extension becoming the
        // delivery vehicle for persistence or a reverse shell.
        let nonSuppressibleReasons: Set<String> = [
            "reverse_shell", "reverse_shell_port", "netcat_connection",
            "temp_binary_network", "raw_ip_outbound", "ssh_key_added",
            "shell_profile_modified"
        ]
        if alert.severity == .critical ||
            alert.contributingSignals.contains(where: {
                $0.source == .persistence ||
                    $0.source == .yara ||
                    $0.source == .systemAudit ||
                    nonSuppressibleReasons.contains($0.metadata["reason"] ?? "")
            }) {
            return false
        }

        let context = SuppressionRule.contextFingerprint(for: alert)
        for rule in suppressionRules {
            guard rule.isActive else { continue }
            if let learnedContext = rule.behaviorContext,
               learnedContext != context {
                continue
            }
            let needle = rule.value.lowercased()
            guard !needle.isEmpty else { continue }
            switch rule.type {
            case .ruleName:
                if alert.title.lowercased().contains(needle) { return true }
            case .processName:
                let names = alert.contributingSignals.compactMap { $0.processInfo?.name.lowercased() }
                if names.contains(where: { $0.contains(needle) }) { return true }
            case .signedProcess:
                let identities = alert.contributingSignals.compactMap { signal -> String? in
                    guard let process = signal.processInfo,
                          case .signed(let teamID) = process.signingStatus,
                          !teamID.isEmpty,
                          !process.path.isEmpty else { return nil }
                    let path = URL(fileURLWithPath: process.path)
                        .standardizedFileURL.path.lowercased()
                    return "\(teamID.lowercased())|\(path)"
                }
                if identities.contains(needle) { return true }
            case .path:
                let paths = alert.contributingSignals.compactMap { $0.fileInfo?.path.lowercased() }
                if paths.contains(where: { $0.hasPrefix(needle) || $0.contains(needle) }) { return true }
            }
        }
        return false
    }
}
