// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation
import Observation
import os

// MARK: - SecurityEngine

/// Central coordinator that owns all detection monitors and the threat correlator.
///
/// `SecurityEngine` is the single source of truth for the security state exposed
/// to the UI layer. All mutations happen on the `@MainActor` to avoid data races
/// with the `@Observable` macro's property tracking.
///
/// Monitors are started concurrently via a `TaskGroup`. Each monitor drains its
/// signals into `ThreatCorrelator`, which evaluates the hardcoded rule set and
/// appends alerts to `alerts`.
///
/// - Note: `SecurityEngine` does **not** import SwiftUI — it lives in `Core/`.
@MainActor
@Observable
final class SecurityEngine {

    // MARK: - Published State

    /// All threat alerts produced by the correlator since the last `reset()`.
    private(set) var alerts: [ThreatAlert] = []

    /// The most recent set of system audit results.
    private(set) var auditResults: [SystemCheckResult] = []

    /// The most recent persistence snapshot.
    private(set) var persistenceItems: [PersistenceItem] = []

    /// The most recent process snapshot.
    private(set) var processes: [NickProcessInfo] = []

    /// The most recent network connection snapshot.
    private(set) var connections: [NetworkConnectionInfo] = []

    /// Whether any monitor is currently running.
    private(set) var isScanning = false

    /// The last error thrown during a scan, if any.
    private(set) var lastError: Error?

    // MARK: - Overall Health Score (0–100)

    /// Computed security health score: 100 = all clear, 0 = critical issues.
    var healthScore: Int {
        guard !auditResults.isEmpty else { return 100 }
        let failCount = auditResults.filter { $0.status == .fail }.count
        let warnCount = auditResults.filter { $0.status == .warning }.count
        let alertBonus = min(alerts.filter { $0.severity >= .high }.count * 10, 40)
        let raw = 100 - (failCount * 15) - (warnCount * 5) - alertBonus
        return max(0, raw)
    }

    // MARK: - Private

    private let auditor    = SystemAuditor()
    private let persistence = PersistenceWatcher()
    private let procMon    = ProcessMonitor()
    private let netMon     = NetworkAnalyzer()
    private let correlator = ThreatCorrelator()

    private let logger = Logger(subsystem: "com.ehsanazish.nick", category: "SecurityEngine")

    // MARK: - Init

    init() {}

    // MARK: - Public API

    /// Runs all monitors sequentially and correlates the resulting signals.
    ///
    /// Each monitor is `@MainActor`-isolated; their async methods suspend (not block)
    /// while waiting for OS responses, keeping the UI responsive.
    /// This is safe to call multiple times; concurrent calls are ignored while
    /// a scan is already in progress.
    func runFullScan() async {
        guard !isScanning else { return }
        isScanning = true
        lastError = nil
        logger.info("Full scan started")

        // SystemAuditor
        do {
            try await auditor.start()
            let sigs = await auditor.latestSignals()
            await correlator.ingest(sigs)
            auditResults = auditor.results
        } catch {
            logger.error("SystemAuditor failed: \(error.localizedDescription)")
        }

        // PersistenceWatcher
        do {
            try await persistence.start()
            let sigs = await persistence.latestSignals()
            await correlator.ingest(sigs)
            persistenceItems = persistence.items
        } catch {
            logger.error("PersistenceWatcher failed: \(error.localizedDescription)")
        }

        // ProcessMonitor
        do {
            try await procMon.start()
            let sigs = await procMon.latestSignals()
            await correlator.ingest(sigs)
            processes = procMon.processes
        } catch {
            logger.error("ProcessMonitor failed: \(error.localizedDescription)")
        }

        // NetworkAnalyzer
        do {
            try await netMon.start()
            let sigs = await netMon.latestSignals()
            await correlator.ingest(sigs)
            connections = netMon.connections
        } catch {
            logger.error("NetworkAnalyzer failed: \(error.localizedDescription)")
        }

        let newAlerts = await correlator.correlate()
        alerts = newAlerts.sorted { $0.score > $1.score }
        isScanning = false
        logger.info("Full scan complete — \(newAlerts.count) alerts, health: \(self.healthScore)")
    }

    /// Clears all collected data and alerts.
    func reset() async {
        alerts = []
        auditResults = []
        persistenceItems = []
        processes = []
        connections = []
        await correlator.flush()
    }
}
