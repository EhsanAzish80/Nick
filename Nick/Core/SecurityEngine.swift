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

    /// Stable deduplication keys for alerts the user has explicitly dismissed.
    /// Persisted to `UserDefaults` so dismissed alerts do not reappear after a rescan.
    private(set) var dismissedAlertKeys: Set<String> = []

    /// The most recent set of system audit results.
    private(set) var auditResults: [SystemCheckResult] = []

    /// Firewall allowlist audit run alongside the system audit.
    private(set) var firewallAllowlist: FirewallAllowlistResult?

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

    /// URL from Finder "Scan with Nick" context menu. The scanner view
    /// consumes this on appear and starts a targeted scan. Set by the
    /// `.nickScanFileRequest` notification handler in `MainWindowView`.
    var pendingFinderScanURL: URL?

    /// The most recent threat score from the real-time ML pipeline (0.0–1.0).
    var currentThreatScore: Double = 0.0

    /// Whether the real-time pipeline is running, stopped, or degraded.
    var activePipelineStatus: PipelineStatus = .stopped

    /// The date of the most recent scan completion.
    var lastScanDate: Date?

    // MARK: - Lifetime Statistics (persisted to UserDefaults)

    /// Date Nick first launched on this system. Set once and never reset.
    private(set) var monitoringSince: Date = Date()

    /// Total number of full scans completed since installation.
    private(set) var totalScanCount: Int = 0

    /// Lifetime count of non-info threats detected across all scans.
    private(set) var totalThreatsDetected: Int = 0

    /// Date of the most recent YARA deep scan.
    var lastDeepScanDate: Date? = nil

    /// Number of files scanned in the most recent YARA deep scan.
    var lastDeepScanFileCount: Int = 0

    /// The trusted process list used to suppress false positive signals.
    ///
    /// Changing this takes effect on the next `runFullScan()` call.
    /// The user-trusted subset is automatically persisted to `UserDefaults`.
    var trustedProcessList: TrustedProcessList = {
        let saved = UserDefaults.standard.stringArray(forKey: "userTrustedProcesses") ?? []
        return TrustedProcessList(userTrusted: Set(saved))
    }() {
        didSet {
            // Persist user-configured entries whenever the list changes.
            let names = Array(trustedProcessList.userTrusted)
            UserDefaults.standard.set(names, forKey: "userTrustedProcesses")
        }
    }

    /// Active suppression rules. Persisted to UserDefaults as JSON.
    var suppressionRules: [SuppressionRule] = {
        guard let data = UserDefaults.standard.data(forKey: "suppressionRulesData"),
              let rules = try? JSONDecoder().decode([SuppressionRule].self, from: data) else { return [] }
        return rules
    }() {
        didSet {
            if let data = try? JSONEncoder().encode(suppressionRules) {
                UserDefaults.standard.set(data, forKey: "suppressionRulesData")
            }
        }
    }

    // MARK: - Overall Health Score (0–100)

    /// Computed security health score: 100 = all clear, 0 = critical issues.
    var healthScore: Int {
        guard !auditResults.isEmpty else { return -1 }
        let failCount = auditResults.filter { $0.status == .fail }.count
        let warnCount = auditResults.filter { $0.status == .warning }.count
        let alertBonus = min(alerts.filter { $0.severity >= .high }.count * 10, 40)
        let raw = 100 - (failCount * 15) - (warnCount * 5) - alertBonus
        return max(0, raw)
    }

    /// Returns `true` once the first full scan has completed and audit results are populated.
    var hasCompletedFirstScan: Bool { !auditResults.isEmpty }

    // MARK: - Private

    private let auditor    = SystemAuditor()
    private let persistence = PersistenceWatcher()
    private let procMon    = ProcessMonitor()
    private let netMon     = NetworkAnalyzer()
    private let avCapture  = AVCaptureMonitor()
    let correlator = ThreatCorrelator()

    /// Phase 7 — Performance / disk-cleanup engine.
    private(set) var performanceMonitor: PerformanceMonitor?

    /// Consumer-friendly wrappers around every active `ThreatAlert`.
    /// Rebuilt automatically whenever `mergeAlerts` is called.
    /// Use this in simple-mode UI instead of reading `alerts` directly.
    private(set) var userFacingAlerts: [UserFacingAlert] = []

    /// Shared Foundation Models explainer — used by both the full scan path and
    /// the real-time pipeline so every new alert gets an AI explanation.
    let explainer = AlertExplainer()

    /// Historical scan snapshots powering sparkline charts in the Overview.
    let scanHistory = ScanHistory()

    /// Running activity log displayed in the Overview's Recent Activity feed.
    let activityLog = ActivityLog()

    private let logger = Logger(subsystem: "com.ehsanazish.nick", category: "SecurityEngine")

    /// Stored handle for the running scan. Kept on the engine so the task outlives
    /// any SwiftUI view scope — panel hide/show cannot cancel it.
    private var scanTask: Task<Void, Never>?

    // MARK: - Init

    init() {
        let ud = UserDefaults.standard
        if let stored = ud.object(forKey: "nickMonitoringSince") as? Date {
            monitoringSince = stored
        } else {
            ud.set(monitoringSince, forKey: "nickMonitoringSince")
        }
        totalScanCount        = ud.integer(forKey: "nickTotalScanCount")
        totalThreatsDetected  = ud.integer(forKey: "nickTotalThreatsDetected")
        lastDeepScanDate      = ud.object(forKey: "nickLastDeepScanDate") as? Date
        lastDeepScanFileCount = ud.integer(forKey: "nickLastDeepScanFileCount")
        let storedKeys        = ud.stringArray(forKey: "nickDismissedAlertKeys") ?? []
        dismissedAlertKeys    = Set(storedKeys)

        // Restore alerts saved from the previous session.
        if let data = ud.data(forKey: "nickPersistedAlerts"),
           let decoded = try? JSONDecoder().decode([ThreatAlert].self, from: data) {
            // Drop any that were later dismissed.
            alerts = Self.boundedPersistedAlerts(
                decoded.filter { !dismissedAlertKeys.contains($0.deduplicationKey) }
            )
            logger.info("Restored \(self.alerts.count) persisted alert(s)")
            if let encoded = try? JSONEncoder().encode(alerts) {
                ud.set(encoded, forKey: "nickPersistedAlerts")
            }
        }

        // One-time purge: remove false-positive raw-IP alerts produced before the
        // private-network / bogus-address filters were added (v2 filter set).
        // The flag is set permanently so this runs exactly once per install.
        if !ud.bool(forKey: "nickRawIPFalsePositivePurgedV2") {
            let before = alerts.count
            alerts.removeAll { $0.title == "Outbound connection to raw IP address" }
            if alerts.count != before {
                logger.info("Purged \(before - self.alerts.count) stale raw-IP false-positive alert(s)")
                // Persist the cleaned list immediately.
                if let encoded = try? JSONEncoder().encode(alerts) {
                    ud.set(encoded, forKey: "nickPersistedAlerts")
                }
            }
            ud.set(true, forKey: "nickRawIPFalsePositivePurgedV2")
        }

        // Phase 7: initialise performance monitor
        performanceMonitor = PerformanceMonitor()
    }

    // MARK: - Public API

    /// Clears all stored threat alerts, resets threat counters, and removes all
    /// dismissed-alert suppression so every alert type can fire again.
    ///
    /// Monitoring continues uninterrupted. This only affects historical display data.
    func clearAlertHistory() {
        alerts = []
        totalThreatsDetected = 0
        dismissedAlertKeys = []
        UserDefaults.standard.set(0, forKey: "nickTotalThreatsDetected")
        UserDefaults.standard.removeObject(forKey: "nickDismissedAlertKeys")
        UserDefaults.standard.removeObject(forKey: "nickPersistedAlerts")
    }

    /// Launches a full security scan as an independent, stored task.
    ///
    /// The scan task is owned by `SecurityEngine` — not by any SwiftUI view scope.
    /// Hiding or reopening the panel has no effect on a scan in progress.
    /// Concurrent calls while a scan is in progress are ignored.
    func runFullScan() {
        guard !isScanning else { return }
        // Unstructured Task inherits @MainActor from the call site, so all state
        // mutations inside run on @MainActor without needing MainActor.run {}.
        // It is NOT a child of any view task and cannot be cancelled by SwiftUI.
        scanTask = Task { [weak self] in
            await self?.performFullScan()
        }
    }

    private func performFullScan() async {
        isScanning = true
        lastError = nil
        logger.info("Full scan started")

        // Propagate the current trusted process configuration to monitors.
        procMon.trustedProcessList = trustedProcessList
        await correlator.updateTrustedProcessList(trustedProcessList)
        await correlator.updateSuppressionRules(suppressionRules)

        await startAuditor()
        guard isScanning else { return }
        activityLog.log(
            icon: "checkmark.shield", color: "green",
            title: "System audit complete",
            subtitle: "\(auditor.results.count) check\(auditor.results.count == 1 ? "" : "s") · \(auditor.results.filter { $0.status == .pass }.count) passed"
        )

        await startPersistence()
        guard isScanning else { return }
        activityLog.log(
            icon: "checkmark.circle", color: "green",
            title: "Persistence check passed",
            subtitle: "\(persistence.items.count) launch item\(persistence.items.count == 1 ? "" : "s") verified"
        )

        await startProcMon()
        guard isScanning else { return }

        await startNetMon()
        guard isScanning else { return }
        activityLog.log(
            icon: "network", color: "green",
            title: "Network baseline updated",
            subtitle: "\(netMon.connections.count) connection\(netMon.connections.count == 1 ? "" : "s") fingerprinted"
        )

        await startAVCapture()
        guard isScanning else { return }

        // Collect signals and batch-update published state on @MainActor.
        var allSignals: [ThreatSignal] = []
        allSignals += await auditor.latestSignals()
        allSignals += await persistence.latestSignals()
        allSignals += await procMon.latestSignals()
        allSignals += await netMon.latestSignals()
        allSignals += await avCapture.latestSignals()

        auditResults     = auditor.results
        persistenceItems = persistence.items
        processes        = procMon.processes
        connections      = netMon.connections

        await correlator.resetEmittedRules()
        await correlator.ingest(allSignals)
        let newAlerts = await correlator.correlate()
        // Capture existing keys before merge so we can detect genuinely new alerts.
        let existingKeys = Set(alerts.map { $0.deduplicationKey })
        mergeAlerts(newAlerts)
        // Notify for alerts whose deduplication key was not already present, preventing
        // re-notification on every deep scan for a persistent threat (e.g. SIP still off).
        var genuinelyNew = newAlerts.filter {
            $0.severity != .info && !existingKeys.contains($0.deduplicationKey)
        }
        // Enrich new alerts with a plain-English explanation before surfacing them.
        if !genuinelyNew.isEmpty {
            for i in genuinelyNew.indices {
                let topFeatures: [(name: String, contribution: Double)] = genuinelyNew[i]
                    .contributingSignals.prefix(5).map {
                        ($0.title, Double($0.severity.rawValue) / 4.0)
                    }
                genuinelyNew[i].explanation = await explainer.explain(
                    alert: genuinelyNew[i],
                    topFeatures: topFeatures
                )
            }
        }
        for alert in genuinelyNew {
            await NotificationManager.shared.send(for: alert)
            let (fmt, outs) = buildPipeline()
            await emitAlert(alert, formatter: fmt, outputs: outs)
        }
        isScanning = false
        scanTask = nil
        lastScanDate = Date()
        totalScanCount += 1
        let newThreatCount = newAlerts.filter { $0.severity != .info }.count
        if newThreatCount > 0 { totalThreatsDetected += newThreatCount }
        let ud = UserDefaults.standard
        ud.set(totalScanCount, forKey: "nickTotalScanCount")
        ud.set(totalThreatsDetected, forKey: "nickTotalThreatsDetected")

        // Record a snapshot for sparkline charts.
        scanHistory.record(
            processes: processes.count,
            network: connections.count,
            persistence: persistenceItems.count,
            auditIssues: auditResults.filter { $0.status != .pass }.count,
            health: healthScore
        )

        // Log overall scan completion.
        let totalItems = processes.count + connections.count + persistenceItems.count + auditResults.count
        activityLog.log(
            icon: "shield.checkered", color: "blue",
            title: "Full system scan completed",
            subtitle: "\(totalItems) items checked · \(newThreatCount) threat\(newThreatCount == 1 ? "" : "s")"
        )

        // Log each actionable threat alert.
        for alert in newAlerts where alert.severity != .info {
            activityLog.log(
                icon: "exclamationmark.triangle", color: "red",
                title: "Threat detected: \(alert.title)",
                subtitle: "\(alert.severity.displayName) · \(alert.contributingSignals.count) signal\(alert.contributingSignals.count == 1 ? "" : "s")"
            )
        }

        logger.info("Full scan complete — \(newAlerts.count) alerts, health: \(self.healthScore)")
    }

    // MARK: - Private monitor starters (for async let decomposition)

    private func startAuditor() async {
        do { try await auditor.start() } catch {
            logger.error("SystemAuditor failed: \(error.localizedDescription)")
        }
        firewallAllowlist = await auditor.checkFirewallAllowlist()
    }

    private func startPersistence() async {
        do { try await persistence.start() } catch {
            logger.error("PersistenceWatcher failed: \(error.localizedDescription)")
        }
    }

    private func startProcMon() async {
        do { try await procMon.start() } catch {
            logger.error("ProcessMonitor failed: \(error.localizedDescription)")
        }
    }

    private func startNetMon() async {
        do { try await netMon.start() } catch {
            logger.error("NetworkAnalyzer failed: \(error.localizedDescription)")
        }
    }

    private func startAVCapture() async {
        do { try await avCapture.start() } catch {
            logger.error("AVCaptureMonitor failed: \(error.localizedDescription)")
        }
    }

    /// Clears all collected data and alerts.
    func reset() async {
        alerts = []
        auditResults = []
        firewallAllowlist = nil
        persistenceItems = []
        processes = []
        connections = []
        await correlator.flush()
    }

    /// Adds a single alert from the real-time pipeline.
    /// Skips dismissed alerts and alerts already shown (matched by `deduplicationKey`).
    @MainActor
    func addAlert(_ alert: ThreatAlert) {
        guard !dismissedAlertKeys.contains(alert.deduplicationKey) else { return }
        guard !alerts.contains(where: { $0.deduplicationKey == alert.deduplicationKey }) else { return }
        mergeAlerts([alert])
    }

    /// Merges new alerts from the real-time pipeline, deduplicating by ID.
    /// Alerts whose `deduplicationKey` has been previously dismissed are silently dropped.
    func mergeAlerts(_ newAlerts: [ThreatAlert]) {
        let filtered = newAlerts.filter { !dismissedAlertKeys.contains($0.deduplicationKey) }
        let newIDs = Set(filtered.map { $0.id })
        alerts = alerts.filter { !newIDs.contains($0.id) } + filtered
        alerts.sort { $0.score > $1.score }
        saveAlerts()
        rebuildUserFacingAlerts()
    }

    private func rebuildUserFacingAlerts() {
        let builder = UserFacingAlertBuilder.shared
        userFacingAlerts = alerts.map { builder.build(from: $0) }
    }

    /// Removes a single alert by ID and persists its `deduplicationKey` so it
    /// is suppressed on all future scans until `clearAlertHistory()` is called.
    func dismissAlert(_ id: UUID) {
        guard let alert = alerts.first(where: { $0.id == id }) else {
            alerts.removeAll { $0.id == id }
            return
        }
        // Record as false positive for optional local training data.
        SignalTelemetry.shared.record(signals: alert.contributingSignals, verdict: .falsePositive)
        dismissedAlertKeys.insert(alert.deduplicationKey)
        alerts.removeAll { $0.id == id }
        UserDefaults.standard.set(Array(dismissedAlertKeys), forKey: "nickDismissedAlertKeys")
        saveAlerts()
        rebuildUserFacingAlerts()
    }

    /// Hides the current alert without classifying it as a false positive or
    /// suppressing future detections of the same pattern.
    func hideAlert(_ id: UUID) {
        alerts.removeAll { $0.id == id }
        saveAlerts()
        rebuildUserFacingAlerts()
    }

    /// Removes a resolved alert (threat was killed / deleted) without adding its
    /// `deduplicationKey` to `dismissedAlertKeys`.  The same threat pattern will
    /// reappear in the alert list if the binary is re-run.
    func resolveAlert(_ id: UUID) {
        if let alert = alerts.first(where: { $0.id == id }) {
            // Record as true positive for optional local training data.
            SignalTelemetry.shared.record(signals: alert.contributingSignals, verdict: .truePositive)
        }
        alerts.removeAll { $0.id == id }
        saveAlerts()
        rebuildUserFacingAlerts()
    }

    /// Cancels an in-progress scan, clearing all progress state immediately.
    ///
    /// Cancels the stored `scanTask` (cooperative cancellation) and resets all
    /// progress state. Each stage in `performFullScan` checks `guard isScanning`
    /// so remaining stages are skipped and no partial results are committed.
    func cancelScan() {
        guard isScanning else { return }
        scanTask?.cancel()
        scanTask = nil
        isScanning = false
    }

    // MARK: - Private Helpers

    /// Encodes the current alerts array to JSON and writes it to UserDefaults
    /// so they survive app restarts.
    private func saveAlerts() {
        let bounded = Self.boundedPersistedAlerts(alerts)
        guard let data = try? JSONEncoder().encode(bounded) else { return }
        UserDefaults.standard.set(data, forKey: "nickPersistedAlerts")
    }

    /// UserDefaults rejects values around 4 MB. Keep only the newest alert
    /// summaries that fit comfortably below that boundary.
    private static func boundedPersistedAlerts(_ source: [ThreatAlert]) -> [ThreatAlert] {
        var bounded = Array(source.sorted { $0.timestamp > $1.timestamp }.prefix(100))
        let encoder = JSONEncoder()
        let byteLimit = 3_000_000
        while bounded.count > 1,
              let data = try? encoder.encode(bounded),
              data.count > byteLimit {
            bounded.removeLast()
        }
        return bounded
    }

    /// Records the completion of a YARA deep scan and persists the stats.
    func recordDeepScan(fileCount: Int) {
        lastDeepScanDate      = Date()
        lastDeepScanFileCount = fileCount
        let ud = UserDefaults.standard
        ud.set(lastDeepScanDate, forKey: "nickLastDeepScanDate")
        ud.set(fileCount, forKey: "nickLastDeepScanFileCount")
    }

    // MARK: - YARA File Scanning

    /// Lazily-created YARA engine used for on-demand file scanning.
    private var yaraEngine: YARAEngine?

    /// Scans a single file or directory with the bundled YARA rule set.
    ///
    /// The YARA engine is compiled lazily on first use from the `Rules` directory
    /// inside the app bundle. If the bundle does not contain a `Rules` directory
    /// (development builds), the engine is still initialised and will return no
    /// matches rather than crashing.
    ///
    /// - Parameter url: The file or directory URL to scan.
    /// - Returns: All YARA matches found in the target.
    /// - Throws: `YARAError` if the engine cannot initialise or the scan fails.
    func scanFile(at url: URL) async throws -> [YARAMatch] {
        if yaraEngine == nil {
            let rulesDir = Bundle.main.resourceURL?
                .appendingPathComponent("Rules").path ?? ""
            yaraEngine = try YARAEngine(rulesDirectory: rulesDir)
        }
        guard let engine = yaraEngine else { throw YARAError.noRulesCompiled }
        if url.hasDirectoryPath {
            return try await engine.scanDirectory(at: url.path, recursive: true)
        }
        return try await engine.scanFile(at: url.path)
    }
}
