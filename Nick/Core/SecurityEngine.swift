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
    private let avCapture  = AVCaptureMonitor()
    private let correlator = ThreatCorrelator()

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
    }

    // MARK: - Public API

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

        await startAuditor()
        guard isScanning else { return }

        await startPersistence()
        guard isScanning else { return }

        await startProcMon()
        guard isScanning else { return }

        await startNetMon()
        guard isScanning else { return }

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

        await correlator.ingest(allSignals)
        let newAlerts = await correlator.correlate()
        alerts = newAlerts.sorted { $0.score > $1.score }
        isScanning = false
        scanTask = nil
        lastScanDate = Date()
        totalScanCount += 1
        let newThreatCount = newAlerts.filter { $0.severity != .info }.count
        if newThreatCount > 0 { totalThreatsDetected += newThreatCount }
        let ud = UserDefaults.standard
        ud.set(totalScanCount, forKey: "nickTotalScanCount")
        ud.set(totalThreatsDetected, forKey: "nickTotalThreatsDetected")
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

    /// Merges new alerts from the real-time pipeline, deduplicating by ID.
    func mergeAlerts(_ newAlerts: [ThreatAlert]) {
        let newIDs = Set(newAlerts.map { $0.id })
        alerts = alerts.filter { !newIDs.contains($0.id) } + newAlerts
        alerts.sort { $0.score > $1.score }
    }

    /// Removes a single alert by ID (user-dismissed).
    func dismissAlert(_ id: UUID) {
        alerts.removeAll { $0.id == id }
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
