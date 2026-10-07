// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation
import Observation
import os

enum MenuBarAttentionState: Int, Comparable, Sendable {
    case protected
    case review
    case urgent

    static func < (lhs: Self, rhs: Self) -> Bool {
        lhs.rawValue < rhs.rawValue
    }

    static func evaluate(_ alerts: [ThreatAlert]) -> Self {
        alerts.reduce(.protected) { current, alert in
            guard alert.severity != .info else { return current }
            switch alert.evidenceState() {
            case .fileNoLongerExists, .processEnded:
                return current
            case .fileAvailable, .processActive, .historical:
                return max(current, alert.severity >= .high ? .urgent : .review)
            }
        }
    }
}

extension ThreatAlert {
    /// Whether this alert still has evidence a user can act on. Keeping this in
    /// Core gives the sidebar badge, Alerts view, and menu-bar state one source
    /// of truth instead of letting persisted, expired evidence disagree.
    var hasActionableEvidence: Bool {
        switch evidenceState() {
        case .fileNoLongerExists, .processEnded:
            return false
        case .fileAvailable, .processActive, .historical:
            return true
        }
    }
}

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
    /// Persisted by the root-owned incident store so dismissals survive restart.
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

    /// App-lifetime deep scanner. Keeping this on the engine allows a scan and its
    /// progress/results to survive sidebar navigation and Scan view reconstruction.
    private(set) var deepScanner = DeepScanner()

    /// The trusted process list used to suppress false positive signals.
    ///
    /// Changing this takes effect on the next `runFullScan()` call.
    /// The user-trusted subset is automatically persisted to `UserDefaults`.
    var trustedProcessList: TrustedProcessList = {
        let saved = UserDefaults.standard.stringArray(forKey: "userTrustedProcesses") ?? []
        let entries: Set<TrustedProcessList.UserEntry>
        if let data = UserDefaults.standard.data(forKey: "userTrustedProcessIdentities"),
           let decoded = try? JSONDecoder().decode(Set<TrustedProcessList.UserEntry>.self, from: data) {
            entries = decoded
        } else {
            entries = []
        }
        return TrustedProcessList(userTrusted: Set(saved), userEntries: entries)
    }() {
        didSet {
            // Persist user-configured entries whenever the list changes.
            let names = Array(trustedProcessList.userTrusted)
            UserDefaults.standard.set(names, forKey: "userTrustedProcesses")
            if let data = try? JSONEncoder().encode(trustedProcessList.userEntries) {
                UserDefaults.standard.set(data, forKey: "userTrustedProcessIdentities")
            }
        }
    }

    /// Active suppression rules. Persisted to UserDefaults as JSON.
    var suppressionRules: [SuppressionRule] = {
        guard let data = UserDefaults.standard.data(forKey: "suppressionRulesData"),
              let rules = try? JSONDecoder().decode([SuppressionRule].self, from: data) else { return [] }
        let result = SuppressionRule.migrateLegacySignedProcessRules(rules) {
            SignatureValidator.shared.evaluate(binaryPath: $0)
        }
        if result.changed,
           let migratedData = try? JSONEncoder().encode(result.rules) {
            UserDefaults.standard.set(migratedData, forKey: "suppressionRulesData")
        }
        UserDefaults.standard.set(result.notices, forKey: "suppressionRuleMigrationNotices")
        return result.rules
    }() {
        didSet {
            if let data = try? JSONEncoder().encode(suppressionRules) {
                UserDefaults.standard.set(data, forKey: "suppressionRulesData")
            }
        }
    }

    var suppressionRuleMigrationNotices: [String] {
        UserDefaults.standard.stringArray(forKey: "suppressionRuleMigrationNotices") ?? []
    }

    func dismissSuppressionMigrationNotices() {
        UserDefaults.standard.removeObject(forKey: "suppressionRuleMigrationNotices")
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

    /// Highest attention level among alerts that are still actionable. Historical
    /// records whose file/process has gone away do not keep the menu-bar icon red.
    var menuBarAttentionState: MenuBarAttentionState {
        MenuBarAttentionState.evaluate(activeActionableAlerts)
    }

    /// Consumer-facing alerts that still have actionable evidence.
    var activeActionableAlerts: [ThreatAlert] {
        alerts.filter { alert in
            alert.hasActionableEvidence
                && UserFacingAlertBuilder.shared.build(from: alert).severity != .safe
        }
    }

    // MARK: - Private

    private let auditor    = SystemAuditor()
    private let persistence = PersistenceWatcher()
    private let procMon    = ProcessMonitor()
    private let netMon     = NetworkAnalyzer()
    private let avCapture  = AVCaptureMonitor()
    let correlator = ThreatCorrelator()
    private(set) var incidentStore = IncidentStore()
    private var incidentActionAuthorizer: ((UUID, IncidentActionKind) async -> Bool)?

    /// Phase 7 — Performance / disk-cleanup engine.
    private(set) var performanceMonitor: PerformanceMonitor?

    /// Consumer-friendly wrappers around every active `ThreatAlert`.
    /// Rebuilt automatically whenever `mergeAlerts` is called.
    /// Use this in simple-mode UI instead of reading `alerts` directly.
    private(set) var userFacingAlerts: [UserFacingAlert] = []

    /// Shared local explainer used by both the full scan path and the real-time
    /// pipeline so every new alert gets deterministic display text.
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
        incidentStore.configure(
            trustedProcessList: trustedProcessList,
            suppressionRules: suppressionRules
        )
        deepScanner.engine = self
        procMon.processDidUpdate = { [weak self] updated in
            self?.applyResolvedProcess(updated)
        }
        avCapture.signalHandler = { [weak self] signal in
            guard let self else { return }
            _ = await self.ingestLiveFinding(
                signal,
                score: 0.55,
                recommendedAction: "Confirm that camera or microphone use matches what you are doing."
            )
        }
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
        syncAlertsFromStore()

        // One-time purge: remove false-positive raw-IP alerts produced before the
        // private-network / bogus-address filters were added (v2 filter set).
        // The flag is set permanently so this runs exactly once per install.
        if !ud.bool(forKey: "nickRawIPFalsePositivePurgedV2") {
            let before = alerts.count
            incidentStore.removeIncidents {
                $0.alert.title == "Outbound connection to raw IP address"
            }
            alerts = incidentStore.visibleAlerts
            if alerts.count != before {
                logger.info("Purged \(before - self.alerts.count) stale raw-IP false-positive alert(s)")
            }
            ud.set(true, forKey: "nickRawIPFalsePositivePurgedV2")
        }

        // Phase 7: initialise performance monitor
        performanceMonitor = PerformanceMonitor()
        rebuildUserFacingAlerts()
    }

    /// Mirrors asynchronous signing updates from `ProcessMonitor` into the
    /// published snapshot used by the Processes table.
    private func applyResolvedProcess(_ updated: NickProcessInfo) {
        guard let index = ProcessMonitor.matchingIndex(for: updated, in: processes) else { return }
        processes[index] = updated
    }

    // MARK: - Public API

    func prepareLegacyIncidentMigration() -> Data? {
        try? incidentStore.prepareLegacyMigration()
    }

    func installPrivilegedIncidentStore(
        payload: Data,
        persistence: @escaping (Data) -> Void,
        authorizer: @escaping (UUID, IncidentActionKind) async -> Bool,
        removeLegacyState: Bool
    ) throws {
        try incidentStore.installPrivilegedSnapshot(payload, persistence: persistence)
        incidentActionAuthorizer = authorizer
        if removeLegacyState {
            incidentStore.removeLegacyPersistence()
        }
        syncAlertsFromStore()
        logger.info("Restored \(self.alerts.count) root-owned incident(s)")
    }

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
        UserDefaults.standard.removeObject(forKey: "nickExpectedAlertCooldowns")
        UserDefaults.standard.removeObject(forKey: "nickPersistedAlerts")
        incidentStore.clear()
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

        // Propagate the current trusted process configuration to monitors and
        // the one post-correlation policy boundary.
        procMon.trustedProcessList = trustedProcessList
        incidentStore.configure(trustedProcessList: trustedProcessList, suppressionRules: suppressionRules)

        var genuinelyNew: [ThreatAlert] = []

        await startAuditor()
        guard isScanning else { return }
        genuinelyNew += await ingestSignals(await auditor.latestSignals())
        activityLog.log(
            icon: "checkmark.shield", color: "green",
            title: "System audit complete",
            subtitle: "\(auditor.results.count) check\(auditor.results.count == 1 ? "" : "s") · \(auditor.results.filter { $0.status == .pass }.count) passed"
        )

        await startPersistence()
        guard isScanning else { return }
        genuinelyNew += await ingestSignals(await persistence.latestSignals())
        activityLog.log(
            icon: "checkmark.circle", color: "green",
            title: "Persistence check passed",
            subtitle: "\(persistence.items.count) launch item\(persistence.items.count == 1 ? "" : "s") verified"
        )

        await startProcMon()
        guard isScanning else { return }
        genuinelyNew += await ingestSignals(await procMon.latestSignals())

        await startNetMon()
        guard isScanning else { return }
        genuinelyNew += await ingestSignals(await netMon.latestSignals())
        activityLog.log(
            icon: "network", color: "green",
            title: "Network baseline updated",
            subtitle: "\(netMon.connections.count) connection\(netMon.connections.count == 1 ? "" : "s") fingerprinted"
        )

        await startAVCapture()
        guard isScanning else { return }
        genuinelyNew += await ingestSignals(await avCapture.latestSignals())

        auditResults     = auditor.results
        persistenceItems = persistence.items
        processes        = procMon.processes
        connections      = netMon.connections

        genuinelyNew = Array(Dictionary(grouping: genuinelyNew, by: IncidentStore.incidentKey(for:))
            .compactMap { $0.value.max(by: { $0.severity < $1.severity }) })
        for alert in genuinelyNew {
            await NotificationManager.shared.send(for: alert)
            let (fmt, outs) = buildPipeline()
            await emitAlert(alert, formatter: fmt, outputs: outs)
        }
        isScanning = false
        scanTask = nil
        lastScanDate = Date()
        totalScanCount += 1
        let newThreatCount = genuinelyNew.count
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
        for alert in genuinelyNew {
            activityLog.log(
                icon: "exclamationmark.triangle", color: "red",
                title: "Threat detected: \(alert.title)",
                subtitle: "\(alert.severity.displayName) · \(alert.contributingSignals.count) signal\(alert.contributingSignals.count == 1 ? "" : "s")"
            )
        }

        logger.info("Full scan complete — \(genuinelyNew.count) new incidents, health: \(self.healthScore)")
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

    /// Shared ingestion boundary used by full scans, quick ticks, Deep Scan and
    /// FSEvents. Correlation stays deterministic; the incident store then applies
    /// trust, suppression and dedup exactly once and persists the explanation.
    @discardableResult
    func ingestSignals(_ signals: [ThreatSignal]) async -> [ThreatAlert] {
        guard !signals.isEmpty else { return [] }
        var candidates = await correlator.ingestAndCorrelateNew(signals.map(Evidence.init(signal:)))
        for index in candidates.indices {
            let topFeatures: [(name: String, contribution: Double)] = candidates[index]
                .contributingSignals.prefix(5).map {
                    ($0.title, Double($0.severity.rawValue) / 4.0)
                }
            candidates[index].explanation = await explainer.explain(
                alert: candidates[index],
                topFeatures: topFeatures
            )
        }
        incidentStore.configure(trustedProcessList: trustedProcessList, suppressionRules: suppressionRules)
        let result = incidentStore.ingest(candidates)
        alerts = result.visibleAlerts
        rebuildUserFacingAlerts()
        return result.newlyActionable
    }

    /// Sends an already-classified source finding through the same incident,
    /// suppression, deduplication, explanation and notification boundary as
    /// correlated monitor output. Sources such as Endpoint Security and the
    /// Network Extension have already applied their detector-specific rule.
    @discardableResult
    func ingestLiveFinding(
        _ signal: ThreatSignal,
        score: Double,
        recommendedAction: String
    ) async -> [ThreatAlert] {
        var alert = ThreatAlert(
            score: score,
            content: AlertContent(
                title: signal.title,
                description: signal.description,
                severity: signal.severity,
                recommendedAction: recommendedAction
            ),
            contributingSignals: [signal],
            timestamp: signal.timestamp
        )
        alert.explanation = await explainer.explain(
            alert: alert,
            topFeatures: [(signal.title, Double(signal.severity.rawValue) / 4.0)]
        )
        incidentStore.configure(trustedProcessList: trustedProcessList, suppressionRules: suppressionRules)
        let result = incidentStore.ingest([alert])
        alerts = result.visibleAlerts
        rebuildUserFacingAlerts()
        for newAlert in result.newlyActionable {
            await NotificationManager.shared.send(for: newAlert)
            let (formatter, outputs) = buildPipeline()
            await emitAlert(newAlert, formatter: formatter, outputs: outputs)
        }
        return result.newlyActionable
    }

    /// Adds a single alert from the real-time pipeline. Repeat evidence updates
    /// the existing incident rather than creating another card.
    @MainActor
    func addAlert(_ alert: ThreatAlert) {
        incidentStore.configure(trustedProcessList: trustedProcessList, suppressionRules: suppressionRules)
        let result = incidentStore.ingest([alert])
        alerts = result.visibleAlerts
        rebuildUserFacingAlerts()
    }

    /// Merges new alerts from the real-time pipeline by stable incident identity.
    /// Alerts whose `deduplicationKey` has been previously dismissed are silently dropped.
    func mergeAlerts(_ newAlerts: [ThreatAlert]) {
        incidentStore.configure(trustedProcessList: trustedProcessList, suppressionRules: suppressionRules)
        alerts = incidentStore.ingest(newAlerts).visibleAlerts
        rebuildUserFacingAlerts()
    }

    private func rebuildUserFacingAlerts() {
        let builder = UserFacingAlertBuilder.shared
        userFacingAlerts = alerts.map { builder.build(from: $0) }
    }

    private func syncAlertsFromStore() {
        alerts = incidentStore.visibleAlerts
        dismissedAlertKeys = incidentStore.dismissedAlertDeduplicationKeys
        rebuildUserFacingAlerts()
    }

    /// Removes a single alert by ID and persists its `deduplicationKey` so it
    /// is suppressed on all future scans until `clearAlertHistory()` is called.
    func dismissAlert(_ id: UUID) {
        performAuthenticatedIncidentAction(.dismissed, alertID: id) { [weak self] alert in
            SignalTelemetry.shared.record(signals: alert.contributingSignals, verdict: .falsePositive)
            self?.incidentStore.performAuthenticatedUserAction(.dismissed, alertID: id)
        }
    }

    /// Hides the current alert without classifying it as a false positive or
    /// suppressing future detections of the same pattern.
    func hideAlert(_ id: UUID) {
        performAuthenticatedIncidentAction(.hidden, alertID: id) { [weak self] _ in
            self?.incidentStore.performAuthenticatedUserAction(.hidden, alertID: id)
        }
    }

    /// Acknowledges this exact, non-critical behavior for 24 hours. Exact malware
    /// detections cannot be muted; reviewable shell-profile and SSH-key changes
    /// may be acknowledged so normal developer workflows do not alert repeatedly.
    func allowAlertOnce(_ id: UUID) {
        performAuthenticatedIncidentAction(.allowedOnce, alertID: id) { [weak self] alert in
            SignalTelemetry.shared.record(signals: alert.contributingSignals, verdict: .falsePositive)
            self?.incidentStore.performAuthenticatedUserAction(.allowedOnce, alertID: id)
        }
    }

    /// Trusts a user-confirmed application/process for future behavioural
    /// correlation. Exact malware hash detections are intentionally excluded
    /// from this preference.
    func alwaysAllowBehavior(from alertID: UUID) {
        performAuthenticatedIncidentAction(.alwaysAllowed, alertID: alertID) { [weak self] alert in
            guard let self,
                  let name = alert.contributingSignals.compactMap(\.processInfo?.name)
                    .first(where: { !$0.isEmpty }) else { return }
            let signedIdentity = alert.contributingSignals.compactMap { signal -> String? in
                guard let process = signal.processInfo,
                      case .signed(let teamID, let signingID?) = process.signingStatus,
                      !teamID.isEmpty,
                      !signingID.isEmpty else { return nil }
                return "\(teamID)|\(signingID)"
            }.first
            guard let signedIdentity else {
                // Unsigned/name-only identities are trivial to impersonate. They
                // may be accepted once, but never receive persistent trust.
                return
            }
            suppressionRules.append(SuppressionRule(
                type: .signedProcess,
                value: signedIdentity,
                note: "Accepted \(name) for this behavior",
                behaviorContext: SuppressionRule.contextFingerprint(for: alert),
                expiresAt: Calendar.current.date(byAdding: .day, value: 7, to: Date())
            ))
            SignalTelemetry.shared.record(signals: alert.contributingSignals, verdict: .falsePositive)
            // Remove only repeats of this same behavior. Different activity from
            // the same app remains visible and reviewable.
            incidentStore.configure(trustedProcessList: trustedProcessList, suppressionRules: suppressionRules)
            incidentStore.performAuthenticatedUserAction(.alwaysAllowed, alertID: alertID)
            syncAlertsFromStore()
        }
    }

    /// Removes a resolved alert (threat was killed / deleted) without adding its
    /// `deduplicationKey` to `dismissedAlertKeys`.  The same threat pattern will
    /// reappear in the alert list if the binary is re-run.
    func resolveAlert(_ id: UUID) {
        performAuthenticatedIncidentAction(.resolved, alertID: id) { [weak self] alert in
            SignalTelemetry.shared.record(signals: alert.contributingSignals, verdict: .truePositive)
            self?.incidentStore.performAuthenticatedUserAction(.resolved, alertID: id)
        }
    }

    private func performAuthenticatedIncidentAction(
        _ action: IncidentActionKind,
        alertID: UUID,
        mutation: @escaping (ThreatAlert) -> Void
    ) {
        guard let alert = alerts.first(where: { $0.id == alertID }),
              let incidentActionAuthorizer else { return }
        Task { @MainActor [weak self] in
            guard await incidentActionAuthorizer(alertID, action), let self else { return }
            mutation(alert)
            self.syncAlertsFromStore()
        }
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
