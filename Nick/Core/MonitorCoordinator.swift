// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation
import os

// MARK: - MonitorCoordinator

/// Owns the real-time signal pipeline that connects all monitors to the ML threat engine.
///
/// `MonitorCoordinator` starts each monitor, merges their `ThreatSignal` outputs,
/// feeds signals into `ThreatCorrelator`, logs alerts via `ThreatLogger`, and notifies
/// `SecurityEngine` so the UI stays current — all in a continuous async loop.
///
/// **Pipeline flow:**
/// ```
/// Monitors (ProcessMonitor, NetworkAnalyzer, PersistenceWatcher, SystemAuditor)
///       │
///       ▼ ThreatSignal
/// ThreatCorrelator (CorrelationWindow → FeatureExtractor → BehavioralScorer)
///       │
///       ▼ ThreatAlert
/// AlertExplainer → ThreatLogger → NotificationManager → SecurityEngine (UI)
/// ```
///
/// Call `startRealTimePipeline()` once from your app's startup path.
/// Call `stopPipeline()` when monitoring should cease (e.g. on quit).
@MainActor
final class MonitorCoordinator {

    // MARK: - Configuration

    /// How often the pipeline evaluates the existing signal window for new alerts.
    /// This is fast: no OS calls, just in-memory correlation.
    static let pipelineTickInterval: TimeInterval = 5.0

    /// How often a full monitor sweep is triggered to refresh the signal window.
    /// A full scan includes `lsof`, process table walk, and persistence baseline diff —
    /// measured at ~150–300 ms on Apple Silicon. Running every 60 s instead of every
    /// 5 s reduces steady-state CPU load by ~12× vs the naive approach.
    ///
    /// Reads `deepScanIntervalSeconds` from `UserDefaults` so the user's Settings
    /// preference is respected without restarting the pipeline.
    var deepScanInterval: TimeInterval {
        let stored = UserDefaults.standard.integer(forKey: "deepScanIntervalSeconds")
        return stored > 0 ? TimeInterval(stored) : 60.0
    }

    // MARK: - Private

    private let engine: SecurityEngine
    private let correlator: ThreatCorrelator
    private var logger: ThreatLogger?

    private var pipelineTask: Task<Void, Never>?
    /// Retains the FSEvents-backed YARA watcher for the lifetime of the pipeline.
    private var fileSystemWatcher: FileSystemWatcher?
    /// Tracks when the last full monitor sweep ran. Initialised to `.distantPast`
    /// so the first tick always runs a deep scan.
    private var lastDeepScan: Date = .distantPast
    /// PID set from the most recent fast-check snapshot.
    /// Empty until the first fast-check tick, which seeds the baseline.
    private var lastKnownPIDs: Set<Int32> = []

    private static let log = Logger(
        subsystem: "com.ehsanazish.nick",
        category: "MonitorCoordinator"
    )

    // MARK: - Init

    /// Creates a `MonitorCoordinator` backed by the given engine and correlator.
    ///
    /// - Parameters:
    ///   - engine: The `@MainActor`-isolated engine that owns the UI state.
    ///   - correlator: The `ThreatCorrelator` instance to feed signals into.
    ///   - threatLogger: The persistent log to record alerts. Pass `nil` to skip logging.
    init(engine: SecurityEngine, correlator: ThreatCorrelator, threatLogger: ThreatLogger? = nil) {
        self.engine = engine
        self.correlator = correlator
        self.logger = threatLogger
    }

    // MARK: - Public API

    /// Starts the continuous real-time monitoring and correlation pipeline.
    ///
    /// Launches a long-running `Task` using a **two-tier cadence**:
    ///
    /// - **Fast tick** (every `pipelineTickInterval` = 5 s): evaluates the existing
    ///   correlation window for new alerts. No OS syscalls — purely in-memory.
    /// - **Deep scan** (every `deepScanInterval` = 60 s): runs all monitors
    ///   (`lsof`, process walk, persistence diff, system audit) to refresh the
    ///   signal window. The first tick after `startRealTimePipeline()` always
    ///   runs a deep scan.
    ///
    /// This separation keeps steady-state CPU/battery impact low while still
    /// detecting newly injected signals within ~5 seconds of a deep scan.
    ///
    /// Safe to call multiple times — a second call replaces the existing pipeline.
    func startRealTimePipeline() {
        pipelineTask?.cancel()

        // Start FSEvents-backed YARA real-time scanner.
        do {
            let rulesDir = (Bundle.main.resourcePath ?? "") + "/Rules"
            let yaraEngine = try YARAEngine(rulesDirectory: rulesDir)
            let watcher = FileSystemWatcher(yaraEngine: yaraEngine) { [weak self] signal in
                Task { [weak self] in
                    guard let self else { return }
                    await self.correlator.ingest([signal])
                    let alerts = await self.correlator.correlateNew()
                    guard !alerts.isEmpty else { return }
                    for alert in alerts {
                        await NotificationManager.shared.send(for: alert)
                    }
                    await self.addFileSystemWatcherAlerts(alerts)
                }
            }
            watcher.startWatching()
            fileSystemWatcher = watcher
        } catch {
            Self.log.error("FileSystemWatcher: YARAEngine init failed — \(error.localizedDescription, privacy: .public)")
        }

        pipelineTask = Task { [weak self] in
            guard let self else { return }
            Self.log.info("Real-time pipeline started (tick interval: \(Self.pipelineTickInterval)s)")
            await MainActor.run { self.engine.activePipelineStatus = .running }

            while !Task.isCancelled {
                await self.tick()
                try? await Task.sleep(nanoseconds: UInt64(Self.pipelineTickInterval * 1_000_000_000))
            }

            Self.log.info("Real-time pipeline stopped")
            await MainActor.run { self.engine.activePipelineStatus = .stopped }
        }
    }

    /// Stops the real-time pipeline.
    func stopPipeline() {
        fileSystemWatcher?.stopWatching()
        fileSystemWatcher = nil
        pipelineTask?.cancel()
        pipelineTask = nil
        Task { @MainActor [weak self] in
            self?.engine.activePipelineStatus = .stopped
        }
    }

    // MARK: - Private Pipeline Tick

    @MainActor
    private func addFileSystemWatcherAlerts(_ alerts: [ThreatAlert]) {
        for alert in alerts { engine.addAlert(alert) }
    }

    private func tick() async {
        // Two-tier cadence: expensive OS sweeps only every deepScanInterval.
        // Correlation runs every tick against the already-buffered signal window.
        let now = Date()
        if now.timeIntervalSince(lastDeepScan) >= deepScanInterval {
            Self.log.debug("Pipeline deep scan (last: \(self.lastDeepScan.formatted())")
            // runFullScan handles its own ingest → correlate → mergeAlerts → UI update.
            // Returning here prevents a second correlate() call racing against it.
            engine.runFullScan()
            lastDeepScan = now
            return
        }

        Self.log.debug("Pipeline fast tick (next deep scan in \(Int(self.deepScanInterval - now.timeIntervalSince(self.lastDeepScan)))s)")
        await quickTick()
    }

    // MARK: - Quick Process Tick

    /// Performs a lightweight per-PID check for newly spawned suspicious processes.
    ///
    /// Uses `ProcessScanner.quickPIDList()` (pure sysctl, no path resolution) to diff
    /// against the previous snapshot. For each new PID, `ProcessScanner.quickInfo(pid:)`
    /// fetches name, path, and parent — then three inline checks fire:
    ///   1. Executable launched from a temp directory
    ///   2. LOLBin argument pattern (`LOLBinDetector`)
    ///   3. Suspicious parent → child chain (`ParentChainAnalyzer`)
    ///
    /// Signals are ingested into the correlator and correlated immediately; each
    /// resulting alert is pushed to `SecurityEngine` and delivered as a notification.
    private func quickTick() async {
        let currentPIDs = ProcessScanner.quickPIDList()
        defer { lastKnownPIDs = currentPIDs }

        // First call: seed baseline without emitting signals.
        guard !lastKnownPIDs.isEmpty else { return }

        let newPIDs = currentPIDs.subtracting(lastKnownPIDs)

        Self.log.info("quickTick: \(currentPIDs.count) current PIDs, \(newPIDs.count) new")

        guard !newPIDs.isEmpty else { return }

        var newSignals: [ThreatSignal] = []

        for pid in newPIDs {
            guard let info = ProcessScanner.quickInfo(pid: pid) else { continue }

            Self.log.info("quickTick: new PID \(pid) — \(info.name, privacy: .public) at \(info.path, privacy: .public) args: \(info.arguments.joined(separator: " "), privacy: .public)")

            if engine.trustedProcessList.isTrusted(info.name) { continue }

            // Check 1: Executable in a writable temp directory, OR interpreter running
            // a script whose first argument points to a temp-directory path.
            // Catches: /tmp/evil (direct) AND /bin/bash /tmp/evil.sh (interpreter pattern).
            let p = info.path
            let isTempExec = !p.isEmpty && (p.hasPrefix("/tmp/") || p.hasPrefix("/private/tmp/")
                                            || p.hasPrefix("/var/tmp/")
                                            || p.hasPrefix("/private/var/folders/"))
            let interpreterBinaries: Set<String> = [
                "bash", "sh", "zsh", "python3", "python", "ruby", "perl", "node"
            ]
            let execName = p.components(separatedBy: "/").last ?? p
            let isInterpreter = interpreterBinaries.contains(execName)
            let scriptInTmp = info.arguments.first {
                $0.hasPrefix("/tmp/") || $0.hasPrefix("/private/tmp/") || $0.hasPrefix("/var/tmp/")
            }

            if isTempExec || (isInterpreter && scriptInTmp != nil) {
                let detectedPath = scriptInTmp ?? p
                newSignals.append(ThreatSignal(
                    source: .process,
                    severity: .high,
                    title: "Script executing from temp directory",
                    description: "'\(info.name)' (PID \(pid)) is executing '\(detectedPath)' from a writable temporary location.",
                    context: ThreatSignalContext(
                        processInfo: info,
                        metadata: ["reason": "temp_path_spawn", "script_path": detectedPath]
                    )
                ))
            }

            // Check 2: LOLBin argument patterns
            let parentInfo = ProcessScanner.quickInfo(pid: info.parentPID)
            if let signal = LOLBinDetector.evaluate(
                info, parentName: parentInfo?.name,
                trustedProcessList: engine.trustedProcessList
            ) {
                newSignals.append(signal)
            }

            // Check 3: Suspicious parent → child chain
            if let parent = parentInfo {
                let chain = ParentChainAnalyzer.ProcessChain(processes: [parent, info])
                if let signal = ParentChainAnalyzer.evaluateChain(
                    chain, trustedProcessList: engine.trustedProcessList
                ) {
                    newSignals.append(signal)
                }
            }
        }

        guard !newSignals.isEmpty else { return }

        Self.log.info("Quick tick: \(newSignals.count) signal(s) from \(newPIDs.count) new PID(s)")
        await correlator.ingest(newSignals)

        let newAlerts = await correlator.correlateNew()
        guard !newAlerts.isEmpty else { return }

        for var alert in newAlerts {
            let explanation = await engine.explainer.explain(alert: alert, topFeatures: [])
            alert.explanation = explanation
            await logger?.log(alert: alert, explanation: explanation)
            await NotificationManager.shared.send(for: alert)
            let (fmt, outs) = buildPipeline()
            await emitAlert(alert, formatter: fmt, outputs: outs)
            Self.log.info("Quick tick alert: \(alert.title) score=\(alert.score)")
        }

        await MainActor.run { [engine, newAlerts] in
            for alert in newAlerts {
                engine.addAlert(alert)
            }
            engine.currentThreatScore = newAlerts.map { $0.score }.max() ?? engine.currentThreatScore
            engine.lastScanDate = Date()
        }
    }
}

// MARK: - PipelineStatus

/// The operational state of `MonitorCoordinator`'s real-time pipeline.
enum PipelineStatus: String, Sendable {
    case stopped  = "Stopped"
    case running  = "Running"
    case degraded = "Degraded"

    var systemImage: String {
        switch self {
        case .stopped:  "pause.circle"
        case .running:  "play.circle"
        case .degraded: "exclamationmark.circle"
        }
    }
}
