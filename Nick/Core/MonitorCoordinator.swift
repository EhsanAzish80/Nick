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

    /// How often the real-time pipeline polls monitors and correlates signals.
    static let pipelineTickInterval: TimeInterval = 5.0

    // MARK: - Private

    private let engine: SecurityEngine
    private let correlator: ThreatCorrelator
    private let explainer = AlertExplainer()
    private var logger: ThreatLogger?

    private var pipelineTask: Task<Void, Never>?

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
    /// Launches a long-running `Task` that:
    /// 1. Runs all monitors concurrently via `SecurityEngine.runFullScan()`.
    /// 2. Correlates the current window with `ThreatCorrelator.correlate()`.
    /// 3. Generates natural-language explanations for new alerts.
    /// 4. Logs new alerts to `ThreatLogger`.
    /// 5. Updates `SecurityEngine` state on the main actor.
    /// 6. Waits `pipelineTickInterval` seconds, then repeats.
    ///
    /// Safe to call multiple times — a second call replaces the existing pipeline.
    func startRealTimePipeline() {
        pipelineTask?.cancel()
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
        pipelineTask?.cancel()
        pipelineTask = nil
        Task { @MainActor [weak self] in
            self?.engine.activePipelineStatus = .stopped
        }
    }

    // MARK: - Private Pipeline Tick

    private func tick() async {
        Self.log.debug("Pipeline tick")

        // Run monitors and ingest signals
        await engine.runFullScan()

        // Correlate current window
        let newAlerts = await correlator.correlate()
        guard !newAlerts.isEmpty else { return }

        // Enrich and log each new alert
        for var alert in newAlerts {
            // Generate explanation (async, Foundation Models on macOS 26+)
            let explanation = await explainer.explain(alert: alert, topFeatures: [])
            alert.explanation = explanation

            // Log to persistent store
            await logger?.log(alert: alert, explanation: explanation)

            Self.log.info("Pipeline alert: \(alert.title) score=\(alert.score)")
        }

        // Update engine on main actor with enriched alerts
        await MainActor.run { [engine, newAlerts] in
            engine.mergeAlerts(newAlerts)
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
