// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation
import Observation
import os

// MARK: - ProcessMonitor

/// Snapshot monitor that enumerates all running processes and derives threat signals.
///
/// `ProcessMonitor` wraps `ProcessScanner` with the `MonitorProtocol` interface.
/// In Phase 1 it is purely snapshot-based; Phase 2 adds OpenBSM / Endpoint Security
/// continuous monitoring.
@Observable
@MainActor
final class ProcessMonitor: MonitorProtocol {

    // MARK: - MonitorProtocol

    let monitorType: MonitorType = .process
    private(set) var isRunning = false

    // MARK: - Published State

    /// All processes found in the most recent snapshot.
    ///
    /// Populated immediately by `scanFast()` with `.pending` signing statuses,
    /// then updated in-place as `SignatureValidator.backfill` resolves each entry.
    private(set) var processes: [NickProcessInfo] = []

    /// The trusted process list used to suppress false positive signals.
    ///
    /// Set this before calling `start()` to apply the current user configuration.
    var trustedProcessList: TrustedProcessList = TrustedProcessList()

    // MARK: - Private

    private var pendingSignals: [ThreatSignal] = []
    /// Background task that resolves `.pending` signing statuses after the fast scan.
    private var backfillTask: Task<Void, Never>?

    private static let logger = Logger(
        subsystem: "com.ehsanazish.nick",
        category: "ProcessMonitor"
    )

    // MARK: - MonitorProtocol

    /// Performs a two-phase process scan.
    ///
    /// **Phase 1 (fast):** `scanFast()` enumerates all processes via `sysctl` and
    /// resolves paths — but skips `SecStaticCodeCheckValidity`. Results appear in
    /// `processes` immediately with `signingStatus == .pending`. Typical duration: < 0.1s.
    ///
    /// **Phase 2 (background):** A detached background `Task` calls
    /// `SignatureValidator.backfill`, evaluating each binary's signing status and
    /// updating the corresponding entry in `processes` as results arrive.
    /// Typical duration: 5–40s depending on process count and cache state.
    ///
    /// Signals are derived after Phase 1 using `.pending` as a neutral status
    /// (no false positives emitted for unvalidated processes). After Phase 2
    /// completes the UI reflects accurate signing information.
    func start() async throws {
        guard !isRunning else { return }
        isRunning = true
        defer { isRunning = false }

        // Phase 1 — fast snapshot, no signing validation
        let scanned = try await Task.detached(priority: .userInitiated) {
            try ProcessScanner().scanFast()
        }.value

        processes = scanned

        // Generate signals immediately from the fast snapshot.
        // Unsigned-binary rules re-run after backfill via signalFromResolved(_:).
        let initialSignals = ProcessScanner().signals(from: scanned, trustedProcessList: trustedProcessList)
        pendingSignals = initialSignals
        Self.logger.info("Process snapshot: \(scanned.count) processes, \(initialSignals.count) signals (signing deferred)")

        // Phase 2 — resolve signing statuses in the background.
        backfillTask?.cancel()
        backfillTask = Task.detached(priority: .background) { [weak self] in
            guard let self else { return }
            await SignatureValidator.shared.backfill(processes: scanned) { [weak self] updated in
                await self?.handleBackfilledProcess(updated)
            }
        }
    }

    @MainActor
    private func handleBackfilledProcess(_ updated: NickProcessInfo) {
        guard let idx = processes.firstIndex(where: { $0.pid == updated.pid }) else { return }
        processes[idx] = updated

        // Emit an additional signal if the resolved status is suspicious
        // and was not already flagged in the initial scan.
        if updated.signingStatus.isSuspicious {
            let signal = ProcessScanner().signalFromResolved(updated)
            if let signal { pendingSignals.append(signal) }
        }
    }

    func stop() async {
        backfillTask?.cancel()
        backfillTask = nil
        isRunning = false
    }

    func latestSignals() async -> [ThreatSignal] {
        let signals = pendingSignals
        pendingSignals = []
        return signals
    }
}
