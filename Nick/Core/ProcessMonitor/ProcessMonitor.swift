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
    private(set) var processes: [NickProcessInfo] = []

    // MARK: - Private

    private var pendingSignals: [ThreatSignal] = []
    private let scanner = ProcessScanner()

    private static let logger = Logger(
        subsystem: "com.ehsanazish.nick",
        category: "ProcessMonitor"
    )

    // MARK: - MonitorProtocol

    /// Performs a single snapshot scan and derives threat signals.
    func start() async throws {
        guard !isRunning else { return }
        isRunning = true
        defer { isRunning = false }

        let scanned: [NickProcessInfo]
        do {
            scanned = try scanner.scan()
        } catch {
            Self.logger.error("Process scan failed: \(error.localizedDescription)")
            throw error
        }

        processes = scanned
        pendingSignals = scanner.signals(from: scanned)
        Self.logger.info("Process snapshot: \(scanned.count) processes, \(self.pendingSignals.count) signals")
    }

    func stop() async {
        isRunning = false
    }

    func latestSignals() async -> [ThreatSignal] {
        let signals = pendingSignals
        pendingSignals = []
        return signals
    }
}
