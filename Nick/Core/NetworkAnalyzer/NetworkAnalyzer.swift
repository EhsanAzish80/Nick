// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation
import Observation
import os

// MARK: - NetworkAnalyzer

/// Snapshot monitor that enumerates active network connections and derives threat signals.
///
/// Wraps `ConnectionScanner` with the `MonitorProtocol` interface. Phase 1 is
/// snapshot-only; Phase 2 adds continuous socket monitoring via
/// `proc_pidfdinfo` and network extensions.
@Observable
@MainActor
final class NetworkAnalyzer: MonitorProtocol {

    // MARK: - MonitorProtocol

    let monitorType: MonitorType = .network
    private(set) var isRunning = false

    // MARK: - Published State

    /// All connections found in the most recent snapshot.
    private(set) var connections: [NetworkConnectionInfo] = []

    // MARK: - Private

    private var pendingSignals: [ThreatSignal] = []
    private let scanner = ConnectionScanner()
    private let baseline = NetworkBaseline()

    private static let logger = Logger(
        subsystem: "com.ehsanazish.nick",
        category: "NetworkAnalyzer"
    )

    // MARK: - MonitorProtocol

    /// Performs a single snapshot scan.
    func start() async throws {
        guard !isRunning else { return }
        isRunning = true
        defer { isRunning = false }

        let scanned: [NetworkConnectionInfo]
        do {
            scanned = try await scanner.scan()
        } catch {
            Self.logger.error("Network scan failed: \(error.localizedDescription)")
            throw error
        }

        connections = scanned

        // Signature validation used by the trusted-process check can block while
        // macOS warms its trust cache. NetworkAnalyzer is MainActor-isolated for UI
        // state, so derive those signals away from the main thread.
        let connectionSignals = await Task.detached(priority: .utility) {
            ConnectionScanner().signals(from: scanned)
        }.value

        // Update baseline first, then detect anomalies.
        baseline.update(connections: scanned)
        let baselineSignals = baseline.anomalies(for: scanned)
        pendingSignals = connectionSignals + baselineSignals
        Self.logger.info("Network snapshot: \(scanned.count) connections, \(self.pendingSignals.count) signals (\(baselineSignals.count) baseline anomalies)")
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
