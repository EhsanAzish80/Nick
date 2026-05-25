// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation
import os

// MARK: - ConnectionFingerprint

/// A unique identifier for a connection pattern: remote address + port + protocol.
struct ConnectionFingerprint: Hashable, Codable {
    let remoteAddress: String
    let remotePort: Int
    let transportProtocol: String
}

// MARK: - NetworkBaseline

/// Builds a per-process connection fingerprint baseline over the first N scans.
///
/// After the baseline is established, new connection patterns from known
/// processes emit low-severity signals — catching C2 beaconing patterns
/// without signature detection.
///
/// **Baseline window:** 5 full scans. Before that, no anomaly signals are emitted.
/// **Persistence:** Baseline is written to Application Support so it survives restarts.
@Observable
@MainActor
final class NetworkBaseline {

    // MARK: - Constants

    static let scansRequiredForBaseline = 5

    // MARK: - Private State

    /// Maps process name → set of known (remote address, port, protocol) tuples.
    private var baseline: [String: Set<ConnectionFingerprint>] = [:]

    /// Number of full scans completed since first launch (used to gate baseline building).
    private var scanCount = 0

    private let baselineURL: URL
    private static let logger = Logger(subsystem: "com.ehsanazish.nick", category: "NetworkBaseline")

    // MARK: - Init

    init() {
        let appSupport = URL(fileURLWithPath: NSHomeDirectory())
            .appendingPathComponent("Library/Application Support/com.ehsanazish.nick")
        baselineURL = appSupport.appendingPathComponent("network-baseline.json")
        loadFromDisk()
    }

    // MARK: - Public API

    /// Updates the baseline with the current connection snapshot.
    ///
    /// Should be called once per full scan, before `anomalies(for:)`.
    /// - Parameter connections: Current network connections.
    func update(connections: [NetworkConnectionInfo]) {
        scanCount += 1

        // Only build baseline during the initial window.
        guard scanCount <= Self.scansRequiredForBaseline else { return }

        for connection in connections {
            guard let remote = connection.remoteAddress,
                  let port = connection.remotePort,
                  !connection.processName.isEmpty else { continue }
            let fp = ConnectionFingerprint(
                remoteAddress: remote,
                remotePort: port,
                transportProtocol: connection.transportProtocol.rawValue
            )
            baseline[connection.processName, default: []].insert(fp)
        }

        saveToDisk()
        Self.logger.debug("Baseline updated: \(self.baseline.count) process entries after scan \(self.scanCount)")
    }

    /// Returns anomaly signals for connections that don't match the established baseline.
    ///
    /// Returns an empty array until `scansRequiredForBaseline` full scans have completed.
    /// - Parameter connections: Current network connections to evaluate.
    /// - Returns: Low-severity signals for first-seen connection patterns.
    func anomalies(for connections: [NetworkConnectionInfo]) -> [ThreatSignal] {
        guard scanCount > Self.scansRequiredForBaseline else { return [] }

        var signals: [ThreatSignal] = []

        for connection in connections {
            guard let remote = connection.remoteAddress,
                  let port = connection.remotePort,
                  !connection.processName.isEmpty else { continue }

            let fp = ConnectionFingerprint(
                remoteAddress: remote,
                remotePort: port,
                transportProtocol: connection.transportProtocol.rawValue
            )

            // Only signal if the process is known from the baseline (new processes are handled by ProcessMonitor).
            guard let known = baseline[connection.processName] else { continue }
            guard !known.contains(fp) else { continue }

            signals.append(ThreatSignal(
                source: .network,
                severity: .low,
                title: "New connection pattern: \(connection.processName)",
                description: "\(connection.processName) connected to \(remote):\(port) — first time seen since baseline was established.",
                context: ThreatSignalContext(
                    networkInfo: NetworkConnectionInfo(
                        id: connection.id,
                        pid: connection.pid,
                        processName: connection.processName,
                        transportProtocol: connection.transportProtocol,
                        localAddress: connection.localAddress,
                        localPort: connection.localPort,
                        remoteAddress: connection.remoteAddress,
                        remotePort: connection.remotePort,
                        state: connection.state
                    ),
                    metadata: ["baseline_anomaly": "true"]
                )
            ))
        }

        return signals
    }

    // MARK: - Persistence

    private struct BaselineStorage: Codable {
        let scanCount: Int
        let baseline: [String: [ConnectionFingerprint]]
    }

    private func saveToDisk() {
        let dir = baselineURL.deletingLastPathComponent()
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let storage = BaselineStorage(
            scanCount: scanCount,
            baseline: baseline.mapValues { Array($0) }
        )
        guard let data = try? JSONEncoder().encode(storage) else { return }
        try? data.write(to: baselineURL, options: .atomic)
    }

    private func loadFromDisk() {
        guard let data = try? Data(contentsOf: baselineURL),
              let storage = try? JSONDecoder().decode(BaselineStorage.self, from: data) else { return }
        scanCount = storage.scanCount
        baseline = storage.baseline.mapValues { Set($0) }
        Self.logger.info("Network baseline restored: \(self.baseline.count) processes, \(self.scanCount) prior scans")
    }
}
