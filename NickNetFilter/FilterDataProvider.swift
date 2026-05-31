// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import NetworkExtension
import os

// MARK: - FilterDataProvider

/// `NEFilterDataProvider` subclass that evaluates outbound network flows
/// against multiple detection layers:
///
/// 1. **Blocklist** (`NetworkBlocklist`) — known malware C2 domains and IPs.
/// 2. **Suspicious port check** — allow-list of well-known safe ports; flag unknown.
/// 3. **ScamGuardian** — phishing / typosquat heuristics.
/// 4. **ConnectionTracker** — per-app connection-rate anomaly detection.
///
/// Flows that pass all checks are allowed; flows that fail any check are
/// dropped and logged.
final class FilterDataProvider: NEFilterDataProvider {

    // MARK: - Private Properties

    private let blocklist      = NetworkBlocklist.shared
    private let tracker        = ConnectionTracker()
    private let scamGuardian   = ScamGuardian()

    private static let logger = Logger(
        subsystem: "com.ehsanazish.nick.NickNetFilter",
        category:  "FilterDataProvider"
    )

    /// Well-known ports that are considered "normal" outbound traffic.
    private let allowlistedPorts: Set<Int> = [
        80, 443, 53, 22, 587, 465, 993, 995, 143, 110, 25, 8080, 8443
    ]

    // MARK: - NEFilterDataProvider

    override func startFilter(completionHandler: @escaping (Error?) -> Void) {
        Self.logger.info("NickNetFilter: content filter starting")
        completionHandler(nil)
    }

    override func stopFilter(with reason: NEProviderStopReason,
                             completionHandler: @escaping () -> Void) {
        Self.logger.info("NickNetFilter: content filter stopping (reason: \(reason.rawValue))")
        completionHandler()
    }

    override func handleNewFlow(_ flow: NEFilterFlow) -> NEFilterNewFlowVerdict {
        guard let socketFlow = flow as? NEFilterSocketFlow else {
            return .allow()
        }

        // Extract remote host + port.
        // remoteFlowEndpoint returns NWEndpoint (Swift enum) on macOS 15+.
        // Fall back to remoteHostname when the endpoint isn't resolved yet.
        let host: String
        let port: Int

        if let endpoint = socketFlow.remoteFlowEndpoint,
           case .hostPort(let h, let p) = endpoint {
            host = "\(h)"
            port = Int(p.rawValue)
        } else if let hostname = socketFlow.remoteHostname {
            host = hostname
            port = -1
        } else {
            return .allow()  // no destination info yet; allow and re-evaluate later
        }

        let portString = port >= 0 ? "\(port)" : "?"
        let appID      = flow.sourceAppAuditToken.map { "\($0)" } ?? "unknown"

        // ── Layer 1: Static blocklist ─────────────────────────────────────
        if blocklist.isBlocked(host: host) {
            Self.logger.warning("NickNetFilter: BLOCKED (blocklist) \(appID) → \(host):\(portString)")
            return .drop()
        }

        // ── Layer 2: Suspicious port ──────────────────────────────────────
        if port > 1024 && !allowlistedPorts.contains(port) {
            Self.logger.info("NickNetFilter: suspicious port \(port) from \(appID) → \(host)")
            // Warn but do not block — not all high-port traffic is malicious.
            // ConnectionTracker will escalate if rates are abnormal.
        }

        // ── Layer 3: ScamGuardian ─────────────────────────────────────────
        if scamGuardian.isSuspicious(host: host) {
            Self.logger.warning("NickNetFilter: BLOCKED (scam guardian) \(appID) → \(host):\(portString)")
            return .drop()
        }

        // ── Layer 4: Connection-rate tracking ─────────────────────────────
        if tracker.shouldBlock(appID: appID, remoteHost: host) {
            Self.logger.warning("NickNetFilter: BLOCKED (rate limit) \(appID) → \(host):\(portString)")
            return .drop()
        }

        return .allow()
    }
}
