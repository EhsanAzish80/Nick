// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation

// MARK: - ReverseShellDetector

/// Detects reverse-shell and bind-shell patterns in network connections.
///
/// A reverse shell is when a compromised machine opens an outbound connection
/// back to the attacker's host and attaches a shell's stdin/stdout to that
/// socket — giving the attacker an interactive command prompt without opening
/// any inbound firewall ports.
///
/// **Detection signals:**
/// - Shell process (`bash`, `sh`, `zsh`, …) with an established outbound TCP connection
///   on a non-standard port (not 22/80/443/8080).
/// - Interpreter (`python`, `perl`, `ruby`, `node`) with an established outbound
///   TCP connection to a non-CDN, non-Apple host (heuristic: unusual port).
/// - Any process with outbound connections on high ephemeral ports (> 1024)
///   where the process is a shell or interpreter *and* the parent is not a
///   trusted terminal.
/// - Outbound connection from a process whose binary lives in a writable temporary path.
///
/// Connections in `.listen` state are ignored — those are bind-shells (inbound) and
/// are covered by a separate inbound-listener rule in `ThreatCorrelator`.
enum ReverseShellDetector {

    // MARK: - Known-Safe Ports

    /// Ports that are common and expected for outbound traffic — not flagged.
    private static let safePorts: Set<Int> = [
        22,    // SSH
        25,    // SMTP
        53,    // DNS
        80,    // HTTP
        110,   // POP3
        143,   // IMAP
        443,   // HTTPS
        465,   // SMTPS
        587,   // SMTP submission
        636,   // LDAPS
        993,   // IMAPS
        995,   // POP3S
        3389,  // RDP
        5228,  // Google services
        8080,  // HTTP alt
        8443,  // HTTPS alt
    ]

    /// Shell and interpreter names to flag when making unexpected outbound connections.
    private static let suspiciousProcessNames: Set<String> = [
        "bash", "sh", "zsh", "csh", "tcsh", "ksh", "fish", "dash",
        "python", "python3", "ruby", "perl", "node", "nodejs",
        "expect", "tclsh", "nc", "ncat", "netcat"
    ]

    // MARK: - Public API

    /// Evaluates connections against processes to detect reverse shell patterns.
    ///
    /// Cross-references running processes with active network connections to find
    /// shell/interpreter processes with unexpected outbound TCP connections.
    ///
    /// - Parameters:
    ///   - processes: Current process snapshot.
    ///   - connections: Current network connection snapshot.
    /// - Returns: All reverse-shell signals found.
    ///
    /// - Note: The process-name trusted list is intentionally **not** applied here.
    ///   Reverse-shell signals are network-behaviour alerts; a trusted process name
    ///   making a reverse-shell connection is *more* suspicious, not less.  The
    ///   trusted list is only relevant for unsigned-binary FP reduction.
    static func signals(
        from processes: [NickProcessInfo],
        connections: [NetworkConnectionInfo]
    ) -> [ThreatSignal] {
        let pidToProcess = Dictionary(uniqueKeysWithValues: processes.map { ($0.pid, $0) })
        var results: [ThreatSignal] = []

        for conn in connections {
            // Only flag established outbound TCP connections.
            guard conn.transportProtocol == .tcp,
                  conn.state == .established,
                  let remotePort = conn.remotePort,
                  remotePort > 0,
                  conn.isOutbound
            else { continue }

            guard let proc = pidToProcess[conn.pid] else { continue }

            let procNameLower = proc.name.lowercased()
            let isSuspiciousProcess = suspiciousProcessNames.contains(procNameLower)

            // Rule 1: Shell/interpreter with outbound connection on unusual port
            if isSuspiciousProcess, !safePorts.contains(remotePort), conn.isOutbound, isHighRiskShellContext(proc) {
                let remote = "\(conn.remoteAddress ?? "?"):\(remotePort)"
                results.append(ThreatSignal(
                    source: .network,
                    severity: .high,
                    title: "Shell process with unexpected outbound connection",
                    description: "'\(proc.name)' (PID \(proc.pid)) has an established TCP connection to \(remote) on non-standard port \(remotePort). This is consistent with a reverse shell.",
                    context: ThreatSignalContext(
                        processInfo: proc,
                        metadata: [
                            "reason": "reverse_shell",
                            "detector": "ReverseShellDetector",
                            "remote": remote,
                            "remote_port": String(remotePort)
                        ]
                    )
                ))
                continue
            }

            // Rule 2: Any process with binary in temp directory making outbound connections
            if !proc.path.isEmpty, isTemporaryPath(proc.path), !safePorts.contains(remotePort), conn.isOutbound, proc.signingStatus.isSuspicious {
                let remote = "\(conn.remoteAddress ?? "?"):\(remotePort)"
                results.append(ThreatSignal(
                    source: .network,
                    severity: .high,
                    title: "Process in temp directory with outbound connection",
                    description: "'\(proc.name)' (PID \(proc.pid)) is running from a temporary path '\(proc.path)' and has an established TCP connection to \(remote).",
                    context: ThreatSignalContext(
                        processInfo: proc,
                        metadata: [
                            "reason": "temp_binary_network",
                            "detector": "ReverseShellDetector",
                            "remote": remote,
                            "path": proc.path
                        ]
                    )
                ))
            }

            // Rule 3: netcat is dual-use. Only escalate when its invocation exposes
            // an execution/listener primitive or the binary context is suspicious.
            if isNetcat(procNameLower), isHighRiskNetcatContext(proc) {
                let remote = "\(conn.remoteAddress ?? "?"):\(remotePort)"
                results.append(ThreatSignal(
                    source: .network,
                    severity: .high,
                    title: "netcat with active connection",
                    description: "'\(proc.name)' (PID \(proc.pid)) has an established TCP connection to \(remote). netcat is frequently used for reverse shells and data exfiltration.",
                    context: ThreatSignalContext(
                        processInfo: proc,
                        metadata: [
                            "reason": "reverse_shell",
                            "detector": "ReverseShellDetector",
                            "remote": remote
                        ]
                    )
                ))
            }
        }

        return results
    }

    /// Evaluates a single (process, connection) pair for reverse-shell characteristics.
    ///
    /// Used by `ThreatCorrelator` when evaluating individual signal pairs rather
    /// than a full cross-product.
    ///
    /// - Parameters:
    ///   - proc: The process owning the connection.
    ///   - connection: The network connection to evaluate.
    /// - Returns: A `ThreatSignal` if a reverse-shell pattern is detected.
    static func evaluate(
        process proc: NickProcessInfo,
        connection: NetworkConnectionInfo
    ) -> ThreatSignal? {
        guard connection.transportProtocol == .tcp,
              connection.state == .established,
              let remotePort = connection.remotePort,
              remotePort > 0
        else { return nil }

        let procNameLower = proc.name.lowercased()
        guard suspiciousProcessNames.contains(procNameLower),
              !safePorts.contains(remotePort),
              connection.isOutbound,
              isHighRiskShellContext(proc) else {
            return nil
        }

        let remote = "\(connection.remoteAddress ?? "?"):\(remotePort)"
        return ThreatSignal(
            source: .network,
            severity: .high,
            title: "Shell process with unexpected outbound connection",
            description: "'\(proc.name)' (PID \(proc.pid)) has an established TCP connection to \(remote) on non-standard port \(remotePort).",
            context: ThreatSignalContext(
                processInfo: proc,
                metadata: [
                    "reason": "reverse_shell",
                    "detector": "ReverseShellDetector",
                    "remote": remote,
                    "remote_port": String(remotePort)
                ]
            )
        )
    }

    // MARK: - Private Helpers

    private static func isHighRiskShellContext(_ process: NickProcessInfo) -> Bool {
        if isNetcat(process.name.lowercased()) { return isHighRiskNetcatContext(process) }
        guard process.signingStatus.isSuspicious || isTemporaryPath(process.path) else { return false }
        let parent = (process.parentName ?? "").lowercased()
        let expectedParents = ["terminal", "iterm", "warp", "ssh", "xcode", "code", "swift", "launchd"]
        return !expectedParents.contains { parent.contains($0) }
    }

    private static func isNetcat(_ name: String) -> Bool {
        ["nc", "ncat", "netcat"].contains(name)
    }

    private static func isHighRiskNetcatContext(_ process: NickProcessInfo) -> Bool {
        let arguments = process.arguments.map { $0.lowercased() }
        let hasExecutionPrimitive = arguments.contains("-e")
            || arguments.contains("--exec")
            || arguments.contains("--sh-exec")
            || arguments.contains("-c")
        let isListener = arguments.contains("-l") || arguments.contains("--listen")
        if hasExecutionPrimitive || isListener { return true }

        guard process.signingStatus.isSuspicious || isTemporaryPath(process.path) else { return false }
        let parent = (process.parentName ?? "").lowercased()
        let expectedParents = ["terminal", "iterm", "warp", "ssh", "xcode", "code", "make", "swift"]
        return !expectedParents.contains { parent.contains($0) }
    }

    private static func isTemporaryPath(_ path: String) -> Bool {
        let lp = path.lowercased()
        return lp.hasPrefix("/tmp/")
            || lp.hasPrefix("/var/folders/")
            || lp.hasPrefix("/private/tmp/")
            || lp.hasPrefix("/private/var/folders/")
    }
}
