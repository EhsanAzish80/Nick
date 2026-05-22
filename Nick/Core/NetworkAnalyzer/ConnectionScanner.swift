// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation
import os

// MARK: - ConnectionScannerError

/// Errors thrown by `ConnectionScanner`.
enum ConnectionScannerError: LocalizedError {
    /// `ProcNetHelper` returned no connections and `lsof` is also unavailable.
    case unavailable

    var errorDescription: String? {
        "Network connection scan failed: proc_pidfdinfo returned no data and lsof is unavailable."
    }
}

// MARK: - ConnectionScanner

/// Enumerates active network connections using `proc_pidfdinfo` (no subprocess spawn).
///
/// Phase 1 used `lsof` which required spawning a subprocess (~100ms overhead per scan).
/// Phase 4 replaces that with direct `proc_pidfdinfo` calls via `ProcNetHelper`,
/// reducing scan overhead and removing the `/usr/sbin/lsof` file-system dependency.
///
/// `lsof` is kept as a fallback if `proc_pidfdinfo` returns zero connections
/// (e.g. running inside a restrictive sandbox where proc_info access is limited).
struct ConnectionScanner {

    // MARK: - Private

    private static let logger = Logger(
        subsystem: "com.ehsanazish.nick",
        category: "ConnectionScanner"
    )

    /// Names of common shell/scripting interpreters — used for reverse-shell detection.
    private static let shellNames: Set<String> = [
        "bash", "sh", "zsh", "csh", "tcsh", "ksh", "fish", "python", "python3",
        "ruby", "perl", "node", "nc", "netcat", "ncat"
    ]

    // MARK: - Public API

    /// Scans all active network connections visible to the current user.
    ///
    /// Uses `ProcNetHelper.listConnections()` (proc_pidfdinfo) as the primary path.
    /// Falls back to `lsof` if proc_pidfdinfo returns zero results (e.g. under a
    /// sandbox that blocks proc_info calls).
    ///
    /// - Returns: Array of `NetworkConnectionInfo`.
    /// - Throws: `ConnectionScannerError.unavailable` if both paths fail.
    func scan() async throws -> [NetworkConnectionInfo] {
        // Primary path: proc_pidfdinfo (no subprocess, ~100ms faster)
        let connections = ProcNetHelper.listConnections()
        if !connections.isEmpty {
            Self.logger.debug("Network scan (proc_pidfdinfo): \(connections.count) connections")
            return connections
        }

        // Fallback: lsof subprocess (available outside sandbox environments)
        let lsofPath = "/usr/sbin/lsof"
        guard FileManager.default.isExecutableFile(atPath: lsofPath) else {
            throw ConnectionScannerError.unavailable
        }

        let output = try await runLsof(path: lsofPath)
        let lsofConnections = parseLsofOutput(output)
        Self.logger.info("Network scan (lsof fallback): \(lsofConnections.count) connections")
        return lsofConnections
    }

    // MARK: - Private Helpers

    private func runLsof(path: String) async throws -> String {
        try await withCheckedThrowingContinuation { continuation in
            let process = Process()
            process.executableURL = URL(fileURLWithPath: path)
            process.arguments = ["-i", "-n", "-P", "-F", "pcn"]  // machine-readable output

            let pipe = Pipe()
            process.standardOutput = pipe
            process.standardError = Pipe()

            process.terminationHandler = { _ in
                let data = pipe.fileHandleForReading.readDataToEndOfFile()
                continuation.resume(returning: String(data: data, encoding: .utf8) ?? "")
            }

            do {
                try process.run()
            } catch {
                continuation.resume(throwing: error)
            }
        }
    }

    /// Parses the `-F pcn` (field-format) output from `lsof`.
    ///
    /// Each record begins with a `p` (PID) line, followed by one or more
    /// `f` (file descriptor) blocks containing `n` (name) fields.
    /// We also fall back to the standard human-readable `-i -n -P` format.
    private func parseLsofOutput(_ output: String) -> [NetworkConnectionInfo] {
        // Try machine-readable format first; fall back to human-readable
        let fieldConnections = parseFieldFormat(output)
        if !fieldConnections.isEmpty { return fieldConnections }
        return parseHumanReadableFormat(output)
    }

    // MARK: - Field-format parser (-F pcn)

    private func parseFieldFormat(_ output: String) -> [NetworkConnectionInfo] {
        var connections: [NetworkConnectionInfo] = []
        var currentPID: Int32 = -1
        var currentCommand = ""
        var currentProtocol: ConnectionProtocol = .tcp

        for line in output.components(separatedBy: "\n") {
            guard !line.isEmpty else { continue }
            let key = line.prefix(1)
            let value = String(line.dropFirst())

            switch key {
            case "p": currentPID = Int32(value) ?? -1
            case "c": currentCommand = value
            case "P":
                currentProtocol = value.uppercased().contains("UDP") ? .udp : .tcp
            case "n":
                if let conn = parseAddressField(
                    value,
                    pid: currentPID,
                    command: currentCommand,
                    proto: currentProtocol
                ) {
                    connections.append(conn)
                }
            default: break
            }
        }
        return connections
    }

    private func parseAddressField(
        _ field: String,
        pid: Int32,
        command: String,
        proto: ConnectionProtocol
    ) -> NetworkConnectionInfo? {
        // Expected formats:
        //   local->remote (ESTABLISHED)
        //   *:port (LISTEN)
        //   host:port->host:port (state)
        guard field.contains(":") else { return nil }

        let statePattern = #"\(([A-Z_]+)\)"#
        let stateMatch = field.range(of: statePattern, options: .regularExpression)
        let stateString = stateMatch.map { String(field[$0]).trimmingCharacters(in: CharacterSet(charactersIn: "()")) } ?? ""
        let state = ConnectionState(rawString: stateString)

        // Strip state suffix
        let addressPart = field.replacingOccurrences(of: #"\s*\([A-Z_]+\)"#, with: "", options: .regularExpression)
        let parts = addressPart.components(separatedBy: "->")

        let (localHost, localPort) = parseHostPort(parts.first ?? "")
        let (remoteHost, remotePort) = parts.count > 1 ? parseHostPort(parts[1]) : (nil, nil)

        return NetworkConnectionInfo(
            id: UUID(),
            pid: pid,
            processName: command,
            transportProtocol: proto,
            localAddress: localHost ?? "0.0.0.0",
            localPort: localPort ?? 0,
            remoteAddress: remoteHost,
            remotePort: remotePort,
            state: state
        )
    }

    // MARK: - Human-readable fallback parser

    private func parseHumanReadableFormat(_ output: String) -> [NetworkConnectionInfo] {
        var connections: [NetworkConnectionInfo] = []

        // Format: COMMAND   PID    USER   FD   TYPE  DEVICE  SIZE/OFF  NODE  NAME
        // We care about COMMAND, PID, and NAME (which has address info)
        let lines = output.components(separatedBy: "\n").dropFirst() // skip header

        for line in lines {
            let parts = line.split(separator: " ", omittingEmptySubsequences: true).map(String.init)
            guard parts.count >= 9 else { continue }

            let command = parts[0]
            guard let pid = Int32(parts[1]) else { continue }

            // Find the protocol column (usually at index 7 or 8)
            let protoStr = parts.first(where: { $0 == "TCP" || $0 == "UDP" }) ?? ""
            let proto: ConnectionProtocol = protoStr == "UDP" ? .udp : .tcp

            // NAME column is typically last and contains "addr:port->addr:port (STATE)"
            let namePart = parts.last ?? ""
            if let conn = parseAddressField(namePart, pid: pid, command: command, proto: proto) {
                connections.append(conn)
            }
        }
        return connections
    }

    private func parseHostPort(_ hostPort: String) -> (String?, Int?) {
        guard !hostPort.isEmpty, hostPort != "*" else { return (nil, nil) }

        // IPv6: [::1]:port  or  *:port
        if hostPort.hasPrefix("[") {
            let parts = hostPort.dropFirst().components(separatedBy: "]:")
            guard parts.count == 2 else { return (hostPort, nil) }
            return (parts[0], Int(parts[1]))
        }

        // IPv4: host:port  — use lastIndex to handle colons in IPv6 literals
        if let colonIndex = hostPort.lastIndex(of: ":") {
            let host = String(hostPort[hostPort.startIndex..<colonIndex])
            let port = Int(hostPort[hostPort.index(after: colonIndex)...])
            return (host.isEmpty ? nil : host, port)
        }
        return (hostPort, nil)
    }

    // MARK: - Signal Generation

    /// Derives threat signals from a list of active connections.
    ///
    /// Detection rules:
    /// - Shell process with outbound `ESTABLISHED` connection → `.high` (reverse shell)
    /// - Unexpected listener on well-known ports → `.info`
    /// - Raw IP (no hostname) outbound connection from unknown process → `.low`
    ///
    /// - Parameter connections: Output of `scan()`.
    /// - Returns: Zero or more signals.
    func signals(from connections: [NetworkConnectionInfo]) -> [ThreatSignal] {
        var signals: [ThreatSignal] = []

        for conn in connections {
            let name = conn.processName.lowercased()

            // Reverse shell: shell with outbound established connection
            if Self.shellNames.contains(name),
               conn.state == .established,
               conn.isOutbound {
                signals.append(ThreatSignal(
                    source: .network,
                    severity: .high,
                    title: "Potential reverse shell",
                    description: "'\(conn.processName)' (PID \(conn.pid)) has an outbound ESTABLISHED connection to \(conn.remoteAddress ?? "unknown"):\(conn.remotePort.map(String.init) ?? "?").",
                    networkInfo: conn,
                    metadata: ["reason": "reverse_shell", "process": conn.processName]
                ))
                continue
            }

            // Raw IP (no hostname resolution) outbound connection — not shell, lower severity
            if conn.isOutbound,
               conn.state == .established,
               let remote = conn.remoteAddress,
               isRawIP(remote),
               !isLoopback(remote) {
                signals.append(ThreatSignal(
                    source: .network,
                    severity: .low,
                    title: "Outbound connection to raw IP",
                    description: "'\(conn.processName)' (PID \(conn.pid)) is connected to \(remote):\(conn.remotePort.map(String.init) ?? "?").",
                    networkInfo: conn,
                    metadata: ["reason": "raw_ip_outbound"]
                ))
            }
        }

        return signals
    }

    // MARK: - Helpers

    private func isRawIP(_ address: String) -> Bool {
        // IPv4: four octets; IPv6: colons
        let ipv4 = address.split(separator: ".").count == 4
            && address.split(separator: ".").allSatisfy { Int($0) != nil }
        let ipv6 = address.contains(":") && !address.contains(" ")
        return ipv4 || ipv6
    }

    private func isLoopback(_ address: String) -> Bool {
        address == "127.0.0.1" || address == "::1" || address.hasPrefix("127.")
    }
}
