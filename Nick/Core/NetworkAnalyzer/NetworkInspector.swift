// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation
import Network
import os

// MARK: - NetworkInspector

/// Scans the local network for devices, open ports, and potential
/// vulnerabilities — the "Network Inspector" feature.
///
/// **Detection strategy:**
/// 1. Parse the system ARP table (`arp -a`) to discover live hosts.
/// 2. For each discovered host, probe a curated set of common ports.
/// 3. Assess each device's risk based on open insecure services.
///
/// **Threading:**
/// All scanning is async. `discoverAndScan()` returns once all port probes
/// complete or time out. Call from a background task — do not call from the
/// main actor.
///
/// **Usage (from a SwiftUI view):**
/// ```swift
/// Task {
///     let devices = await NetworkInspector().discoverAndScan()
///     await MainActor.run { self.devices = devices }
/// }
/// ```
@Observable
@MainActor
final class NetworkInspector {

    // MARK: - Types

    struct NetworkDevice: Identifiable, Sendable {
        let id: UUID
        let ipAddress: String
        let hostname: String?
        var openPorts: [PortResult]
        var riskLevel: RiskLevel
        var issues: [String]

        enum RiskLevel: String, Sendable, Comparable {
            case safe, review, risky

            static func < (lhs: Self, rhs: Self) -> Bool {
                let order: [Self] = [.safe, .review, .risky]
                return (order.firstIndex(of: lhs) ?? 0) < (order.firstIndex(of: rhs) ?? 0)
            }
        }
    }

    struct PortResult: Sendable {
        let port: UInt16
        let service: String
        let isSecure: Bool   // HTTPS vs HTTP, SFTP vs FTP, etc.
    }

    // MARK: - Observable State

    private(set) var devices: [NetworkDevice] = []
    private(set) var isScanning: Bool = false
    private(set) var lastScanDate: Date?

    // MARK: - Private

    private static let logger = Logger(
        subsystem: "com.ehsanazish.nick",
        category: "NetworkInspector"
    )

    /// Ports to probe on each discovered device.
    private let targetPorts: [(port: UInt16, service: String, isSecure: Bool)] = [
        (22,   "SSH",        true),
        (23,   "Telnet",     false),
        (21,   "FTP",        false),
        (80,   "HTTP",       false),
        (443,  "HTTPS",      true),
        (445,  "SMB",        false),
        (548,  "AFP",        true),
        (3389, "RDP",        false),
        (5900, "VNC",        false),
        (8080, "HTTP Alt",   false),
        (8443, "HTTPS Alt",  true),
    ]

    // MARK: - Public API

    /// Discovers hosts on the local network and scans each one for open ports.
    ///
    /// Updates `devices`, `isScanning`, and `lastScanDate` on the main actor.
    func discoverAndScan() async {
        isScanning = true
        defer { isScanning = false }

        let hosts = await discoverHosts()
        Self.logger.info("NetworkInspector: discovered \(hosts.count) host(s)")

        var scannedDevices: [NetworkDevice] = []

        await withTaskGroup(of: NetworkDevice?.self) { group in
            for (ip, hostname) in hosts {
                group.addTask { [weak self] in
                    await self?.scan(ip: ip, hostname: hostname)
                }
            }
            for await result in group {
                if let device = result {
                    scannedDevices.append(device)
                }
            }
        }

        scannedDevices.sort { $0.riskLevel > $1.riskLevel }

        devices = scannedDevices
        lastScanDate = Date()
    }

    // MARK: - Private: Host Discovery

    /// Returns a list of `(ip, hostname?)` pairs from the system ARP table.
    private func discoverHosts() async -> [(String, String?)] {
        // Parse `arp -a` output — works on macOS without sandbox restrictions
        // since Nick runs with `ENABLE_APP_SANDBOX = NO`.
        let output = await runCommand("/usr/sbin/arp", args: ["-a"])
        var hosts: [(String, String?)] = []

        // ARP output format: "hostname (IP) at MAC on interface"
        // or "? (IP) at ..."
        let lines = output.components(separatedBy: "\n")
        for line in lines {
            guard let ipRange = line.range(of: #"\((\d+\.\d+\.\d+\.\d+)\)"#,
                                           options: .regularExpression) else { continue }
            let ipWithParens = String(line[ipRange])
            let ip = ipWithParens.trimmingCharacters(in: CharacterSet(charactersIn: "()"))

            // Skip link-local and broadcast
            guard !ip.hasPrefix("169.254.") && !ip.hasSuffix(".255") else { continue }

            let hostname = line.components(separatedBy: " (").first.map {
                $0 == "?" ? nil : $0
            } ?? nil

            hosts.append((ip, hostname))
        }

        return hosts
    }

    // MARK: - Private: Port Scanning

    private func scan(ip: String, hostname: String?) async -> NetworkDevice {
        var openPorts: [PortResult] = []

        await withTaskGroup(of: PortResult?.self) { group in
            for target in targetPorts {
                group.addTask {
                    let isOpen = await self.probePort(ip: ip, port: target.port)
                    return isOpen ? PortResult(port: target.port,
                                               service: target.service,
                                               isSecure: target.isSecure) : nil
                }
            }
            for await result in group {
                if let port = result { openPorts.append(port) }
            }
        }

        openPorts.sort { $0.port < $1.port }

        var device = NetworkDevice(
            id:         UUID(),
            ipAddress:  ip,
            hostname:   hostname,
            openPorts:  openPorts,
            riskLevel:  .safe,
            issues:     []
        )
        assessRisk(device: &device)
        return device
    }

    private func assessRisk(device: inout NetworkDevice) {
        var issues: [String] = []

        for port in device.openPorts {
            switch port.port {
            case 23:
                issues.append("Telnet active (port 23) — unencrypted, should be disabled immediately")
            case 21:
                issues.append("FTP active (port 21) — transmits credentials in plaintext")
            case 3389:
                issues.append("RDP exposed (port 3389) — a primary ransomware entry vector")
            case 5900:
                issues.append("VNC exposed (port 5900) — screen sharing without encryption")
            case 445:
                issues.append("SMB exposed (port 445) — targeted by EternalBlue and ransomware")
            case 80, 8080:
                issues.append("\(port.service) active (port \(port.port)) — unencrypted web interface")
            default:
                if !port.isSecure {
                    issues.append("\(port.service) (port \(port.port)) — unencrypted service")
                }
            }
        }

        device.issues = issues
        let riskWhenNotSafe: NetworkDevice.RiskLevel = issues.count >= 2 ? .risky : .review
        device.riskLevel = issues.isEmpty ? .safe : riskWhenNotSafe
    }

    // MARK: - Private: TCP Probe

    /// Attempts a TCP connection to `ip:port` with a 2-second timeout.
    /// Returns `true` if the port is open (connection reached `.ready`).
    private func probePort(ip: String, port: UInt16) async -> Bool {
        guard let nwPort = NWEndpoint.Port(rawValue: port) else { return false }
        let connection = NWConnection(
            host:  NWEndpoint.Host(ip),
            port:  nwPort,
            using: .tcp
        )

        return await withCheckedContinuation { continuation in
            let resumed = OSAllocatedUnfairLock(initialState: false)

            // Nested function rather than a closure so the withLock call inside
            // does not add a third level of closure nesting.
            @Sendable func finish(_ result: Bool) {
                let shouldResume = resumed.withLock { alreadyResumed -> Bool in
                    guard !alreadyResumed else { return false }
                    alreadyResumed = true
                    return true
                }
                guard shouldResume else { return }
                connection.cancel()
                continuation.resume(returning: result)
            }

            connection.stateUpdateHandler = { state in
                switch state {
                case .ready:              finish(true)
                case .failed, .cancelled: finish(false)
                default: break
                }
            }
            connection.start(queue: .global(qos: .utility))
            DispatchQueue.global().asyncAfter(deadline: .now() + 2) { finish(false) }
        }
    }

    // MARK: - Private: Shell Helpers

    private func runCommand(_ path: String, args: [String]) async -> String {
        await withCheckedContinuation { continuation in
            DispatchQueue.global(qos: .utility).async {
                let process = Process()
                process.executableURL = URL(fileURLWithPath: path)
                process.arguments = args
                let pipe = Pipe()
                process.standardOutput = pipe
                process.standardError = Pipe()
                do {
                    try process.run()
                    process.waitUntilExit()
                    let data = pipe.fileHandleForReading.readDataToEndOfFile()
                    continuation.resume(returning: String(data: data, encoding: .utf8) ?? "")
                } catch {
                    continuation.resume(returning: "")
                }
            }
        }
    }
}
