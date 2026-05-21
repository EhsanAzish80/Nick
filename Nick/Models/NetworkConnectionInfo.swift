// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation

// MARK: - ConnectionProtocol

/// Transport-layer protocol for a network connection.
///
/// - Note: Named `ConnectionProtocol` (not `Protocol`) to avoid collision
///         with Swift's built-in `protocol` keyword.
enum ConnectionProtocol: String, Codable, Sendable, CaseIterable {
    case tcp = "TCP"
    case udp = "UDP"
}

// MARK: - ConnectionState

/// TCP connection state as reported by the kernel or `lsof`.
///
/// Maps to standard TCP FSM states. `.unknown` covers any state string
/// not in this enumeration (defensive parsing of `lsof` output).
enum ConnectionState: String, Codable, Sendable, CaseIterable {
    case established  = "ESTABLISHED"
    case listen       = "LISTEN"
    case timeWait     = "TIME_WAIT"
    case closeWait    = "CLOSE_WAIT"
    case closed       = "CLOSED"
    case synSent      = "SYN_SENT"
    case synReceived  = "SYN_RECEIVED"
    case finWait1     = "FIN_WAIT_1"
    case finWait2     = "FIN_WAIT_2"
    case lastAck      = "LAST_ACK"
    case closing      = "CLOSING"
    case unknown      = "UNKNOWN"

    // MARK: - Helpers

    /// Whether this state represents an active, bidirectional data exchange.
    var isActive: Bool { self == .established }

    /// Whether this process is accepting inbound connections on this socket.
    var isListening: Bool { self == .listen }

    /// Initialise from an arbitrary string, falling back to `.unknown`.
    init(rawString: String) {
        self = ConnectionState(rawValue: rawString.uppercased()) ?? .unknown
    }
}

// MARK: - NetworkConnectionInfo

/// A single network connection captured by `ConnectionScanner`.
///
/// Provides a unified view of one socket: its endpoints, protocol, state,
/// and the process that owns the socket. Used by `NetworkAnalyzer` to
/// detect reverse shells, unexpected listeners, and suspicious connections.
struct NetworkConnectionInfo: Sendable, Codable, Identifiable, Equatable {

    // MARK: - Properties

    /// Stable identifier for this connection record within a scan session.
    let id: UUID

    /// PID of the process owning this socket. `-1` if unresolvable.
    let pid: Int32

    /// Short process name owning this socket. Empty string if unresolvable.
    let processName: String

    /// Transport-layer protocol of this socket.
    ///
    /// - Note: Property is named `transportProtocol` because `protocol`
    ///         is a reserved Swift keyword.
    let transportProtocol: ConnectionProtocol

    /// Local IP address string (IPv4 dotted-decimal or IPv6).
    let localAddress: String

    /// Local port number.
    let localPort: Int

    /// Remote IP address string, or `nil` for listening sockets.
    let remoteAddress: String?

    /// Remote port number, or `nil` for listening sockets.
    let remotePort: Int?

    /// Current TCP state; always `.unknown` for UDP.
    let state: ConnectionState

    // MARK: - Helpers

    /// Whether this connection targets a remote host (not just a loopback listener).
    var isOutbound: Bool {
        guard let remote = remoteAddress else { return false }
        return remote != "127.0.0.1" && remote != "::1" && remote != "*"
    }

    /// Whether the process name is a shell interpreter.
    var isShellProcess: Bool {
        let shells = ["bash", "zsh", "sh", "fish", "python3", "python", "ruby", "perl", "nc", "ncat", "netcat"]
        return shells.contains(processName.lowercased())
    }
}
