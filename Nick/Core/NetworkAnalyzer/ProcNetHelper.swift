// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Darwin
import Foundation
import os

// MARK: - ProcNetHelper

/// Enumerates TCP/UDP sockets for all accessible processes via `proc_pidfdinfo`.
///
/// This is a zero-subprocess replacement for the `lsof` approach used in Phase 1.
/// Eliminating the `Process()` spawn reduces per-scan overhead by ~100ms and removes
/// the file-system dependency on `/usr/sbin/lsof`.
///
/// **Coverage:** All processes visible to the current user. Privileged-process sockets
/// (root-owned, sandboxed) are silently skipped — `proc_pidfdinfo` returns an error
/// for FDs owned by processes the caller cannot introspect.
///
/// **Limitations:** UDP sockets have no "state" in the TCP sense; they are reported
/// with `state = .unknown`. IPv6 address formatting uses `inet_ntop`.
///
/// - Note: All constants (`PROC_PIDLISTFDS`, `PROC_PIDFDSOCKETINFO`, etc.) are from
///   `<sys/proc_info.h>` and have been stable since macOS 10.5. They are re-declared
///   here because the Swift Darwin overlay does not export them as top-level symbols.
enum ProcNetHelper {

    // MARK: - proc_info.h Constants

    // PROC_PIDLISTFDS = 1 (list all open file descriptors for a PID)
    private static let kPROC_PIDLISTFDS: Int32 = 1
    // PROX_FDTYPE_SOCKET = 2 (fd is a network socket)
    private static let kPROX_FDTYPE_SOCKET: UInt32 = 2
    // PROC_PIDFDSOCKETINFO = 3 (retrieve socket_fdinfo for one socket fd)
    private static let kPROC_PIDFDSOCKETINFO: Int32 = 3

    // MARK: - netinet/tcp_fsm.h Constants

    private static let kTCPS_LISTEN: Int32      = 1
    private static let kTCPS_ESTABLISHED: Int32 = 4
    private static let kTCPS_CLOSE_WAIT: Int32  = 5
    private static let kTCPS_TIME_WAIT: Int32   = 10

    // MARK: - Private State

    private static let logger = Logger(
        subsystem: "com.ehsanazish.nick",
        category: "ProcNetHelper"
    )

    // MARK: - Public API

    /// Returns all TCP/UDP sockets visible to the current process.
    ///
    /// Iterates all PIDs via `proc_listallpids`, then lists each PID's open sockets
    /// via `proc_pidfdinfo`. Sockets from processes the caller cannot introspect
    /// (insufficient privilege) are silently skipped.
    ///
    /// - Returns: Array of `NetworkConnectionInfo`, or an empty array on failure.
    static func listConnections() -> [NetworkConnectionInfo] {
        // Phase 1: collect all accessible PIDs
        let estimatedCount = proc_listallpids(nil, 0)
        guard estimatedCount > 0 else { return [] }

        // Allocate with slack — process count can change between the two calls.
        var pids = [pid_t](repeating: 0, count: Int(estimatedCount) + 32)
        let pidCount = proc_listallpids(
            &pids,
            Int32(pids.count * MemoryLayout<pid_t>.size)
        )
        guard pidCount > 0 else { return [] }

        var connections: [NetworkConnectionInfo] = []
        connections.reserveCapacity(256)

        for pid in pids.prefix(Int(pidCount)) where pid > 0 {
            connections.append(contentsOf: sockets(for: pid))
        }

        Self.logger.debug("ProcNetHelper: \(connections.count) sockets enumerated across \(pidCount) PIDs")
        return connections
    }

    // MARK: - Private Helpers

    /// Enumerates all socket file descriptors for `pid`.
    private static func sockets(for pid: pid_t) -> [NetworkConnectionInfo] {
        // Resolve process name — proc_name returns at most MAXCOMLEN (16) bytes.
        var nameBuf = [CChar](repeating: 0, count: Int(MAXCOMLEN) + 1)
        proc_name(pid, &nameBuf, UInt32(nameBuf.count))
        let processName = String(cString: nameBuf)

        // Query the total size needed for the fd list.
        let fdBufBytes = proc_pidinfo(pid, kPROC_PIDLISTFDS, 0, nil, 0)
        guard fdBufBytes > 0 else { return [] }

        let fdCount = Int(fdBufBytes) / MemoryLayout<proc_fdinfo>.size
        // Add slack: new FDs may open between the size query and the data query.
        var fdInfos = [proc_fdinfo](repeating: proc_fdinfo(), count: fdCount + 8)

        let actualBytes = proc_pidinfo(
            pid,
            kPROC_PIDLISTFDS,
            0,
            &fdInfos,
            Int32(fdCount * MemoryLayout<proc_fdinfo>.size)
        )
        guard actualBytes > 0 else { return [] }

        let actualFdCount = Int(actualBytes) / MemoryLayout<proc_fdinfo>.size
        var result: [NetworkConnectionInfo] = []

        for fdInfo in fdInfos.prefix(actualFdCount) {
            // Only interested in socket fds
            guard fdInfo.proc_fdtype == kPROX_FDTYPE_SOCKET else { continue }

            var sockInfo = socket_fdinfo()
            let got = proc_pidfdinfo(
                pid,
                fdInfo.proc_fd,
                kPROC_PIDFDSOCKETINFO,
                &sockInfo,
                Int32(MemoryLayout<socket_fdinfo>.size)
            )
            guard got == MemoryLayout<socket_fdinfo>.size else { continue }

            let family = sockInfo.psi.soi_family
            guard family == AF_INET || family == AF_INET6 else { continue }

            if let conn = parseSocketInfo(sockInfo, pid: pid, processName: processName) {
                result.append(conn)
            }
        }

        return result
    }

    /// Converts a `socket_fdinfo` into a `NetworkConnectionInfo`.
    ///
    /// The local/remote addresses are extracted from the `in_sockinfo` embedded in
    /// `soi_proto` (both `pri_tcp.tcpsi_ini` and `pri_in` for UDP start at the same
    /// memory offset — offset 0 of the union). TCP state is read from `tcpsi_state`,
    /// which immediately follows `in_sockinfo` in `tcp_sockinfo`.
    private static func parseSocketInfo(
        _ sockInfo: socket_fdinfo,
        pid: pid_t,
        processName: String
    ) -> NetworkConnectionInfo? {
        let family = sockInfo.psi.soi_family
        let sockType = sockInfo.psi.soi_type
        let proto: ConnectionProtocol = (sockType == SOCK_DGRAM) ? .udp : .tcp

        // Both tcp_sockinfo and udp_sockinfo (pri_in) embed in_sockinfo as their
        // first field, so we can treat the union as in_sockinfo for address extraction.
        let insi: in_sockinfo = withUnsafeBytes(of: sockInfo.psi.soi_proto) { raw in
            raw.load(fromByteOffset: 0, as: in_sockinfo.self)
        }

        let localPort  = Int(UInt16(bigEndian: UInt16(truncatingIfNeeded: insi.insi_lport)))
        let remotePort = Int(UInt16(bigEndian: UInt16(truncatingIfNeeded: insi.insi_fport)))

        let localAddr  = addressString(from: insi.insi_laddr, family: family)
        let remoteAddr = addressString(from: insi.insi_faddr, family: family)

        // Determine connection state for TCP sockets.
        let state: ConnectionState
        if proto == .tcp {
            let tcpState: Int32 = withUnsafeBytes(of: sockInfo.psi.soi_proto) { raw in
                raw.load(fromByteOffset: MemoryLayout<in_sockinfo>.size, as: Int32.self)
            }
            state = connectionState(fromTCPState: tcpState)
        } else {
            state = .unknown
        }

        // Ignore loopback-only sockets (both endpoints on 127.x or ::1)
        let isLoopbackOnly = isLoopback(localAddr) && (remoteAddr == nil || isLoopback(remoteAddr ?? ""))
        if isLoopbackOnly && state != .listen { return nil }

        return NetworkConnectionInfo(
            id: UUID(),
            pid: pid,
            processName: processName,
            transportProtocol: proto,
            localAddress: localAddr,
            localPort: localPort,
            remoteAddress: remotePort > 0 ? remoteAddr : nil,
            remotePort: remotePort > 0 ? remotePort : nil,
            state: state
        )
    }

    /// Converts an `insi_faddr` / `insi_laddr` union to a human-readable IP string.
    ///
    /// The union is 16 bytes (same as `in6_addr`). For IPv4, the first 4 bytes hold
    /// the `in_addr.s_addr` value. For IPv6, all 16 bytes form the `in6_addr`.
    private static func addressString<T>(
        from addrUnion: T,
        family: Int32
    ) -> String {
        if family == AF_INET {
            var s_addr: in_addr_t = 0
            withUnsafeBytes(of: addrUnion) { raw in
                s_addr = raw.load(fromByteOffset: 0, as: in_addr_t.self)
            }
            var buf = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
            inet_ntop(AF_INET, &s_addr, &buf, socklen_t(INET_ADDRSTRLEN))
            return String(cString: buf)
        } else {
            var addr6 = in6_addr()
            withUnsafeBytes(of: addrUnion) { raw in
                addr6 = raw.load(fromByteOffset: 0, as: in6_addr.self)
            }
            var buf = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
            inet_ntop(AF_INET6, &addr6, &buf, socklen_t(INET6_ADDRSTRLEN))
            return String(cString: buf)
        }
    }

    /// Maps a macOS TCP finite state machine state integer to `ConnectionState`.
    private static func connectionState(fromTCPState tcpState: Int32) -> ConnectionState {
        switch tcpState {
        case kTCPS_LISTEN:        return .listen
        case kTCPS_ESTABLISHED:   return .established
        case kTCPS_CLOSE_WAIT:    return .closeWait
        case kTCPS_TIME_WAIT:     return .timeWait
        default:                  return .unknown
        }
    }

    private static func isLoopback(_ addr: String) -> Bool {
        addr == "127.0.0.1" || addr == "::1" || addr.hasPrefix("127.")
    }
}
