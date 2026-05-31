// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation
import os

// MARK: - ProcessTree

/// Phase 6.2 — Process genealogy tracker.
///
/// Maintains a lightweight in-memory tree of every process exec'd since the
/// extension started. For each threat alert Nick can reconstruct the full
/// attack chain (root → threat) and the subtree the threat spawned.
///
/// All mutations are serialised through an `NSLock` so the class can be safely
/// called from ES event callbacks on arbitrary threads.
///
/// **Memory management:** call `pruneExited(olderThan:)` periodically
/// (e.g. every hour from `main.swift`) to discard exited, benign nodes.
final class ProcessTree: @unchecked Sendable {

    // MARK: - Types

    /// A single node in the process tree.
    struct ProcessNode: Codable, Sendable {
        let pid: Int32
        let ppid: Int32
        let path: String
        let args: [String]
        let startTime: Date
        var exitTime: Date?
        var exitCode: Int32?
        var childPids: [Int32]
        var filesAccessed: [FileAccess]
        var networkConnections: [NetworkConn]
        /// Marked `true` when a downstream detector flags this process.
        var isThreat: Bool

        struct FileAccess: Codable, Sendable {
            let path: String
            /// One of: "open", "write", "delete", "exec", "rename"
            let operation: String
            let timestamp: Date
        }

        struct NetworkConn: Codable, Sendable {
            let host: String
            let port: String
            let timestamp: Date
        }
    }

    /// Snapshot exported to the container app for visualization.
    struct Export: Codable, Sendable {
        /// Chain from the root ancestor down to the threat process.
        let attackChain: [ProcessNode]
        /// The threat process and all processes it spawned.
        let subtree: [ProcessNode]
        let exportedAt: Date
    }

    // MARK: - Private

    private var nodes: [Int32: ProcessNode] = [:]
    private let lock = NSLock()

    private static let logger = Logger(
        subsystem: "com.ehsanazish.nick",
        category: "ProcessTree"
    )

    // MARK: - Record Events

    /// Records an `exec` event. Called from `ES_EVENT_TYPE_NOTIFY_EXEC`.
    func recordExec(pid: Int32, ppid: Int32, path: String, args: [String]) {
        lock.withLock {
            let node = ProcessNode(
                pid: pid, ppid: ppid, path: path, args: args,
                startTime: Date(), exitTime: nil, exitCode: nil,
                childPids: [], filesAccessed: [], networkConnections: [],
                isThreat: false
            )
            nodes[pid] = node
            nodes[ppid]?.childPids.append(pid)
        }
    }

    /// Records a process exit. Called from `ES_EVENT_TYPE_NOTIFY_EXIT`.
    func recordExit(pid: Int32, exitCode: Int32) {
        lock.withLock {
            nodes[pid]?.exitTime = Date()
            nodes[pid]?.exitCode = exitCode
        }
    }

    /// Records a file-access event for the given process.
    func recordFileAccess(pid: Int32, path: String, operation: String) {
        lock.withLock {
            let access = ProcessNode.FileAccess(
                path: path, operation: operation, timestamp: Date()
            )
            nodes[pid]?.filesAccessed.append(access)
        }
    }

    /// Records an outbound network connection for the given process.
    func recordNetworkConnection(pid: Int32, host: String, port: String) {
        lock.withLock {
            let conn = ProcessNode.NetworkConn(host: host, port: port, timestamp: Date())
            nodes[pid]?.networkConnections.append(conn)
        }
    }

    /// Marks a process (and all its ancestors up to launchd) as part of an
    /// attack chain. Called when a threat alert is raised for `pid`.
    func markAsThreat(pid: Int32) {
        lock.withLock {
            var current = pid
            while let node = nodes[current] {
                nodes[current]?.isThreat = true
                if node.ppid <= 1 { break }
                current = node.ppid
            }
        }
    }

    // MARK: - Query

    /// Returns the chain from the root ancestor down to `pid` (inclusive).
    ///
    /// The first element is the oldest ancestor; the last is `pid` itself.
    func attackChain(pid: Int32) -> [ProcessNode] {
        lock.withLock {
            var chain: [ProcessNode] = []
            var current = pid
            while let node = nodes[current] {
                chain.append(node)
                if node.ppid <= 1 { break }
                current = node.ppid
            }
            return chain.reversed()
        }
    }

    /// Returns `pid` and all of its descendants (breadth-first).
    func subtree(pid: Int32) -> [ProcessNode] {
        lock.withLock {
            var result: [ProcessNode] = []
            var queue: [Int32] = [pid]
            while !queue.isEmpty {
                let current = queue.removeFirst()
                if let node = nodes[current] {
                    result.append(node)
                    queue.append(contentsOf: node.childPids)
                }
            }
            return result
        }
    }

    /// Builds a JSON-encodable `Export` for the threat at `pid`.
    func export(pid: Int32) -> Export {
        Export(
            attackChain: attackChain(pid: pid),
            subtree: subtree(pid: pid),
            exportedAt: Date()
        )
    }

    /// Serialises an `Export` to JSON `Data` for XPC transmission.
    func exportData(pid: Int32) -> Data? {
        let snapshot = export(pid: pid)
        return try? JSONEncoder().encode(snapshot)
    }

    // MARK: - Maintenance

    /// Removes exited, non-threat nodes older than `seconds`.
    ///
    /// Call periodically (e.g. hourly) to prevent unbounded memory growth.
    func pruneExited(olderThan seconds: TimeInterval = 3600) {
        lock.withLock {
            let cutoff = Date().addingTimeInterval(-seconds)
            let stale = nodes.filter {
                $0.value.exitTime != nil
                    && $0.value.exitTime! < cutoff
                    && !$0.value.isThreat
            }
            for pid in stale.keys {
                nodes.removeValue(forKey: pid)
            }
            if !stale.isEmpty {
                Self.logger.debug("ProcessTree: pruned \(stale.count) stale node(s)")
            }
        }
    }

    /// Total number of tracked processes.
    var count: Int {
        lock.withLock { nodes.count }
    }
}
