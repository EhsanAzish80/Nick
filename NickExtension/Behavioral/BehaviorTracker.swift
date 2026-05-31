// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation
import os

// MARK: - BehaviorTracker

/// Records per-process event timelines and scores each process for suspicious
/// behavioural patterns (ransomware, droppers, exfiltration, fork-bombs, etc.).
///
/// All public methods are thread-safe — mutations are serialised via `NSLock`.
/// Timelines are pruned to a configurable sliding window on every `record` call.
/// Call `cleanupExited(pid:)` on `NOTIFY_EXIT` to reclaim memory.
final class BehaviorTracker {

    // MARK: - Configuration

    struct AlertThresholds {
        /// Writes/renames/deletes per second → ransomware signal
        let rapidFileOpsPerSecond: Int = 20
        /// Child processes spawned in the window → fork-bomb signal
        let maxChildProcesses: Int = 50
        /// Total file ops in the window → exfiltration signal
        let maxFileOpsBurst: Int = 100
        /// Consecutive shell-like exec depths → dropper signal
        let suspiciousShellChainDepth: Int = 3
        /// Sliding window duration
        let timelineWindowSeconds: TimeInterval = 60
    }

    // MARK: - Types

    struct ProcessTimeline {
        let pid: Int32
        let processPath: String
        let startTime: Date
        var events: [BehaviorEvent]
        var childPids: [Int32]

        mutating func prune(window: TimeInterval) {
            let cutoff = Date().addingTimeInterval(-window)
            events.removeAll { $0.timestamp < cutoff }
        }
    }

    struct BehaviorEvent {
        let timestamp: Date
        let type: BehaviorEventType
        let detail: String
    }

    enum BehaviorEventType: Equatable {
        case fileOpen, fileWrite, fileRename, fileDelete, fileCreate
        case processExec, processFork
        case networkConnect
        case memoryMap
        case persistenceModify
    }

    // MARK: - Private

    private static let logger = Logger(
        subsystem: "com.ehsanazish.nick.NickExtension",
        category: "BehaviorTracker"
    )

    private var processTimelines: [Int32: ProcessTimeline] = [:]
    private let lock = NSLock()
    private let thresholds: AlertThresholds

    // MARK: - Init

    init(thresholds: AlertThresholds = AlertThresholds()) {
        self.thresholds = thresholds
    }

    // MARK: - Public API

    /// Records a single behavioural event for a process.
    func record(pid: Int32, processPath: String, eventType: BehaviorEventType, detail: String) {
        lock.lock()
        defer { lock.unlock() }

        if processTimelines[pid] == nil {
            processTimelines[pid] = ProcessTimeline(
                pid: pid, processPath: processPath,
                startTime: Date(), events: [], childPids: []
            )
        }
        processTimelines[pid]?.events.append(
            BehaviorEvent(timestamp: Date(), type: eventType, detail: detail)
        )
        processTimelines[pid]?.prune(window: thresholds.timelineWindowSeconds)
    }

    /// Records a fork event — links the child PID to the parent's timeline.
    func recordFork(parentPid: Int32, childPid: Int32, processPath: String) {
        lock.lock()
        defer { lock.unlock() }

        if processTimelines[parentPid] == nil {
            processTimelines[parentPid] = ProcessTimeline(
                pid: parentPid, processPath: processPath,
                startTime: Date(), events: [], childPids: []
            )
        }
        processTimelines[parentPid]?.childPids.append(childPid)
        processTimelines[parentPid]?.events.append(
            BehaviorEvent(timestamp: Date(), type: .processFork, detail: "child:\(childPid)")
        )
        processTimelines[parentPid]?.prune(window: thresholds.timelineWindowSeconds)
    }

    /// Analyses a process's recorded behaviour and returns a threat score (0–1).
    func analyze(pid: Int32) -> BehaviorAnalysis {
        lock.lock()
        defer { lock.unlock() }

        guard let timeline = processTimelines[pid] else {
            return BehaviorAnalysis(pid: pid, score: 0.0, indicators: [])
        }

        var score = 0.0
        var indicators: [String] = []
        let now = Date()

        // ── Rapid file operations (ransomware) ──────────────────────────
        let fileOps = timeline.events.filter {
            switch $0.type {
            case .fileWrite, .fileRename, .fileDelete, .fileCreate: return true
            default: return false
            }
        }
        let opsLastSecond = fileOps.filter { $0.timestamp > now.addingTimeInterval(-1.0) }
        if opsLastSecond.count > thresholds.rapidFileOpsPerSecond {
            score += 0.4
            indicators.append("Rapid file ops: \(opsLastSecond.count)/sec")
        }

        // ── File operation burst (exfiltration) ─────────────────────────
        if fileOps.count > thresholds.maxFileOpsBurst {
            score += 0.3
            indicators.append("File op burst: \(fileOps.count) in window")
        }

        // ── Mass renames to a common extension (ransomware) ─────────────
        let renames = fileOps.filter { $0.type == .fileRename }
        if renames.count > 10 {
            let exts = renames.compactMap { $0.detail.components(separatedBy: ".").last }
            let grouped = Dictionary(grouping: exts, by: { $0 })
            if let (ext, matches) = grouped.max(by: { $0.value.count < $1.value.count }),
               matches.count > 5 {
                score += 0.5
                indicators.append("Mass rename to .\(ext): \(matches.count) files")
            }
        }

        // ── Fork bomb ───────────────────────────────────────────────────
        if timeline.childPids.count > thresholds.maxChildProcesses {
            score += 0.3
            indicators.append("Excessive children: \(timeline.childPids.count)")
        }

        // ── Deep shell chain (dropper) ───────────────────────────────────
        let shellExecs = timeline.events.filter { $0.type == .processExec && isShell($0.detail) }
        if shellExecs.count >= thresholds.suspiciousShellChainDepth {
            score += 0.3
            indicators.append("Deep shell chain: \(shellExecs.count) levels")
        }

        // ── Persistence modification ─────────────────────────────────────
        let persistenceOps = timeline.events.filter { $0.type == .persistenceModify }
        if !persistenceOps.isEmpty {
            score += 0.2
            let paths = persistenceOps.map(\.detail).joined(separator: ", ")
            indicators.append("Persistence modified: \(paths)")
        }

        return BehaviorAnalysis(pid: pid, score: min(score, 1.0), indicators: indicators)
    }

    /// Removes a process's timeline. Call on `NOTIFY_EXIT`.
    func cleanupExited(pid: Int32) {
        lock.lock()
        defer { lock.unlock() }
        processTimelines.removeValue(forKey: pid)
    }

    // MARK: - Helpers

    private func isShell(_ path: String) -> Bool {
        let shells: Set<String> = [
            "/bin/bash", "/bin/sh", "/bin/zsh",
            "/usr/bin/env", "/usr/bin/osascript",
            "/usr/bin/python3", "/usr/bin/perl",
        ]
        return shells.contains(path)
    }
}

// MARK: - BehaviorAnalysis

struct BehaviorAnalysis {
    let pid: Int32
    let score: Double       // 0.0 = benign  →  1.0 = definitely malicious
    let indicators: [String]

    var isSuspicious: Bool { score >= 0.5 }
    var isMalicious:  Bool { score >= 0.8 }
}
