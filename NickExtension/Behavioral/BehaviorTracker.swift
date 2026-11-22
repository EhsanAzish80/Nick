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
        /// Hard memory bound for a single busy process. This remains well
        /// above every behavioural threshold used below.
        let maxEventsPerProcess: Int = 512
        let maxChildrenPerProcess: Int = 256
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
        /// Rename source path; `detail` holds the destination.
        var source: String? = nil
        /// False for a recent same-process/process-group write-then-swap.
        var countsTowardRenameBurst: Bool = true
        /// A recent temp file replaced a pre-existing non-encrypted file with
        /// high-entropy content that has no recognized file magic.
        var encryptedReplacement: Bool = false
        /// Computed once at ingestion, never reclassified for every window scan.
        var introducedRenameExtension: String? = nil
    }

    private struct RecentCreation {
        let pid: Int32
        let processGroupID: Int32
        let timestamp: Date
    }

    struct RenameReplacementEvidence: Equatable {
        let sourceIsHighEntropyWithoutKnownMagic: Bool
        let destinationExisted: Bool
        let destinationWasHighEntropyWithoutKnownMagic: Bool

        var indicatesEncryptedReplacement: Bool {
            sourceIsHighEntropyWithoutKnownMagic
                && destinationExisted
                && !destinationWasHighEntropyWithoutKnownMagic
        }

        init(sourceData: Data?, destinationData: Data?, destinationExisted: Bool) {
            self.sourceIsHighEntropyWithoutKnownMagic = Self.isHighEntropyWithoutKnownMagic(sourceData)
            self.destinationExisted = destinationExisted
            self.destinationWasHighEntropyWithoutKnownMagic = Self.isHighEntropyWithoutKnownMagic(destinationData)
        }

        init(
            sourceIsHighEntropyWithoutKnownMagic: Bool,
            destinationExisted: Bool,
            destinationWasHighEntropyWithoutKnownMagic: Bool
        ) {
            self.sourceIsHighEntropyWithoutKnownMagic = sourceIsHighEntropyWithoutKnownMagic
            self.destinationExisted = destinationExisted
            self.destinationWasHighEntropyWithoutKnownMagic = destinationWasHighEntropyWithoutKnownMagic
        }

        private static func isHighEntropyWithoutKnownMagic(_ data: Data?) -> Bool {
            guard let data, !data.isEmpty, !hasKnownFileMagic(data) else { return false }
            var frequencies = [Int](repeating: 0, count: 256)
            for byte in data { frequencies[Int(byte)] += 1 }
            let length = Double(data.count)
            let entropy = frequencies.reduce(0.0) { result, count in
                guard count > 0 else { return result }
                let probability = Double(count) / length
                return result - probability * log2(probability)
            }
            return entropy >= 7.5
        }

        private static func hasKnownFileMagic(_ data: Data) -> Bool {
            let magics: [[UInt8]] = [
                [0x25, 0x50, 0x44, 0x46], [0x50, 0x4B, 0x03, 0x04],
                [0x89, 0x50, 0x4E, 0x47], [0xFF, 0xD8, 0xFF],
                [0x47, 0x49, 0x46, 0x38], [0x7F, 0x45, 0x4C, 0x46],
                [0xCF, 0xFA, 0xED, 0xFE], [0xCA, 0xFE, 0xBA, 0xBE],
            ]
            return magics.contains { magic in
                data.count >= magic.count && data.prefix(magic.count).elementsEqual(magic)
            }
        }
    }

    /// Result of the extension-change analysis for one process.
    struct ExtensionChangeBurst: Equatable {
        let newExtension: String
        let fileCount: Int
        let directoryCount: Int
    }

    /// Stable scope for a rename burst. Short-lived utilities such as `mv`
    /// receive a fresh PID for every file, so ransomware evidence must follow
    /// the responsible lineage and destination directory instead of the leaf
    /// process.
    struct RenameBurstScope: Hashable {
        let lineage: String
        let destinationDirectory: String
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
    private var scopedRenameEvents: [RenameBurstScope: [BehaviorEvent]] = [:]
    private var recentCreations = RecentCreationIndex<RecentCreation>()
    private var renameIntents: [String: RenameReplacementEvidence] = [:]
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
        if let count = processTimelines[pid]?.events.count,
           count > thresholds.maxEventsPerProcess {
            processTimelines[pid]?.events.removeFirst(
                count - thresholds.maxEventsPerProcess
            )
        }
    }

    /// Records a completed rename with both paths so extension changes can be
    /// attributed to the renaming process.
    func recordCreate(
        pid: Int32,
        processGroupID: Int32,
        processPath: String,
        path: String,
        at timestamp: Date = Date()
    ) {
        lock.lock()
        defer { lock.unlock() }
        recentCreations.update(path: path, value: RecentCreation(
            pid: pid, processGroupID: processGroupID, timestamp: timestamp
        ), timestamp: timestamp)
        pruneRecentCreations(now: timestamp)
    }

    func recordRename(
        pid: Int32,
        processGroupID: Int32,
        processPath: String,
        source: String,
        destination: String,
        burstScope: RenameBurstScope? = nil,
        at timestamp: Date = Date(),
        replacementEvidence: RenameReplacementEvidence? = nil
    ) {
        lock.lock()
        defer { lock.unlock() }

        if processTimelines[pid] == nil {
            processTimelines[pid] = ProcessTimeline(
                pid: pid, processPath: processPath,
                startTime: Date(), events: [], childPids: []
            )
        }
        pruneRecentCreations(now: timestamp)
        let creation = recentCreations[source]
        let isAtomicSwap = creation.map {
            timestamp.timeIntervalSince($0.timestamp) <= 10
                && ($0.pid == pid || $0.processGroupID == processGroupID)
        } ?? false
        // A freshly written temporary renamed to `document.ext.locked` is the
        // common write-then-swap ransomware shape. It must not inherit the
        // ordinary atomic-save exemption merely because the temporary was
        // created by the same process. Conversely, an exact one-suffix
        // finalization (`archive.tar.zst.tmp` -> `archive.tar.zst`) is a normal
        // atomic save even though the destination still has multiple suffixes.
        // Content evidence always overrides this exemption.
        let destinationStem = (destination as NSString).deletingPathExtension
        let isExactTemporaryFinalization = isAtomicSwap
            && ESCallbackPath.normalize((source as NSString).deletingPathExtension)
                == ESCallbackPath.normalize(destination)
        let appendsExtensionToNamedFile = !(destination as NSString).pathExtension.isEmpty
            && !(destinationStem as NSString).pathExtension.isEmpty
            && !isExactTemporaryFinalization
        let event = BehaviorEvent(
            timestamp: timestamp,
            type: .fileRename,
            detail: destination,
            source: source,
            countsTowardRenameBurst: !isAtomicSwap || appendsExtensionToNamedFile
                || replacementEvidence?.indicatesEncryptedReplacement == true,
            encryptedReplacement: replacementEvidence?.indicatesEncryptedReplacement == true,
            introducedRenameExtension: Self.introducedExtension(source: source, destination: destination)
        )
        processTimelines[pid]?.events.append(event)
        if let burstScope {
            var events = scopedRenameEvents[burstScope, default: []]
            events.append(event)
            let cutoff = timestamp.addingTimeInterval(-thresholds.timelineWindowSeconds)
            events.removeAll { $0.timestamp < cutoff }
            if events.count > thresholds.maxEventsPerProcess {
                events.removeFirst(events.count - thresholds.maxEventsPerProcess)
            }
            scopedRenameEvents[burstScope] = events
            if scopedRenameEvents.count > thresholds.maxEventsPerProcess {
                scopedRenameEvents = scopedRenameEvents.filter {
                    $0.value.last.map { $0.timestamp >= cutoff } ?? false
                }
            }
        }
        recentCreations.removeValue(forKey: source)
        processTimelines[pid]?.prune(window: thresholds.timelineWindowSeconds)
        if let count = processTimelines[pid]?.events.count,
           count > thresholds.maxEventsPerProcess {
            processTimelines[pid]?.events.removeFirst(count - thresholds.maxEventsPerProcess)
        }
    }

    func recordRenameIntent(
        pid: Int32,
        source: String,
        destination: String,
        evidence: RenameReplacementEvidence
    ) {
        lock.lock()
        defer { lock.unlock() }
        renameIntents[Self.renameIntentKey(pid: pid, source: source, destination: destination)] = evidence
        if renameIntents.count > thresholds.maxEventsPerProcess * 2 {
            renameIntents.removeAll(keepingCapacity: true)
        }
    }

    func wasRecentlyCreated(
        path: String,
        by pid: Int32,
        processGroupID: Int32,
        at timestamp: Date = Date()
    ) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard let creation = recentCreations[path] else { return false }
        return timestamp.timeIntervalSince(creation.timestamp) <= 10
            && (creation.pid == pid || creation.processGroupID == processGroupID)
    }

    func consumeRenameIntent(
        pid: Int32,
        source: String,
        destination: String
    ) -> RenameReplacementEvidence? {
        lock.lock()
        defer { lock.unlock() }
        return renameIntents.removeValue(
            forKey: Self.renameIntentKey(pid: pid, source: source, destination: destination)
        )
    }

    /// The most common *new* extension a process has given files by renaming
    /// within `window` seconds (`a.docx → a.docx.xyz` or `a.docx → a.xyz`).
    ///
    /// Atomic saves (`x.json.tmp → x.json`), download completion, and common
    /// data formats are excluded: they rename many files but never to a new,
    /// uncommon extension.
    func extensionChangeBurst(
        pid: Int32,
        burstScope: RenameBurstScope? = nil,
        window: TimeInterval = 10
    ) -> ExtensionChangeBurst? {
        lock.lock()
        defer { lock.unlock() }
        let events: [BehaviorEvent]
        if let burstScope {
            events = scopedRenameEvents[burstScope] ?? []
        } else {
            guard let timeline = processTimelines[pid] else { return nil }
            events = timeline.events
        }
        let cutoff = Date().addingTimeInterval(-window)
        var files: [String: Set<String>] = [:]
        var directories: [String: Set<String>] = [:]
        for event in events where event.type == .fileRename
            && event.timestamp >= cutoff && event.countsTowardRenameBurst {
            guard let newExtension = event.encryptedReplacement
                    ? "encrypted replacement"
                    : event.introducedRenameExtension
            else { continue }
            files[newExtension, default: []].insert(event.detail)
            directories[newExtension, default: []].insert((event.detail as NSString).deletingLastPathComponent)
        }
        guard let (ext, paths) = files.max(by: { $0.value.count < $1.value.count }) else { return nil }
        return ExtensionChangeBurst(
            newExtension: ext,
            fileCount: paths.count,
            directoryCount: directories[ext]?.count ?? 0
        )
    }

    static func introducedExtension(source: String, destination: String) -> String? {
        RansomwareRenamePolicy.introducedExtension(source: source, destination: destination)
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
        if let count = processTimelines[parentPid]?.childPids.count,
           count > thresholds.maxChildrenPerProcess {
            processTimelines[parentPid]?.childPids.removeFirst(
                count - thresholds.maxChildrenPerProcess
            )
        }
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

        // ── Mass extension change (ransomware) ──────────────────────────
        // Counts only renames that introduce a new, uncommon extension, so
        // atomic saves and download completion do not contribute.
        let cutoff = now.addingTimeInterval(-10)
        var introduced: [String: Int] = [:]
        for event in fileOps where event.type == .fileRename
            && event.timestamp >= cutoff && event.countsTowardRenameBurst {
            if event.encryptedReplacement {
                introduced["encrypted replacement", default: 0] += 1
            } else if let ext = event.introducedRenameExtension {
                introduced[ext, default: 0] += 1
            }
        }
        if let (ext, count) = introduced.max(by: { $0.value < $1.value }), count > 5 {
            score += 0.5
            indicators.append("Mass rename to .\(ext): \(count) files")
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
        recentCreations.removeAll { $0.pid == pid }
        let prefix = "\(pid)\u{0}"
        renameIntents = renameIntents.filter { !$0.key.hasPrefix(prefix) }
    }

    private func pruneRecentCreations(now: Date) {
        recentCreations.prune(before: now.addingTimeInterval(-thresholds.timelineWindowSeconds),
                              capacity: thresholds.maxEventsPerProcess * 8)
    }

    private static func renameIntentKey(pid: Int32, source: String, destination: String) -> String {
        "\(pid)\u{0}\(source)\u{0}\(destination)"
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


/// Timestamp-ordered indexed min-heap for creation evidence. Callers hold the
/// BehaviorTracker lock. Every path owns exactly one slot: refreshes repair that
/// slot in place, so no stale generations or unbounded tombstones accumulate.
/// Timestamp ties use path order; the previous dictionary sort did not specify
/// which equally old path to evict. Maintenance is O(log n) per removed/updated
/// record and O(n) storage, with no whole-map rebuild/sort on create or rename.
struct RecentCreationIndex<Value> {
    private struct Entry { let path: String; var value: Value; var timestamp: Date }
    private var heap: [Entry] = []
    private var positions: [String: Int] = [:]
    var count: Int { heap.count }
    subscript(path: String) -> Value? { positions[path].map { heap[$0].value } }

    mutating func update(path: String, value: Value, timestamp: Date) {
        if let i = positions[path] {
            heap[i].value = value; heap[i].timestamp = timestamp
            repair(i)
        } else {
            positions[path] = heap.count
            heap.append(Entry(path: path, value: value, timestamp: timestamp))
            siftUp(heap.count - 1)
        }
    }
    @discardableResult mutating func removeValue(forKey path: String) -> Value? {
        guard let i = positions[path] else { return nil }
        let value = heap[i].value
        positions.removeValue(forKey: path)
        let last = heap.removeLast()
        if i < heap.count {
            heap[i] = last; positions[last.path] = i; repair(i)
        }
        return value
    }
    mutating func prune(before cutoff: Date, capacity: Int) {
        precondition(capacity >= 0)
        while let first = heap.first, first.timestamp < cutoff {
            removeValue(forKey: first.path)
        }
        while heap.count > capacity, let first = heap.first {
            removeValue(forKey: first.path)
        }
    }
    /// Exit cleanup only; not called by per-create/rename maintenance.
    mutating func removeAll(where predicate: (Value) -> Bool) {
        let paths = heap.compactMap { predicate($0.value) ? $0.path : nil }
        for path in paths { removeValue(forKey: path) }
    }
    private func less(_ a: Int, _ b: Int) -> Bool {
        heap[a].timestamp == heap[b].timestamp
            ? heap[a].path < heap[b].path : heap[a].timestamp < heap[b].timestamp
    }
    private mutating func exchange(_ a: Int, _ b: Int) {
        heap.swapAt(a, b)
        positions[heap[a].path] = a; positions[heap[b].path] = b
    }
    private mutating func repair(_ i: Int) {
        if i > 0 && less(i, (i - 1) / 2) { siftUp(i) } else { siftDown(i) }
    }
    private mutating func siftUp(_ index: Int) {
        var i = index
        while i > 0 {
            let parent = (i - 1) / 2
            guard less(i, parent) else { break }
            exchange(i, parent); i = parent
        }
    }
    private mutating func siftDown(_ index: Int) {
        var i = index
        while i * 2 + 1 < heap.count {
            let left = i * 2 + 1, right = left + 1
            let child = right < heap.count && less(right, left) ? right : left
            guard less(child, i) else { break }
            exchange(i, child); i = child
        }
    }
}
