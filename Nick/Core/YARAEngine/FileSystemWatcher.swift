// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation
import CoreServices
import os

// MARK: - FileSystemWatcher

/// Monitors a set of directories for file-creation events using FSEvents and
/// queues newly created executables for YARA scanning.
///
/// `FileSystemWatcher` is the bridge between the macOS FSEvents API and the
/// `YARAEngine`. When the OS notifies us that a file was created or modified in
/// a monitored directory, this class checks whether the file is executable and,
/// if so, hands it to `YARAEngine` for asynchronous scanning.
///
/// On a match, a `ThreatSignal` is emitted via the `onThreatSignal` closure so
/// the `ThreatCorrelator` can act on it.
///
/// - Note: FSEvents callbacks arrive on a private serial dispatch queue.
///         All work done in the callback is brief (isExecutable check + queue
///         work item). Scanning is always offloaded to a detached async task.
///
/// - Important: Start monitoring with `startWatching()`. Stop with `stopWatching()`.
///              The watcher does not retain itself — the caller must hold a reference.
final class FileSystemWatcher: @unchecked Sendable {

    // MARK: - Configuration

    /// Directories monitored for new executable files.
    static let defaultMonitoredDirectories: [String] = [
        "/usr/local/bin",
        NSString("~/Desktop").expandingTildeInPath,
        NSString("~/Downloads").expandingTildeInPath,
        NSString("~/.local/bin").expandingTildeInPath,
        NSString("~/.ssh").expandingTildeInPath,              // SSH authorized_keys
        "/etc",                                                // /etc/zshrc, /etc/zprofile, …
    ]

    /// Seconds of latency passed to FSEvents. Lower = faster detection but more CPU.
    private static let fsEventsLatency: CFTimeInterval = 2.0

    // MARK: - Private State

    private let directories: [String]
    private let yaraEngine: YARAEngine
    private let onThreatSignal: (ThreatSignal) -> Void

    private var eventStream: FSEventStreamRef?
    private let callbackQueue = DispatchQueue(
        label: "com.ehsanazish.nick.fsevents",
        qos: .utility
    )
    private let lock = NSLock()
    private var scansInFlight: Set<String> = []
    private var pendingScans = BoundedPathQueue(capacity: 1_024)
    private(set) var droppedEventCount = 0
    /// Prevent an installer or build system from queuing thousands of scans at once.
    private static let maxConcurrentScans = 8
    /// Interactive real-time coverage is for downloaded executables. Larger files
    /// remain covered by explicit/deep scans without causing an idle CPU spike.
    private static let maxRealtimeFileSize: UInt64 = 100 * 1_024 * 1_024

    private static let log = Logger(
        subsystem: "com.ehsanazish.nick",
        category: "FileSystemWatcher"
    )

    // MARK: - Init

    /// Creates a `FileSystemWatcher`.
    ///
    /// - Parameters:
    ///   - directories: Paths to watch. Defaults to `defaultMonitoredDirectories`.
    ///   - yaraEngine: The compiled-rule engine to use for scanning.
    ///   - onThreatSignal: Called on the main actor whenever a YARA match is found.
    init(
        directories: [String] = FileSystemWatcher.defaultMonitoredDirectories,
        yaraEngine: YARAEngine,
        onThreatSignal: @escaping @Sendable (ThreatSignal) -> Void
    ) {
        self.directories = directories
        self.yaraEngine = yaraEngine
        self.onThreatSignal = onThreatSignal
    }

    // MARK: - Public API

    /// Starts the FSEvents stream for all monitored directories.
    ///
    /// Safe to call multiple times — a second call stops the existing stream
    /// and starts a new one.
    func startWatching() {
        lock.lock()
        defer { lock.unlock() }
        stopStreamLocked()
        startStreamLocked()
        Self.log.info("FileSystemWatcher: started watching \(self.directories.count) directories")
    }

    /// Stops the FSEvents stream and releases all resources.
    func stopWatching() {
        lock.lock()
        defer { lock.unlock() }
        stopStreamLocked()
        Self.log.info("FileSystemWatcher: stopped.")
    }

    /// Number of paths discarded because the bounded real-time scan queue was full.
    /// The lock makes this safe to read from the coordinator while callbacks enqueue.
    func droppedEventsSnapshot() -> Int {
        lock.withLock { droppedEventCount }
    }

    // MARK: - Internal Helpers

    private func startStreamLocked() {
        let watchedPaths = directories as CFArray
        // Retain self across the C callback boundary via Unmanaged.
        // SECURITY: The context info pointer is released in stopStreamLocked,
        // preventing memory leaks. passRetained balances with release() in stop.
        let selfPtr = Unmanaged.passRetained(self).toOpaque()

        var context = FSEventStreamContext(
            version: 0,
            info: selfPtr,
            retain: nil,
            release: { ptr in
                guard let p = ptr else { return }
                Unmanaged<FileSystemWatcher>.fromOpaque(p).release()
            },
            copyDescription: nil
        )

        guard let stream = FSEventStreamCreate(
            kCFAllocatorDefault,
            fileSystemEventCallback,
            &context,
            watchedPaths,
            FSEventStreamEventId(kFSEventStreamEventIdSinceNow),
            Self.fsEventsLatency,
            UInt32(kFSEventStreamCreateFlagFileEvents |
                   kFSEventStreamCreateFlagNoDefer |
                   kFSEventStreamCreateFlagUseCFTypes)
        ) else {
            Self.log.error("FileSystemWatcher: FSEventStreamCreate failed — YARA real-time scanning disabled")
            Unmanaged<FileSystemWatcher>.fromOpaque(selfPtr).release()
            return
        }

        FSEventStreamSetDispatchQueue(stream, callbackQueue)
        FSEventStreamStart(stream)
        eventStream = stream
    }

    private func stopStreamLocked() {
        guard let stream = eventStream else { return }
        FSEventStreamStop(stream)
        FSEventStreamInvalidate(stream)
        FSEventStreamRelease(stream)
        eventStream = nil
    }

    // MARK: - Private Implementation

    /// Called (on `callbackQueue`) for each FSEvents batch.
    fileprivate func handleEvents(paths: [String], flags: [UInt32]) {
        // Browsers download to a temporary name and rename on completion, so the
        // finished file only ever produces a rename event.
        let createdOrModified = UInt32(
            kFSEventStreamEventFlagItemCreated
                | kFSEventStreamEventFlagItemModified
                | kFSEventStreamEventFlagItemRenamed
        )
        for (path, flag) in zip(paths, flags) {
            guard (flag & createdOrModified) != 0 else { continue }

            // Detect shell profile modifications (Fix 4).
            if isShellProfile(path) {
                emitPersistenceSignal(
                    for: path,
                    reason: "shell_profile_modified",
                    severity: .medium
                )
            }

            // Detect SSH authorized_keys modifications (Fix 5).
            if path.hasSuffix("/authorized_keys") {
                emitPersistenceSignal(
                    for: path,
                    reason: "ssh_keys_modified",
                    severity: .critical
                )
            }

            // Only queue content that can run. Downloads are not `+x`, so the
            // executable bit alone missed scripts, installers, and raw Mach-O.
            guard isScanCandidate(at: path) else { continue }
            queueYARAScan(for: path)
        }
    }

    /// Returns `true` when `path` is one of the known shell startup/profile files.
    private func isShellProfile(_ path: String) -> Bool {
        let name = URL(fileURLWithPath: path).lastPathComponent
        let profiles: Set<String> = [
            ".zshrc", ".zprofile", ".zlogin", ".zlogout", ".zshenv",
            ".bash_profile", ".bashrc", ".bash_login", ".bash_logout",
            ".profile",
            "zshrc", "zprofile", "zshenv",   // /etc/zshrc, /etc/zprofile, /etc/zshenv
        ]
        return profiles.contains(name)
    }

    /// Emits a `.persistence` threat signal on the main actor.
    ///
    /// - Parameters:
    ///   - path:   Absolute path of the modified file.
    ///   - reason: Value written to `metadata["reason"]` for rule matching.
    ///   - severity: Severity of the emitted signal.
    private func emitPersistenceSignal(for path: String,
                                       reason: String,
                                       severity: SignalSeverity) {
        let fileName = URL(fileURLWithPath: path).lastPathComponent
        let signal = ThreatSignal(
            source: .persistence,
            severity: severity,
            title: "Sensitive file modified: \(fileName)",
            description: "'\(path)' was created or modified. This is a common persistence and privilege-escalation vector.",
            context: ThreatSignalContext(metadata: ["reason": reason, "path": path])
        )
        Self.log.warning("Persistence signal: \(reason, privacy: .public) — \(path, privacy: .private)")
        Task.detached(priority: .utility) { [weak self, signal] in
            guard let self else { return }
            await MainActor.run { self.onThreatSignal(signal) }
        }
    }

    private func queueYARAScan(for path: String) {
        // Do not scan Nick's own Xcode products during local development.
        // Production builds do not monitor /private/tmp, but this also protects
        // developers who explicitly add a build directory to the watcher.
        let lowerPath = path.lowercased()
        if lowerPath.contains("/nickperformanceaudit"),
           lowerPath.contains("/nick.app/contents/") {
            return
        }

        let shouldStart = lock.withLock { () -> Bool in
            guard !scansInFlight.contains(path), !pendingScans.contains(path) else { return false }
            if scansInFlight.count < Self.maxConcurrentScans {
                scansInFlight.insert(path)
                return true
            }
            guard pendingScans.enqueue(path) else {
                droppedEventCount += 1
                Self.log.error("FSEvents scan queue full; dropped count: \(self.droppedEventCount)")
                return false
            }
            return false
        }
        guard shouldStart else { return }
        startYARAScan(for: path)
    }

    private func startYARAScan(for path: String) {
        // Detach a low-priority task so the FSEvents callback returns immediately.
        Task.detached(priority: .utility) { [weak self, path] in
            guard let self else { return }
            defer {
                let next = self.lock.withLock { () -> String? in
                    self.scansInFlight.remove(path)
                    guard let next = self.pendingScans.dequeue() else { return nil }
                    self.scansInFlight.insert(next)
                    return next
                }
                if let next { self.startYARAScan(for: next) }
            }
            do {
                let rawMatches = try await self.yaraEngine.scanFile(at: path)
                // Apply the same context classifier as Deep Scan so a behaviour
                // rule inside a signed app's data or a verified build tree does
                // not raise a real-time alert that Deep Scan would not.
                let matches = DeepScanner.uniqueMatches(rawMatches).filter {
                    let verdict = DeepScanner.classify(match: $0)
                    return verdict == .threat || verdict == .suspicious
                }
                guard !matches.isEmpty else { return }
                let signal = self.makeThreatSignal(for: path, matches: matches)
                Self.log.warning("YARA match on \(path, privacy: .private): \(matches.map(\.ruleName).joined(separator: ", "), privacy: .public)")
                await MainActor.run { self.onThreatSignal(signal) }
            } catch YARAError.scanTimeout(let p) {
                Self.log.warning("YARA scan timeout (FSEvents): \(p, privacy: .private)")
            } catch YARAError.fileNotReadable {
                // Transient — file may have been deleted between FSEvent and scan.
                return
            } catch {
                Self.log.error("YARA scan error on \(path, privacy: .private): \(error.localizedDescription, privacy: .public)")
            }
        }
    }

    private func isScanCandidate(at path: String) -> Bool {
        let fm = FileManager.default
        guard let attributes = try? fm.attributesOfItem(atPath: path),
              attributes[.type] as? FileAttributeType == .typeRegular,
              let size = (attributes[.size] as? NSNumber)?.uint64Value,
              size > 0,
              size <= Self.maxRealtimeFileSize
        else {
            return false
        }
        if fm.isExecutableFile(atPath: path) { return true }
        return ScanCandidatePolicy.isExecutableContent(ScanCandidatePolicy.kind(atPath: path))
    }

    private func makeThreatSignal(for path: String, matches: [YARAMatch]) -> ThreatSignal {
        let ruleNames = matches.map(\.ruleName).joined(separator: ", ")
        let tags = Set(matches.flatMap(\.tags)).sorted().joined(separator: ", ")
        let severity = matches
            .map(DeepScanner.signalSeverity(for:))
            .max() ?? .medium

        // Metadata dictionary for correlator use.
        var meta: [String: String] = [
            "yaraRules": ruleNames,
            "yaraTags": tags,
            "yaraAuthors": Set(matches.compactMap { $0.metadata["author"] }).sorted().joined(separator: ", "),
        ]
        if let firstMeta = matches.first?.metadata {
            for (k, v) in firstMeta { meta["yara_\(k)"] = v }
        }

        return ThreatSignal(
            source: .yara,
            severity: severity,
            title: "YARA match: \(ruleNames)",
            description: "YARA rule(s) [\(ruleNames)] matched file at \(path). Tags: \(tags.isEmpty ? "none" : tags).",
            context: ThreatSignalContext(
                fileInfo: FileInfo(
                    path: path,
                    sha256Hash: nil,
                    entropy: nil,
                    signingStatus: nil,
                    sizeBytes: (try? FileManager.default.attributesOfItem(atPath: path)[.size] as? Int) ?? nil
                ),
                metadata: meta
            )
        )
    }
}

/// FIFO queue used by FSEvents. Duplicate paths coalesce; overflow is explicit
/// so the caller can increment a health counter instead of silently dropping.
struct BoundedPathQueue: Sendable {
    private let capacity: Int
    private var items: [String] = []
    private var members: Set<String> = []

    init(capacity: Int) { self.capacity = max(1, capacity) }

    func contains(_ path: String) -> Bool { members.contains(path) }

    mutating func enqueue(_ path: String) -> Bool {
        if members.contains(path) { return true }
        guard items.count < capacity else { return false }
        items.append(path)
        members.insert(path)
        return true
    }

    mutating func dequeue() -> String? {
        guard !items.isEmpty else { return nil }
        let path = items.removeFirst()
        members.remove(path)
        return path
    }
}

// MARK: - FSEvents C Callback

/// Non-capturing C callback registered with `FSEventStreamCreate`.
///
/// `context.info` carries a retained `FileSystemWatcher` pointer. The FSEvents
/// runtime calls the release function (set in context) when the stream is
/// invalidated, balancing the `passRetained` in `startStreamLocked`.
private let fileSystemEventCallback: FSEventStreamCallback = {
    _, contextInfo, numEvents, eventPaths, eventFlags, _ in
    guard let contextInfo else { return }
    let watcher = Unmanaged<FileSystemWatcher>.fromOpaque(contextInfo).takeUnretainedValue()

    // kFSEventStreamCreateFlagUseCFTypes ensures eventPaths is a CFArray of CFStrings,
    // which toll-free bridges to NSArray of NSString. The unsafeBitCast below is valid
    // only because that flag is set; without it eventPaths would be a plain char**.
    let pathsArray = unsafeBitCast(eventPaths, to: NSArray.self)
    var paths: [String] = []
    var flagsArray: [UInt32] = []
    for i in 0 ..< numEvents {
        if let p = pathsArray[i] as? String {
            paths.append(p)
            flagsArray.append(eventFlags[i])
        }
    }
    watcher.handleEvents(paths: paths, flags: flagsArray)
}
