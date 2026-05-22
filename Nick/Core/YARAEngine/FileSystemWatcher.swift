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
        "/usr/bin",
        "/usr/sbin",
        "/private/tmp",
        NSString("~/Library/Application Support").expandingTildeInPath,
        NSString("~/.local/bin").expandingTildeInPath,
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
            UInt32(kFSEventStreamCreateFlagFileEvents | kFSEventStreamCreateFlagNoDefer)
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
        let created: UInt32 = UInt32(kFSEventStreamEventFlagItemCreated | kFSEventStreamEventFlagItemModified)
        for (path, flag) in zip(paths, flags) {
            guard (flag & created) != 0 else { continue }
            // SECURITY: Only queue files that are executable to avoid
            // scanning data files and wasting CPU budget.
            guard isExecutable(at: path) else { continue }
            queueYARAScan(for: path)
        }
    }

    private func queueYARAScan(for path: String) {
        // Detach a low-priority task so the FSEvents callback returns immediately.
        Task.detached(priority: .utility) { [weak self, path] in
            guard let self else { return }
            do {
                let matches = try await self.yaraEngine.scanFile(at: path)
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

    private func isExecutable(at path: String) -> Bool {
        let fm = FileManager.default
        guard fm.fileExists(atPath: path) else { return false }
        return fm.isExecutableFile(atPath: path)
    }

    private func makeThreatSignal(for path: String, matches: [YARAMatch]) -> ThreatSignal {
        let ruleNames = matches.map(\.ruleName).joined(separator: ", ")
        let tags = Set(matches.flatMap(\.tags)).sorted().joined(separator: ", ")
        let severity: SignalSeverity = tags.contains("critical") ? .critical : .high

        // Metadata dictionary for correlator use.
        var meta: [String: String] = [
            "yaraRules": ruleNames,
            "yaraTags": tags,
        ]
        if let firstMeta = matches.first?.metadata {
            for (k, v) in firstMeta { meta["yara_\(k)"] = v }
        }

        return ThreatSignal(
            source: .yara,
            severity: severity,
            title: "YARA match: \(ruleNames)",
            description: "YARA rule(s) [\(ruleNames)] matched file at \(path). Tags: \(tags.isEmpty ? "none" : tags).",
            fileInfo: FileInfo(
                path: path,
                sha256Hash: nil,
                entropy: nil,
                signingStatus: nil,
                sizeBytes: (try? FileManager.default.attributesOfItem(atPath: path)[.size] as? Int) ?? nil
            ),
            metadata: meta
        )
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

    // eventPaths is UnsafeMutableRawPointer (non-optional) from FSEventStreamCallback.
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
