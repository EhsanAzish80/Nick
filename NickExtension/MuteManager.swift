// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import EndpointSecurity
import Foundation
import os

// MARK: - MuteManager

/// Registers only path mutes that have measurement evidence and cannot hide a
/// monitored target. Process-image prefix mutes were removed because Endpoint
/// Security applies them to events involving those paths, which can hide a
/// trusted writer (Finder, Mail, Safari, xpcproxy) modifying an untrusted file.
///
/// Call `applyMutes(to:)` once after the ES client has started and subscribed.
///
/// - Note: Uses `es_mute_path` (available macOS 12+, still functional on 13+).
///   TODO Phase 4: migrate to `es_mute_path_events` for per-event-type granularity.
enum MuteManager {

    private static let logger = Logger(
        subsystem: "com.ehsanazish.nick.NickExtension",
        category: "MuteManager"
    )

    // MARK: - Muted Path Prefixes

    /// Read/map targets on the sealed system volume. These mutes never apply to
    /// EXEC or writer events. `/usr/local` is deliberately not covered.
    static let sealedReadTargetPrefixes: [String] = [
        "/System/", "/usr/bin/", "/usr/lib/", "/usr/libexec/", "/usr/sbin/",
        "/usr/share/", "/bin/", "/sbin/", "/Library/Apple/",
    ]

    struct MeasuredProcessMute {
        let executableName: String
        let reason: String
    }

    /// Spotlight workers dominate OPEN/MMAP traffic during indexing. Only
    /// those two read events are muted; file writes, EXEC and lifecycle events
    /// remain visible. The real-Mac soak verifies this list before merge.
    static let measuredProcessMutes: [MeasuredProcessMute] = [
        .init(executableName: "mds", reason: "Spotlight index traversal produces sustained read-only OPEN/MMAP traffic"),
        .init(executableName: "mdworker", reason: "Spotlight metadata workers repeatedly read/map indexed content"),
        .init(executableName: "mdworker_shared", reason: "Spotlight shared workers repeatedly read/map indexed content"),
    ]

    private static let mutedPIDs = OSAllocatedUnfairLock(initialState: Set<Int32>())

    // MARK: - Public API

    /// Applies all prefix mutes to `esClient`.
    ///
    /// - Parameter esClient: A started (post-`start()`) `EndpointSecurityClient`.
    static func applyMutes(to esClient: EndpointSecurityClient) {
        let readEvents = [ES_EVENT_TYPE_AUTH_OPEN, ES_EVENT_TYPE_AUTH_MMAP]
        var mutedCount = 0
        for prefix in sealedReadTargetPrefixes {
            if esClient.muteTargetPrefix(prefix, events: readEvents) {
                mutedCount += 1
            } else {
                logger.warning("Failed to mute prefix: \(prefix)")
            }
        }
        logger.info("Applied \(mutedCount)/\(sealedReadTargetPrefixes.count) sealed target-prefix read mutes")
    }

    static func muteMeasuredProcessIfNeeded(_ process: es_process_t, client: OpaquePointer) {
        guard process.is_platform_binary else { return }
        let token = process.executable.pointee.path
        let path = token.data.map { String(decoding: UnsafeRawBufferPointer(start: $0, count: token.length), as: UTF8.self) } ?? ""
        let name = URL(fileURLWithPath: path).lastPathComponent
        guard let entry = measuredProcessMutes.first(where: { $0.executableName == name }) else { return }
        let pid = audit_token_to_pid(process.audit_token)
        let shouldMute = mutedPIDs.withLock { $0.insert(pid).inserted }
        guard shouldMute else { return }
        var auditToken = process.audit_token
        let events = [ES_EVENT_TYPE_AUTH_OPEN, ES_EVENT_TYPE_AUTH_MMAP]
        let result = events.withUnsafeBufferPointer {
            es_mute_process_events(client, &auditToken, $0.baseAddress!, $0.count)
        }
        if result == ES_RETURN_SUCCESS {
            logger.info("Muted read events for \(name, privacy: .public): \(entry.reason, privacy: .public)")
        } else {
            mutedPIDs.withLock { $0.remove(pid) }
            logger.warning("Could not mute measured process \(name, privacy: .public): \(result.rawValue)")
        }
    }
}
