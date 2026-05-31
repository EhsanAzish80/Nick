// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import EndpointSecurity
import Foundation
import os

// MARK: - MuteManager

/// Registers high-volume, trusted path prefixes with the ES client so the
/// extension never receives events for them.
///
/// Muting system paths dramatically reduces event throughput. Without muting,
/// `/System/` and `/usr/` alone generate thousands of events per second on
/// a busy system. These paths are definitionally trusted (SIP-protected) and
/// do not need to be monitored for Phase 2.
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

    /// SIP-protected system locations that are safe to ignore entirely.
    static let mutedPrefixes: [String] = [
        "/System/",
        "/usr/lib/",
        "/usr/libexec/",
        "/usr/bin/",
        "/usr/sbin/",
        "/Library/Apple/",
        "/private/var/db/",
        "/private/var/run/",
        // NOTE: /private/var/folders/ intentionally NOT muted — malware stages payloads there
    ]

    // MARK: - Public API

    /// Applies all prefix mutes to `esClient`.
    ///
    /// - Parameter esClient: A started (post-`start()`) `EndpointSecurityClient`.
    static func applyMutes(to esClient: EndpointSecurityClient) {
        var mutedCount = 0
        for prefix in mutedPrefixes {
            if esClient.mutePathPrefix(prefix) {
                mutedCount += 1
            } else {
                logger.warning("Failed to mute prefix: \(prefix)")
            }
        }
        logger.info("Applied \(mutedCount)/\(mutedPrefixes.count) path prefix mutes")
    }
}
