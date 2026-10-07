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

    /// Empty until a prefix is proven noisy and safe for every subscribed event.
    /// Nick's own extension process is muted separately by audit token.
    static let mutedPrefixes: [String] = []

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
