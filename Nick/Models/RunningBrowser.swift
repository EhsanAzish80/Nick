// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation

// MARK: - RunningBrowser

/// A browser process that was detected as active by `BrowserDetector`.
///
/// `CleanupExecutor` skips cache cleanup for running browsers to avoid
/// corrupting in-flight session data.
struct RunningBrowser: Identifiable, Sendable {
    let id: UUID
    /// Bundle identifier (e.g. `"com.apple.Safari"`).
    let bundleID: String
    /// Human-readable name.
    let name: String
    /// Cache directories owned by this browser.
    let cachePaths: [URL]

    init(bundleID: String, name: String, cachePaths: [URL]) {
        self.id         = UUID()
        self.bundleID   = bundleID
        self.name       = name
        self.cachePaths = cachePaths
    }
}
