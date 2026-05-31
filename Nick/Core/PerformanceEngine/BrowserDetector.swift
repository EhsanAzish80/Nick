// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation
import AppKit

/// Detects browsers that are currently running so the cleanup executor can skip their live caches.
final class BrowserDetector: Sendable {

    struct KnownBrowser {
        let bundleID: String
        let name: String
        let cachePaths: @Sendable (URL) -> [URL]
    }

    private let knownBrowsers: [KnownBrowser] = [
        .init(bundleID: "com.apple.Safari", name: "Safari") { home in
            [ScanRuleHelpers.homeURL("Library", "Caches", "com.apple.Safari")]
        },
        .init(bundleID: "com.google.Chrome", name: "Google Chrome") { home in
            [
                ScanRuleHelpers.homeURL("Library", "Application Support", "Google", "Chrome", "Default", "Cache"),
                ScanRuleHelpers.homeURL("Library", "Application Support", "Google", "Chrome", "Default", "Code Cache"),
            ]
        },
        .init(bundleID: "com.microsoft.edgemac", name: "Microsoft Edge") { home in
            [ScanRuleHelpers.homeURL("Library", "Application Support", "Microsoft Edge", "Default", "Cache")]
        },
        .init(bundleID: "org.mozilla.firefox", name: "Firefox") { home in
            [ScanRuleHelpers.homeURL("Library", "Application Support", "Firefox", "Profiles")]
        },
        .init(bundleID: "com.brave.Browser", name: "Brave") { home in
            [ScanRuleHelpers.homeURL("Library", "Application Support", "BraveSoftware", "Brave-Browser", "Default", "Cache")]
        },
        .init(bundleID: "com.operasoftware.Opera", name: "Opera") { home in
            [ScanRuleHelpers.homeURL("Library", "Application Support", "com.operasoftware.Opera")]
        },
    ]

    /// Returns browsers currently running on the system.
    @MainActor
    func runningBrowsers() -> [RunningBrowser] {
        let running = NSWorkspace.shared.runningApplications
            .compactMap(\.bundleIdentifier)
        let runningSet = Set(running)

        let home = ScanRuleHelpers.home
        return knownBrowsers
            .filter { runningSet.contains($0.bundleID) }
            .map { RunningBrowser(bundleID: $0.bundleID, name: $0.name, cachePaths: $0.cachePaths(home)) }
    }
}
