// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation

/// Scans Chrome / Chromium cache directories.
struct ChromeCacheRule: ScanRule {
    let category = JunkCategory.browserCache
    let displayName = "Chrome Cache"

    private let chromePaths: [(URL, String)] = [
        (ScanRuleHelpers.homeURL("Library", "Application Support", "Google", "Chrome", "Default", "Cache"), "Chrome Default Cache"),
        (ScanRuleHelpers.homeURL("Library", "Application Support", "Google", "Chrome", "Default", "Code Cache"), "Chrome Code Cache"),
        (ScanRuleHelpers.homeURL("Library", "Application Support", "Chromium", "Default", "Cache"), "Chromium Cache"),
        (ScanRuleHelpers.homeURL("Library", "Application Support", "BraveSoftware", "Brave-Browser", "Default", "Cache"), "Brave Cache"),
    ]

    func scan() async -> [JunkItem] {
        chromePaths.compactMap { (url, label) in
            guard ScanRuleHelpers.exists(url) else { return nil }
            let size = ScanRuleHelpers.size(of: url)
            guard size > 0 else { return nil }
            return JunkItem(url: url, size: size, category: category,
                            riskLevel: .safe, name: label,
                            reason: "Browser HTTP cache — cleared automatically by the browser, safe to remove while Chrome is closed.")
        }
    }
}
