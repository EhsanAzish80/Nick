// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation

/// Scans Safari, Firefox, and other browser caches.
struct BrowserCacheRule: ScanRule {
    let category = JunkCategory.browserCache
    let displayName = "Browser Cache"

    private let paths: [(URL, String)] = [
        (ScanRuleHelpers.homeURL("Library", "Caches", "com.apple.Safari"),           "Safari Cache"),
        (ScanRuleHelpers.homeURL("Library", "Caches", "com.apple.SafariTechnologyPreview"), "Safari TP Cache"),
        (ScanRuleHelpers.homeURL("Library", "Application Support", "Firefox", "Profiles"), "Firefox Profile Cache"),
        (ScanRuleHelpers.homeURL("Library", "Application Support", "Microsoft Edge", "Default", "Cache"), "Edge Cache"),
        (ScanRuleHelpers.homeURL("Library", "Application Support", "Opera Software", "Opera Stable", "Cache"), "Opera Cache"),
        (ScanRuleHelpers.homeURL("Library", "Caches", "com.operasoftware.Opera"),    "Opera Caches"),
    ]

    func scan() async -> [JunkItem] {
        paths.compactMap { (url, label) in
            guard ScanRuleHelpers.exists(url) else { return nil }
            let size = ScanRuleHelpers.size(of: url)
            guard size > 0 else { return nil }
            return JunkItem(url: url, size: size, category: category,
                            riskLevel: .safe, name: label,
                            reason: "Browser HTTP cache — safe to clean while the browser is closed.")
        }
    }
}
