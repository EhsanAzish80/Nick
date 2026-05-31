// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation

/// Scans npm and Yarn caches.
struct JavaScriptCacheRule: ScanRule {
    let category = JunkCategory.scriptingCaches
    let displayName = "npm / Yarn Cache"

    func scan() async -> [JunkItem] {
        var items: [JunkItem] = []

        let candidates: [(URL, String)] = [
            (ScanRuleHelpers.homeURL(".npm"),          "npm Cache"),
            (ScanRuleHelpers.homeURL(".yarn", "cache"), "Yarn Cache"),
            (ScanRuleHelpers.homeURL("Library", "Caches", "node"),   "Node Cache"),
        ]

        for (url, label) in candidates {
            guard ScanRuleHelpers.exists(url) else { continue }
            let size = ScanRuleHelpers.size(of: url)
            guard size > 0 else { continue }
            items.append(JunkItem(url: url, size: size, category: category,
                                  riskLevel: .safe, name: label,
                                  reason: "JavaScript package manager cache — regenerated on next install."))
        }
        return items
    }
}
