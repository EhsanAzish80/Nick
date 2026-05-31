// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation

/// Scans `~/Library/Caches` and reports the total size.
struct CacheRule: ScanRule {
    let category = JunkCategory.applicationCaches
    let displayName = "Application Caches"

    func scan() async -> [JunkItem] {
        let root = ScanRuleHelpers.homeURL("Library", "Caches")
        guard ScanRuleHelpers.exists(root) else { return [] }
        let size = ScanRuleHelpers.size(of: root)
        guard size > 0 else { return [] }
        return [JunkItem(url: root, size: size, category: category,
                         riskLevel: .safe, name: "Application Caches",
                         reason: "Cache files that macOS regenerates automatically.")]
    }
}
