// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation

/// Scans `~/.swiftpm` and SPM caches inside DerivedData.
struct SwiftPMRule: ScanRule {
    let category = JunkCategory.developerCache
    let displayName = "Swift Package Manager Cache"

    func scan() async -> [JunkItem] {
        var items: [JunkItem] = []

        let localCache = ScanRuleHelpers.homeURL(".swiftpm")
        if ScanRuleHelpers.exists(localCache) {
            let size = ScanRuleHelpers.size(of: localCache)
            if size > 0 {
                items.append(JunkItem(url: localCache, size: size, category: category,
                                      riskLevel: .safe, name: "Swift PM Local Cache",
                                      reason: "SPM dependency cache — re-downloaded on next build."))
            }
        }

        // SPM downloaded sources inside DerivedData
        let spmSource = ScanRuleHelpers.homeURL("Library", "Developer", "Xcode", "DerivedData", "SourcePackages")
        if ScanRuleHelpers.exists(spmSource) {
            let size = ScanRuleHelpers.size(of: spmSource)
            if size > 0 {
                items.append(JunkItem(url: spmSource, size: size, category: category,
                                      riskLevel: .safe, name: "Xcode SPM Sources",
                                      reason: "Swift Package Manager fetched sources — re-cloned on next build."))
            }
        }

        return items
    }
}
