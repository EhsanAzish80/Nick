// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation

/// Scans `~/Library/Developer/Xcode/Archives` for old release archives.
struct ArchivesRule: ScanRule {
    let category = JunkCategory.xcodeArchives
    let displayName = "Xcode Archives"

    func scan() async -> [JunkItem] {
        let root = ScanRuleHelpers.homeURL("Library", "Developer", "Xcode", "Archives")
        guard ScanRuleHelpers.exists(root) else { return [] }

        var items: [JunkItem] = []
        for dateDir in ScanRuleHelpers.subdirectories(of: root) {
            for archive in ScanRuleHelpers.children(of: dateDir) {
                let size = ScanRuleHelpers.size(of: archive)
                guard size > 1_000_000 else { continue }
                items.append(JunkItem(url: archive, size: size, category: category,
                                      riskLevel: .review, name: archive.lastPathComponent,
                                      reason: "Xcode archive — keep only if you need to re-export or debug crashes from this build."))
            }
        }
        return items
    }
}
