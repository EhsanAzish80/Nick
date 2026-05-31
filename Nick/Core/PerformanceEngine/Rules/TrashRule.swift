// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation

/// Reports the total size of the user's Trash.
struct TrashRule: ScanRule {
    let category = JunkCategory.trash
    let displayName = "Trash"

    func scan() async -> [JunkItem] {
        let trashURL = ScanRuleHelpers.homeURL(".Trash")
        guard ScanRuleHelpers.exists(trashURL) else { return [] }
        let size = ScanRuleHelpers.size(of: trashURL)
        guard size > 0 else { return [] }
        return [JunkItem(url: trashURL, size: size, category: category,
                         riskLevel: .safe, name: "Trash",
                         reason: "Files already moved to Trash — permanently delete to free space.")]
    }
}
