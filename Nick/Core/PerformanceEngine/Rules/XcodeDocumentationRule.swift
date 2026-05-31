// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation

/// Scans `~/Library/Developer/Shared/Documentation/DocSets` for Xcode documentation.
struct XcodeDocumentationRule: ScanRule {
    let category = JunkCategory.documentation
    let displayName = "Xcode Documentation"

    func scan() async -> [JunkItem] {
        let root = ScanRuleHelpers.homeURL("Library", "Developer", "Shared", "Documentation", "DocSets")
        guard ScanRuleHelpers.exists(root) else { return [] }

        return ScanRuleHelpers.children(of: root).compactMap { url in
            let size = ScanRuleHelpers.size(of: url)
            guard size > 10_000_000 else { return nil }
            return JunkItem(url: url, size: size, category: category,
                            riskLevel: .review, name: url.lastPathComponent,
                            reason: "Xcode documentation set — re-downloaded from Xcode Preferences.")
        }
    }
}
