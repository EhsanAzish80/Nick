// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation

/// Finds `.tiff` and `.psd` files ≥ 50 MB (large image exports / working files).
struct LargeImageExportsRule: ScanRule {
    let category = JunkCategory.largeFiles
    let displayName = "Large Image Exports"

    private static let imageExtensions: Set<String> = ["tiff", "tif", "psd", "psb", "xcf"]
    private static let minSize: Int64 = 50_000_000 // 50 MB

    func scan() async -> [JunkItem] {
        let roots = [
            ScanRuleHelpers.homeURL("Desktop"),
            ScanRuleHelpers.homeURL("Downloads"),
            ScanRuleHelpers.homeURL("Documents"),
            ScanRuleHelpers.homeURL("Pictures"),
        ]

        return roots.flatMap { root -> [JunkItem] in
            guard ScanRuleHelpers.exists(root) else { return [] }
            return ScanRuleHelpers.files(under: root, withExtensions: Self.imageExtensions, maxDepth: 3)
                .compactMap { url in
                    let size = ScanRuleHelpers.size(of: url)
                    guard size >= Self.minSize else { return nil }
                    return JunkItem(url: url, size: size, category: category,
                                    riskLevel: .review, name: url.lastPathComponent,
                                    reason: "Large image export or working file (≥ 50 MB).")
                }
        }
    }
}
