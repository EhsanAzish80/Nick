// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation

/// Finds `.mov`, `.mp4`, and `.avi` files ≥ 500 MB on the Desktop and in Downloads.
struct LargeVideoFilesRule: ScanRule {
    let category = JunkCategory.largeFiles
    let displayName = "Large Video Files"

    private static let videoExtensions: Set<String> = ["mov", "mp4", "avi", "mkv", "m4v"]
    private static let minSize: Int64 = 500_000_000 // 500 MB

    func scan() async -> [JunkItem] {
        let roots = [
            ScanRuleHelpers.homeURL("Desktop"),
            ScanRuleHelpers.homeURL("Downloads"),
            ScanRuleHelpers.homeURL("Movies"),
        ]

        return roots.flatMap { root -> [JunkItem] in
            guard ScanRuleHelpers.exists(root) else { return [] }
            return ScanRuleHelpers.files(under: root, withExtensions: Self.videoExtensions, maxDepth: 2)
                .compactMap { url in
                    let size = ScanRuleHelpers.size(of: url)
                    guard size >= Self.minSize else { return nil }
                    return JunkItem(url: url, size: size, category: category,
                                    riskLevel: .review, name: url.lastPathComponent,
                                    reason: "Large video file (≥ 500 MB).")
                }
        }
    }
}
