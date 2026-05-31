// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation

/// Finds `.mov` files on the Desktop that look like screen recordings (QuickTime Player output).
struct ScreenRecordingExportsRule: ScanRule {
    let category = JunkCategory.screenRecordings
    let displayName = "Screen Recording Exports"

    private static let minSize: Int64 = 5_000_000 // 5 MB

    func scan() async -> [JunkItem] {
        let roots = [
            ScanRuleHelpers.homeURL("Desktop"),
            ScanRuleHelpers.homeURL("Documents"),
        ]

        return roots.flatMap { root -> [JunkItem] in
            guard ScanRuleHelpers.exists(root) else { return [] }
            return ScanRuleHelpers.files(under: root, withExtensions: ["mov"], maxDepth: 1)
                .compactMap { url in
                    // QuickTime screen recordings follow the pattern "Screen Recording <date>.mov"
                    let name = url.deletingPathExtension().lastPathComponent
                    guard name.lowercased().contains("screen recording") ||
                          name.lowercased().contains("screen shot") else { return nil }
                    let size = ScanRuleHelpers.size(of: url)
                    guard size >= Self.minSize else { return nil }
                    return JunkItem(url: url, size: size, category: category,
                                    riskLevel: .review, name: url.lastPathComponent,
                                    reason: "Screen recording export — review and delete if no longer needed.")
                }
        }
    }
}
