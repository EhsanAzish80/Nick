// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation

/// Finds large files (≥ 50 MB) in `~/Downloads` not accessed in 90+ days.
struct DownloadsRule: ScanRule {
    let category = JunkCategory.downloads
    let displayName = "Large Old Downloads"

    private static let minSize: Int64 = 50_000_000   // 50 MB
    private static let ageCutoff: TimeInterval = 90 * 86400 // 90 days

    func scan() async -> [JunkItem] {
        let downloads = ScanRuleHelpers.homeURL("Downloads")
        guard ScanRuleHelpers.exists(downloads) else { return [] }

        let cutoff = Date().addingTimeInterval(-Self.ageCutoff)

        return ScanRuleHelpers.children(of: downloads).compactMap { url in
            let size = ScanRuleHelpers.size(of: url)
            guard size >= Self.minSize else { return nil }
            guard let accessed = ScanRuleHelpers.lastAccessed(url), accessed < cutoff else { return nil }
            return JunkItem(url: url, size: size, category: category,
                            riskLevel: .review, name: url.lastPathComponent,
                            reason: "Large file not opened in over 90 days.")
        }
    }
}
