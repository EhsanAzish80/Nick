// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation

/// Finds `.zip` archives on the Desktop and in Downloads older than 30 days.
struct OldZipArchivesRule: ScanRule {
    let category = JunkCategory.other
    let displayName = "Old Zip Archives"

    private static let archiveExtensions: Set<String> = ["zip", "tar", "gz", "bz2", "rar", "7z"]
    private static let ageCutoff: TimeInterval = 30 * 86400

    func scan() async -> [JunkItem] {
        let roots = [
            ScanRuleHelpers.homeURL("Desktop"),
            ScanRuleHelpers.homeURL("Downloads"),
        ]
        let cutoff = Date().addingTimeInterval(-Self.ageCutoff)

        return roots.flatMap { root -> [JunkItem] in
            guard ScanRuleHelpers.exists(root) else { return [] }
            return ScanRuleHelpers.files(under: root, withExtensions: Self.archiveExtensions, maxDepth: 1)
                .compactMap { url in
                    guard let modified = ScanRuleHelpers.lastModified(url), modified < cutoff else { return nil }
                    let size = ScanRuleHelpers.size(of: url)
                    guard size > 0 else { return nil }
                    return JunkItem(url: url, size: size, category: .other,
                                    riskLevel: .review, name: url.lastPathComponent,
                                    reason: "Archive file more than 30 days old.")
                }
        }
    }
}
