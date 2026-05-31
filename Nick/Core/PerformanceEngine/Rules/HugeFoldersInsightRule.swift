// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation

/// Flags direct children of `~` that are > 1 GB and haven't been modified in 6 months.
struct HugeFoldersInsightRule: ScanRule {
    let category = JunkCategory.hugeFolders
    let displayName = "Huge Folders"

    private static let minSize: Int64 = 1_000_000_000  // 1 GB
    private static let ageCutoff: TimeInterval = 6 * 30 * 86400  // ~6 months

    /// Folders to skip — they're scanned by dedicated rules.
    private static let skipNames: Set<String> = [
        "Library", "Applications", ".Trash", ".npm", ".gradle",
        ".docker", ".android", ".swiftpm",
    ]

    func scan() async -> [JunkItem] {
        let home = ScanRuleHelpers.home
        let cutoff = Date().addingTimeInterval(-Self.ageCutoff)

        return ScanRuleHelpers.children(of: home).compactMap { url in
            guard !Self.skipNames.contains(url.lastPathComponent) else { return nil }
            guard let rv = try? url.resourceValues(forKeys: [.isDirectoryKey, .contentModificationDateKey]),
                  rv.isDirectory == true else { return nil }
            guard let modified = rv.contentModificationDate, modified < cutoff else { return nil }
            let size = ScanRuleHelpers.size(of: url)
            guard size >= Self.minSize else { return nil }
            return JunkItem(url: url, size: size, category: category,
                            riskLevel: .review, name: url.lastPathComponent,
                            reason: "Large folder (≥ 1 GB) not modified in over 6 months.")
        }
    }
}
