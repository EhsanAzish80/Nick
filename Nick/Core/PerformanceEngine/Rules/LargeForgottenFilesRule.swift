// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation

/// Finds files ≥ 500 MB that haven't been accessed in 90+ days across the home folder.
struct LargeForgottenFilesRule: ScanRule {
    let category = JunkCategory.largeFiles
    let displayName = "Large Forgotten Files"

    private static let minSize: Int64 = 500_000_000  // 500 MB
    private static let ageCutoff: TimeInterval = 90 * 86400

    /// Directories to skip (system/cache paths scanned by other rules).
    private static let skipPrefixes = [
        "Library/Developer",
        "Library/Caches",
        ".Trash",
    ]

    func scan() async -> [JunkItem] {
        let home = ScanRuleHelpers.home
        guard let enumerator = FileManager.default.enumerator(
            at: home,
            includingPropertiesForKeys: [.fileSizeKey, .contentAccessDateKey, .isDirectoryKey],
            options: [.skipsHiddenFiles, .skipsPackageDescendants]
        ) else { return [] }

        let cutoff = Date().addingTimeInterval(-Self.ageCutoff)
        var items: [JunkItem] = []

        for case let url as URL in enumerator {
            // Skip known-junk subtrees handled by other rules
            let rel = url.path.replacingOccurrences(of: home.path + "/", with: "")
            if Self.skipPrefixes.contains(where: { rel.hasPrefix($0) }) {
                enumerator.skipDescendants()
                continue
            }

            guard let rv = try? url.resourceValues(forKeys: [.fileSizeKey, .contentAccessDateKey, .isDirectoryKey]),
                  rv.isDirectory == false else { continue }

            let size = Int64(rv.fileSize ?? 0)
            guard size >= Self.minSize else { continue }
            guard let accessed = rv.contentAccessDate, accessed < cutoff else { continue }

            items.append(JunkItem(url: url, size: size, category: category,
                                  riskLevel: .review, name: url.lastPathComponent,
                                  reason: "Large file not accessed in over 90 days."))

            await Task.yield()
        }

        return items
    }
}
