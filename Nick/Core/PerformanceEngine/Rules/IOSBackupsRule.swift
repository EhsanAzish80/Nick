// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation

/// Scans `~/Library/Application Support/MobileSync/Backup` for old iOS device backups.
struct IOSBackupsRule: ScanRule {
    let category = JunkCategory.iosBackups
    let displayName = "iOS Device Backups"

    func scan() async -> [JunkItem] {
        let root = ScanRuleHelpers.homeURL("Library", "Application Support", "MobileSync", "Backup")
        guard ScanRuleHelpers.exists(root) else { return [] }

        return ScanRuleHelpers.subdirectories(of: root).compactMap { dir in
            let size = ScanRuleHelpers.size(of: dir)
            guard size > 0 else { return nil }
            // Approximate date from modification time
            let modified = ScanRuleHelpers.lastModified(dir)
            let ageLabel = modified.map { d in
                let days = Int(Date().timeIntervalSince(d) / 86400)
                return "\(days) day(s) old"
            } ?? "unknown age"
            return JunkItem(url: dir, size: size, category: category,
                            riskLevel: .review, name: dir.lastPathComponent,
                            reason: "iOS backup (\(ageLabel)) — delete only if you no longer need it.")
        }
    }
}
