// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation

/// Scans `~/Library/Developer/Xcode/DerivedData` — typically several GB.
struct DerivedDataRule: ScanRule {
    let category = JunkCategory.developerCache
    let displayName = "Xcode Derived Data"

    func scan() async -> [JunkItem] {
        let root = ScanRuleHelpers.homeURL("Library", "Developer", "Xcode", "DerivedData")
        guard ScanRuleHelpers.exists(root) else { return [] }

        return ScanRuleHelpers.subdirectories(of: root).compactMap { dir in
            let size = ScanRuleHelpers.size(of: dir)
            guard size > 1_000_000 else { return nil }
            return JunkItem(url: dir, size: size, category: category,
                            riskLevel: .safe, name: dir.lastPathComponent,
                            reason: "Xcode build artefacts — regenerated on next build.")
        }
    }
}
