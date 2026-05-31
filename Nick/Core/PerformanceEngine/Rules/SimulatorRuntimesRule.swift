// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation

/// Scans `~/Library/Developer/CoreSimulator/Profiles/Runtimes` for simulator OS images.
struct SimulatorRuntimesRule: ScanRule {
    let category = JunkCategory.simulatorData
    let displayName = "Simulator Runtimes"

    func scan() async -> [JunkItem] {
        let root = ScanRuleHelpers.homeURL("Library", "Developer", "CoreSimulator", "Profiles", "Runtimes")
        guard ScanRuleHelpers.exists(root) else { return [] }

        return ScanRuleHelpers.children(of: root).compactMap { url in
            let size = ScanRuleHelpers.size(of: url)
            guard size > 50_000_000 else { return nil }
            return JunkItem(url: url, size: size, category: category,
                            riskLevel: .review, name: url.lastPathComponent,
                            reason: "Simulator OS runtime — download again from Xcode if needed.")
        }
    }
}
