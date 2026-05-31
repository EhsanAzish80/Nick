// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation

/// Scans `~/Library/Developer/CoreSimulator/Devices` for simulator device images.
struct SimulatorDataRule: ScanRule {
    let category = JunkCategory.simulatorData
    let displayName = "Simulator Devices"

    func scan() async -> [JunkItem] {
        let root = ScanRuleHelpers.homeURL("Library", "Developer", "CoreSimulator", "Devices")
        guard ScanRuleHelpers.exists(root) else { return [] }

        return ScanRuleHelpers.subdirectories(of: root).compactMap { dir in
            let size = ScanRuleHelpers.size(of: dir)
            guard size > 10_000_000 else { return nil }
            return JunkItem(url: dir, size: size, category: category,
                            riskLevel: .review, name: dir.lastPathComponent,
                            reason: "Simulator device disk image — safe to delete if you no longer test on this device type.")
        }
    }
}
