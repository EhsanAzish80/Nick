// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation

/// Scans `~/Library/Developer/Xcode/watchOS DeviceSupport` for old watchOS support files.
struct WatchOSDeviceSupportRule: ScanRule {
    let category = JunkCategory.deviceSupport
    let displayName = "watchOS Device Support"

    func scan() async -> [JunkItem] {
        let root = ScanRuleHelpers.homeURL("Library", "Developer", "Xcode", "watchOS DeviceSupport")
        guard ScanRuleHelpers.exists(root) else { return [] }

        return ScanRuleHelpers.subdirectories(of: root).compactMap { dir in
            let size = ScanRuleHelpers.size(of: dir)
            guard size > 0 else { return nil }
            return JunkItem(url: dir, size: size, category: category,
                            riskLevel: .safe, name: dir.lastPathComponent,
                            reason: "watchOS device symbol files — re-downloaded when the device reconnects.")
        }
    }
}
