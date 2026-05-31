// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation

/// Scans Steam's download cache and re-distributable content.
struct SteamCacheRule: ScanRule {
    let category = JunkCategory.applicationCaches
    let displayName = "Steam Cache"

    private let steamPaths: [(URL, String)] = [
        (ScanRuleHelpers.homeURL("Library", "Application Support", "Steam", "steamapps", "downloading"), "Steam In-Progress Downloads"),
        (ScanRuleHelpers.homeURL("Library", "Application Support", "Steam", "depotcache"),               "Steam Depot Cache"),
        (ScanRuleHelpers.homeURL("Library", "Caches", "com.valvesoftware.steam"),                        "Steam App Cache"),
    ]

    func scan() async -> [JunkItem] {
        steamPaths.compactMap { (url, label) in
            guard ScanRuleHelpers.exists(url) else { return nil }
            let size = ScanRuleHelpers.size(of: url)
            guard size > 0 else { return nil }
            return JunkItem(url: url, size: size, category: category,
                            riskLevel: .safe, name: label,
                            reason: "Steam cache files — re-downloaded when needed.")
        }
    }
}
