// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation

/// Scans for Python `__pycache__` directories and `.pyc` files.
struct PythonCacheRule: ScanRule {
    let category = JunkCategory.scriptingCaches
    let displayName = "Python Cache"

    private let searchRoots: [URL] = [
        ScanRuleHelpers.homeURL("Documents"),
        ScanRuleHelpers.homeURL("Developer"),
        ScanRuleHelpers.homeURL("Projects"),
        ScanRuleHelpers.homeURL(".venv"),
    ]

    func scan() async -> [JunkItem] {
        let fm = FileManager.default
        var items: [JunkItem] = []

        // pip/pip3 cache
        let pipCache = ScanRuleHelpers.homeURL("Library", "Caches", "pip")
        if ScanRuleHelpers.exists(pipCache) {
            let size = ScanRuleHelpers.size(of: pipCache)
            if size > 0 {
                items.append(JunkItem(url: pipCache, size: size, category: category,
                                      riskLevel: .safe, name: "pip Cache",
                                      reason: "pip wheel cache — safe to remove, re-downloaded on next install."))
            }
        }

        // virtualenv caches in known locations
        let venvCache = ScanRuleHelpers.homeURL(".venv")
        if ScanRuleHelpers.exists(venvCache) {
            let size = ScanRuleHelpers.size(of: venvCache)
            if size > 0 {
                items.append(JunkItem(url: venvCache, size: size, category: category,
                                      riskLevel: .review, name: "Python venv (~/.venv)",
                                      reason: "Python virtual environment — remove only if no longer needed."))
            }
        }

        return items
    }
}
