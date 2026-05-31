// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation

/// Scans `~/.gradle/caches` for Gradle/Android build cache.
struct GradleAndroidCacheRule: ScanRule {
    let category = JunkCategory.androidGradleCache
    let displayName = "Gradle / Android Cache"

    func scan() async -> [JunkItem] {
        var items: [JunkItem] = []

        let candidates: [(URL, String)] = [
            (ScanRuleHelpers.homeURL(".gradle", "caches"),                    "Gradle Caches"),
            (ScanRuleHelpers.homeURL(".android", "build-cache"),              "Android Build Cache"),
            (ScanRuleHelpers.homeURL("Library", "Android", "sdk", ".temp"),   "Android SDK Temp"),
        ]

        for (url, label) in candidates {
            guard ScanRuleHelpers.exists(url) else { continue }
            let size = ScanRuleHelpers.size(of: url)
            guard size > 0 else { continue }
            items.append(JunkItem(url: url, size: size, category: category,
                                  riskLevel: .safe, name: label,
                                  reason: "Gradle/Android build cache — regenerated on next build."))
        }
        return items
    }
}
