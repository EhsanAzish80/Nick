// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation

/// Scans Adobe application caches (Photoshop, Lightroom, Premiere, After Effects).
struct AdobeCacheRule: ScanRule {
    let category = JunkCategory.applicationCaches
    let displayName = "Adobe Cache"

    private let adobePaths: [(URL, String)] = [
        (ScanRuleHelpers.homeURL("Library", "Application Support", "Adobe", "Common", "Media Cache Files"), "Adobe Media Cache"),
        (ScanRuleHelpers.homeURL("Library", "Application Support", "Adobe", "Common", "Media Cache"),       "Adobe Media Cache DB"),
        (ScanRuleHelpers.homeURL("Library", "Caches", "Adobe"),                                             "Adobe Caches"),
        (ScanRuleHelpers.homeURL("Library", "Application Support", "Adobe", "CameraRaw", "Cache"),          "Camera Raw Cache"),
    ]

    func scan() async -> [JunkItem] {
        adobePaths.compactMap { (url, label) in
            guard ScanRuleHelpers.exists(url) else { return nil }
            let size = ScanRuleHelpers.size(of: url)
            guard size > 0 else { return nil }
            return JunkItem(url: url, size: size, category: category,
                            riskLevel: .safe, name: label,
                            reason: "Adobe cache — regenerated when you open Adobe applications.")
        }
    }
}
