// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation

/// Scans Homebrew's local download cache.
struct HomebrewRule: ScanRule {
    let category = JunkCategory.homebrew
    let displayName = "Homebrew Cache"

    private static let knownBrewPaths: [URL] = [
        URL(fileURLWithPath: "/usr/local/Homebrew/Library/Homebrew/vendor/portable-ruby"),
        URL(fileURLWithPath: "/usr/local/var/homebrew"),
        URL(fileURLWithPath: "/opt/homebrew/var/homebrew"),
    ]

    private var brewCachePath: URL? {
        // `brew --cache` returns ~/Library/Caches/Homebrew
        let candidates = [
            ScanRuleHelpers.homeURL("Library", "Caches", "Homebrew"),
            URL(fileURLWithPath: "/Library/Caches/Homebrew"),
        ]
        return candidates.first { ScanRuleHelpers.exists($0) }
    }

    func scan() async -> [JunkItem] {
        guard let cacheURL = brewCachePath else { return [] }
        let size = ScanRuleHelpers.size(of: cacheURL)
        guard size > 0 else { return [] }
        return [JunkItem(url: cacheURL, size: size, category: category,
                         riskLevel: .safe, name: "Homebrew Cache",
                         reason: "Downloaded Homebrew formulae and bottles — re-downloaded on next brew update/upgrade.")]
    }
}
