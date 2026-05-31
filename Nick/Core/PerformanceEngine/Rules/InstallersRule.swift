// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation

/// Scans `~/Downloads` for `.dmg`, `.pkg`, and `.mpkg` installer files older than 30 days.
struct InstallersRule: ScanRule {
    let category = JunkCategory.installers
    let displayName = "Old Installers"

    private static let installerExtensions: Set<String> = ["dmg", "pkg", "mpkg"]
    private static let ageCutoff: TimeInterval = 30 * 86400 // 30 days

    func scan() async -> [JunkItem] {
        let downloads = ScanRuleHelpers.homeURL("Downloads")
        guard ScanRuleHelpers.exists(downloads) else { return [] }

        let cutoff = Date().addingTimeInterval(-Self.ageCutoff)
        return ScanRuleHelpers.children(of: downloads).compactMap { url in
            guard Self.installerExtensions.contains(url.pathExtension.lowercased()) else { return nil }
            guard let modified = ScanRuleHelpers.lastModified(url), modified < cutoff else { return nil }
            let size = ScanRuleHelpers.size(of: url)
            guard size > 0 else { return nil }
            return JunkItem(url: url, size: size, category: category,
                            riskLevel: .safe, name: url.lastPathComponent,
                            reason: "Installer file more than 30 days old — the application is already installed.")
        }
    }
}
