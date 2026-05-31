// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation

/// Reports the size of the GarageBand / Logic Pro sound library (system-wide).
struct AppleSoundLibraryRule: ScanRule {
    let category = JunkCategory.applicationCaches
    let displayName = "Apple Sound Libraries"

    private let paths: [(URL, String)] = [
        (URL(fileURLWithPath: "/Library/Application Support/GarageBand"),           "GarageBand Sound Library"),
        (URL(fileURLWithPath: "/Library/Application Support/Logic"),                "Logic Pro Sound Library"),
        (URL(fileURLWithPath: "/Library/Audio/Apple Loops"),                        "Apple Loops"),
        (ScanRuleHelpers.homeURL("Music", "Audio Music Apps", "Plug-Ins"),          "User Audio Plug-Ins"),
    ]

    func scan() async -> [JunkItem] {
        paths.compactMap { (url, label) in
            guard ScanRuleHelpers.exists(url) else { return nil }
            let size = ScanRuleHelpers.size(of: url)
            guard size > 50_000_000 else { return nil }
            return JunkItem(url: url, size: size, category: category,
                            riskLevel: .advanced, name: label,
                            reason: "Apple sound library — remove only if you no longer use GarageBand or Logic Pro. Re-download from the app itself.")
        }
    }
}
