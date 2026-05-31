// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation

/// Reports Docker volume and image storage footprint.
struct DockerInsightRule: ScanRule {
    let category = JunkCategory.docker
    let displayName = "Docker"

    private let dockerPaths: [(URL, String)] = [
        (ScanRuleHelpers.homeURL("Library", "Containers", "com.docker.docker", "Data"),  "Docker Data"),
        (ScanRuleHelpers.homeURL(".docker"),                                              "Docker Config & Cache"),
    ]

    func scan() async -> [JunkItem] {
        dockerPaths.compactMap { (url, label) in
            guard ScanRuleHelpers.exists(url) else { return nil }
            let size = ScanRuleHelpers.size(of: url)
            guard size > 100_000_000 else { return nil } // > 100 MB
            return JunkItem(url: url, size: size, category: category,
                            riskLevel: .advanced, name: label,
                            reason: "Docker storage — use 'docker system prune' before deleting manually.")
        }
    }
}
