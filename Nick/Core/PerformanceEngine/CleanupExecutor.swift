// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation

/// Executes a `CleanupPlan` by moving items to the Trash.
@MainActor @Observable
final class CleanupExecutor {

    private(set) var progress: Double = 0
    private(set) var freedBytes: Int64 = 0

    private let auditLogger: AuditLogger

    init(auditLogger: AuditLogger) {
        self.auditLogger = auditLogger
    }

    /// Moves each item in `plan` to the Trash, skipping paths used by any running browser.
    func execute(_ plan: CleanupPlan, runningBrowsers: [RunningBrowser]) async throws {
        progress = 0
        freedBytes = 0

        let browserCachePaths = Set(runningBrowsers.flatMap(\.cachePaths).map(\.path))
        let total = plan.itemsToClean.count
        guard total > 0 else { return }

        for (idx, item) in plan.itemsToClean.enumerated() {
            // Skip if the item is inside a running browser's cache directory
            if browserCachePaths.contains(where: { item.url.path.hasPrefix($0) }) {
                progress = Double(idx + 1) / Double(total)
                continue
            }

            do {
                var resultURL: NSURL?
                try FileManager.default.trashItem(at: item.url, resultingItemURL: &resultURL)
                freedBytes += item.size
                auditLogger.log(action: "trash", url: item.url, size: item.size)
            } catch {
                // Log failure but continue with remaining items
                auditLogger.log(action: "trash-failed: \(error.localizedDescription)", url: item.url, size: 0)
            }

            progress = Double(idx + 1) / Double(total)
        }
    }
}
