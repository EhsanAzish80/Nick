// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation

// MARK: - CleanupPlan

/// The set of items the user has approved for removal.
///
/// Built by `CleanupPlanner` and executed by `CleanupExecutor`.
struct CleanupPlan: Sendable {
    /// Items to be moved to Trash.
    let itemsToClean: [JunkItem]
    /// Total bytes that will be freed.
    let totalBytes: Int64
    /// Timestamp when the plan was created.
    let createdAt: Date

    init(items: [JunkItem]) {
        self.itemsToClean = items
        self.totalBytes   = items.reduce(0) { $0 + $1.size }
        self.createdAt    = Date()
    }

    var isEmpty: Bool { itemsToClean.isEmpty }
}
