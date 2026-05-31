// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation

/// Builds a `CleanupPlan` from a list of junk items and a set of selected item IDs.
final class CleanupPlanner: Sendable {
    func plan(from items: [JunkItem], selectedIDs: Set<UUID>) -> CleanupPlan {
        let selected = items.filter { selectedIDs.contains($0.id) }
        return CleanupPlan(items: selected)
    }
}
