// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation

// MARK: - ScanRule

/// Contract for every scan rule in the Performance Engine.
///
/// Each rule is responsible for scanning one logical category of junk
/// (e.g. Xcode DerivedData, browser caches, old installers) and returning
/// a list of `JunkItem` values. Rules are stateless — they perform their
/// scan in `scan()` and return results; the `PerformanceCoordinator` owns
/// the aggregated state.
///
/// All rules are `Sendable` so they can be run concurrently via `TaskGroup`.
protocol ScanRule: Sendable {

    /// The category this rule belongs to.
    var category: JunkCategory { get }

    /// Display name shown in scan progress and rule list.
    var displayName: String { get }

    /// SF Symbol shown alongside this rule in the UI.
    var systemImage: String { get }

    /// Scans for junk and returns found items.
    ///
    /// Implementations must be non-blocking for the caller — heavy I/O should
    /// use `Task.yield()` periodically to allow cooperative cancellation.
    func scan() async -> [JunkItem]
}

// MARK: - ScanRule Default Implementations

extension ScanRule {
    var systemImage: String { category.systemImage }

    /// Convenience: returns the total bytes of all items this rule would find.
    func totalSize() async -> Int64 {
        await scan().reduce(0) { $0 + $1.size }
    }
}
