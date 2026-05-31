// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation

// MARK: - PerformanceScanState

/// Current state of the `PerformanceCoordinator` scan / cleanup pipeline.
/// Renamed from Junkyard's `ScanState` to avoid collisions with Nick's existing types.
enum PerformanceScanState: Sendable {
    case idle
    case scanning(progress: Double, currentCategory: String?)
    case readyToClean(totalSize: Int64, itemCount: Int)
    case cleaning(progress: Double, freedSize: Int64)
    case completed(freedSize: Int64, itemCount: Int)

    var displayTitle: String {
        switch self {
        case .idle:                               return "Ready"
        case .scanning:                           return "Scanning…"
        case .readyToClean:                       return "Ready to Clean"
        case .cleaning:                           return "Cleaning…"
        case .completed:                          return "Done"
        }
    }

    var isActive: Bool {
        switch self {
        case .scanning, .cleaning: return true
        default: return false
        }
    }
}
