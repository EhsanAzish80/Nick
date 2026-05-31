// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation

// MARK: - MemoryBlock

/// Represents one disk-usage segment in the `DiskUsageView` visual grid.
///
/// Each block corresponds to either one `JunkItem` or a group of items
/// in the same category, scaled to fill available UI space proportionally.
struct MemoryBlock: Identifiable, Sendable {
    let id: UUID
    let label: String
    let sizeBytes: Int64
    let category: JunkCategory
    /// Normalised fraction of total disk used (0.0–1.0).
    let fraction: Double

    init(label: String, sizeBytes: Int64, category: JunkCategory, totalDiskBytes: Int64) {
        self.id        = UUID()
        self.label     = label
        self.sizeBytes = sizeBytes
        self.category  = category
        self.fraction  = totalDiskBytes > 0
            ? Double(sizeBytes) / Double(totalDiskBytes)
            : 0
    }
}
