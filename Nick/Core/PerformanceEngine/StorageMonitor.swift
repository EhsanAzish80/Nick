// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation

/// Reads the current disk usage for the boot volume.
@MainActor @Observable
final class StorageMonitor {

    private(set) var totalDiskBytes: Int64 = 0
    private(set) var usedDiskBytes: Int64 = 0
    private(set) var freeDiskBytes: Int64 = 0

    func refresh() {
        let homeURL = ScanRuleHelpers.home
        guard let values = try? homeURL.resourceValues(forKeys: [
            .volumeTotalCapacityKey,
            .volumeAvailableCapacityKey,
        ]) else { return }

        totalDiskBytes = Int64(values.volumeTotalCapacity ?? 0)
        freeDiskBytes  = Int64(values.volumeAvailableCapacity ?? 0)
        usedDiskBytes  = totalDiskBytes - freeDiskBytes
    }
}
