// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import SwiftUI

// MARK: - DiskUsageView

/// Phase 7 — Visual representation of disk usage as proportional colour blocks.
struct DiskUsageView: View {

    @Environment(SecurityEngine.self) private var engine
    @State private var storageMonitor = StorageMonitor()

    var body: some View {
        GeometryReader { proxy in
            ZStack(alignment: .leading) {
                RoundedRectangle(cornerRadius: 8)
                    .fill(.quaternary)

                if storageMonitor.totalDiskBytes > 0 {
                    let usedFraction = min(1, Double(storageMonitor.usedDiskBytes) / Double(storageMonitor.totalDiskBytes))
                    let reclaimFraction: Double = {
                        guard let monitor = engine.performanceMonitor,
                              storageMonitor.totalDiskBytes > 0 else { return 0 }
                        return min(usedFraction, Double(monitor.coordinator.totalReclaimableSize) / Double(storageMonitor.totalDiskBytes))
                    }()

                    HStack(spacing: 0) {
                        // Used (excluding reclaimable)
                        Rectangle()
                            .fill(.red.opacity(0.7))
                            .frame(width: proxy.size.width * (usedFraction - reclaimFraction))

                        // Reclaimable
                        Rectangle()
                            .fill(.orange.opacity(0.8))
                            .frame(width: proxy.size.width * reclaimFraction)
                    }
                    .cornerRadius(8)
                }
            }
            .overlay(alignment: .bottom) {
                labels
                    .padding(.bottom, 6)
            }
        }
        .task {
            storageMonitor.refresh()
        }
    }

    @ViewBuilder
    private var labels: some View {
        HStack {
            legendDot(.red.opacity(0.7), "Used: \(ByteCountFormatter.string(fromByteCount: storageMonitor.usedDiskBytes, countStyle: .file))")
            legendDot(.orange.opacity(0.8), "Reclaimable: \(reclaimableLabel)")
            legendDot(.quaternary, "Free: \(ByteCountFormatter.string(fromByteCount: storageMonitor.freeDiskBytes, countStyle: .file))")
        }
        .font(.caption2)
        .padding(.horizontal, 8)
    }

    private var reclaimableLabel: String {
        let bytes = engine.performanceMonitor?.coordinator.totalReclaimableSize ?? 0
        return ByteCountFormatter.string(fromByteCount: bytes, countStyle: .file)
    }

    @ViewBuilder
    private func legendDot(_ color: Color, _ label: String) -> some View {
        HStack(spacing: 4) {
            Circle().fill(color).frame(width: 8, height: 8)
            Text(label)
        }
    }
}
