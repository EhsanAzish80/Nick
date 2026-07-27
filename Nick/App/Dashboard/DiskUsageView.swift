// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import SwiftUI

/// A calm, data-first summary of the boot volume.
struct DiskUsageView: View {

    @Environment(SecurityEngine.self) private var engine
    @State private var storageMonitor = StorageMonitor()

    private var reclaimableBytes: Int64 {
        engine.performanceMonitor?.coordinator.totalReclaimableSize ?? 0
    }

    private var usedFraction: Double {
        guard storageMonitor.totalDiskBytes > 0 else { return 0 }
        return min(1, max(0, Double(storageMonitor.usedDiskBytes) / Double(storageMonitor.totalDiskBytes)))
    }

    private var pressureTint: Color {
        switch usedFraction {
        case 0..<0.75: return .mint
        case 0..<0.9: return .orange
        default: return .red
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: NickSpacing.xl) {
            HStack(alignment: .firstTextBaseline) {
                VStack(alignment: .leading, spacing: NickSpacing.xs) {
                    Text("Macintosh HD")
                        .font(.headline)
                    Text(storageSummary)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }

                Spacer()

                Text("\(Int(usedFraction * 100))% used")
                    .font(.subheadline.weight(.semibold))
                    .monospacedDigit()
                    .foregroundStyle(pressureTint)
            }

            GeometryReader { proxy in
                ZStack(alignment: .leading) {
                    Capsule().fill(.quaternary)
                    Capsule()
                        .fill(pressureTint)
                        .frame(width: proxy.size.width * usedFraction)
                }
            }
            .frame(height: 10)
            .accessibilityElement()
            .accessibilityLabel("Disk usage")
            .accessibilityValue("\(Int(usedFraction * 100)) percent used")

            HStack(spacing: 0) {
                metric(formatted(storageMonitor.usedDiskBytes), "Used", pressureTint)
                Spacer()
                metric(formatted(storageMonitor.freeDiskBytes), "Available", .secondary)
                if reclaimableBytes > 0 {
                    Spacer()
                    metric(formatted(reclaimableBytes), "Found by Nick", .orange)
                }
            }
        }
        .padding(NickSpacing.xl)
        .nickCard()
        .task { storageMonitor.refresh() }
    }

    private var storageSummary: String {
        guard storageMonitor.totalDiskBytes > 0 else { return "Reading storage…" }
        if usedFraction >= 0.9 {
            return "Storage is nearly full. Review larger findings first."
        }
        if usedFraction >= 0.75 {
            return "Storage is filling up, but you still have room available."
        }
        return "\(formatted(storageMonitor.totalDiskBytes)) total capacity"
    }

    private func metric(_ value: String, _ label: String, _ tint: Color) -> some View {
        VStack(alignment: .leading, spacing: NickSpacing.xs) {
            Text(value)
                .font(.title3.weight(.semibold))
                .monospacedDigit()
                .foregroundStyle(tint)
            Text(label)
                .font(.caption)
                .foregroundStyle(.secondary)
        }
    }

    private func formatted(_ bytes: Int64) -> String {
        ByteCountFormatter.string(fromByteCount: bytes, countStyle: .file)
    }
}
