// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import SwiftUI

// MARK: - PerformanceView

/// Phase 7 — Main performance / disk cleanup view.
struct PerformanceView: View {

    @Environment(SecurityEngine.self) private var engine
    @State private var showingCleanupProgress = false

    private var monitor: PerformanceMonitor? { engine.performanceMonitor }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                storageSection
                scanSection
                if case .readyToClean = monitor?.scanState ?? .idle {
                    categoryList
                    cleanupActionBar
                }
                if case .completed(let freed, let count) = monitor?.scanState ?? .idle {
                    completedBanner(freed: freed, count: count)
                }
            }
            .padding()
        }
        .navigationTitle("Performance")
        .sheet(isPresented: $showingCleanupProgress) {
            CleanupProgressView()
                .environment(engine)
        }
    }

    // MARK: Storage Gauge

    @ViewBuilder
    private var storageSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Disk Usage")
                .font(.headline)

            DiskUsageView()
                .environment(engine)
                .frame(height: 120)
                .cornerRadius(10)
        }
    }

    // MARK: Scan

    @ViewBuilder
    private var scanSection: some View {
        HStack {
            VStack(alignment: .leading, spacing: 4) {
                Text("Junk Files")
                    .font(.headline)
                if let lastScan = monitor?.lastScanDate {
                    Text("Last scan: \(lastScan.formatted(.relative(presentation: .named)))")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                } else {
                    Text("Not yet scanned")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            Spacer()
            scanButton
        }

        if case .scanning(let progress, let category) = monitor?.scanState ?? .idle {
            VStack(alignment: .leading, spacing: 4) {
                ProgressView(value: progress)
                if let category {
                    Text("Scanning \(category)…")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
        }

        if let monitor, monitor.foundItems.isEmpty == false {
            let reclaimable = monitor.coordinator.totalReclaimableSize
            if reclaimable > 0 {
                Label("\(ByteCountFormatter.string(fromByteCount: reclaimable, countStyle: .file)) reclaimable",
                      systemImage: "externaldrive.badge.minus")
                    .foregroundStyle(.orange)
            }
        }
    }

    @ViewBuilder
    private var scanButton: some View {
        let isScanning = monitor?.coordinator.isScanning ?? false
        Button {
            if isScanning {
                monitor?.coordinator.cancelScan()
            } else {
                Task { await monitor?.runPerformanceScan() }
            }
        } label: {
            Label(isScanning ? "Cancel" : "Scan", systemImage: isScanning ? "stop.circle" : "magnifyingglass")
        }
        .buttonStyle(.borderedProminent)
        .tint(isScanning ? .red : .accentColor)
    }

    // MARK: Category List

    @ViewBuilder
    private var categoryList: some View {
        let grouped = Dictionary(grouping: monitor?.foundItems ?? [], by: \.category)
        let sorted = grouped.sorted { a, b in
            let sa = a.value.reduce(0) { $0 + $1.size }
            let sb = b.value.reduce(0) { $0 + $1.size }
            return sa > sb
        }

        VStack(alignment: .leading, spacing: 2) {
            ForEach(sorted, id: \.key) { category, items in
                let totalSize = items.reduce(0) { $0 + $1.size }
                HStack {
                    Label(category.displayName, systemImage: category.systemImage)
                        .frame(maxWidth: .infinity, alignment: .leading)
                    Text(ByteCountFormatter.string(fromByteCount: totalSize, countStyle: .file))
                        .foregroundStyle(.secondary)
                }
                .padding(.vertical, 6)
                Divider()
            }
        }
    }

    // MARK: Cleanup Action Bar

    @ViewBuilder
    private var cleanupActionBar: some View {
        HStack {
            Button("Clean Safe Items") {
                guard let monitor else { return }
                let safeItems = monitor.foundItems.filter { $0.riskLevel == .safe }
                monitor.startCleanup(items: safeItems)
                showingCleanupProgress = true
            }
            .buttonStyle(.borderedProminent)

            Button("Review All…") {
                showingCleanupProgress = true
            }
            .buttonStyle(.bordered)
        }
    }

    // MARK: Completed Banner

    @ViewBuilder
    private func completedBanner(freed: Int64, count: Int) -> some View {
        HStack {
            Image(systemName: "checkmark.circle.fill")
                .foregroundStyle(.green)
            Text("Cleaned \(count) item(s) — freed \(ByteCountFormatter.string(fromByteCount: freed, countStyle: .file))")
        }
        .padding()
        .background(.green.opacity(0.1))
        .cornerRadius(8)
    }
}
