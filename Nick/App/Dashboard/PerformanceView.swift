// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import SwiftUI

/// Disk cleanup and storage recommendations backed by `PerformanceMonitor`.
struct PerformanceView: View {

    @Environment(SecurityEngine.self) private var engine
    @State private var showingCleanupProgress = false

    private var monitor: PerformanceMonitor? { engine.performanceMonitor }
    private var state: PerformanceScanState { monitor?.scanState ?? .idle }
    private var items: [JunkItem] { monitor?.foundItems ?? [] }
    private var reclaimableBytes: Int64 { monitor?.coordinator.totalReclaimableSize ?? 0 }
    private var safeItems: [JunkItem] { items.filter { $0.riskLevel == .safe } }
    private var reviewItems: [JunkItem] { items.filter { $0.riskLevel != .safe } }
    private var safeBytes: Int64 { safeItems.reduce(0) { $0 + $1.size } }

    var body: some View {
        ScrollView {
            LazyVStack(alignment: .leading, spacing: NickSpacing.xxl) {
                DiskUsageView()
                    .environment(engine)

                scanCard

                if hasScanResults {
                    recommendationsSection
                    categoriesSection
                } else if case .idle = state {
                    beforeScanSection
                }

                if case .completed(let freed, let count) = state {
                    completedBanner(freed: freed, count: count)
                }
            }
            .padding(NickSpacing.xxl)
        }
        .navigationTitle("Performance")
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Button {
                    startOrCancelScan()
                } label: {
                    Label(isScanning ? "Cancel Scan" : "Scan Storage",
                          systemImage: isScanning ? "stop.fill" : "arrow.clockwise")
                }
                .disabled(monitor == nil)
                .keyboardShortcut("r", modifiers: .command)
            }
        }
        .sheet(isPresented: $showingCleanupProgress) {
            CleanupProgressView()
                .environment(engine)
        }
    }

    // MARK: - Scan

    private var isScanning: Bool { monitor?.coordinator.isScanning ?? false }

    private var hasScanResults: Bool {
        switch state {
        case .readyToClean, .completed:
            return items.isEmpty == false
        default:
            return false
        }
    }

    private var scanCard: some View {
        VStack(alignment: .leading, spacing: NickSpacing.xl) {
            HStack(alignment: .top, spacing: NickSpacing.lg) {
                Image(systemName: scanIcon)
                    .font(.title2)
                    .foregroundStyle(scanTint)
                    .frame(width: 32)
                    .accessibilityHidden(true)

                VStack(alignment: .leading, spacing: NickSpacing.sm) {
                    Text(scanTitle)
                        .font(.headline)
                    Text(scanDetail)
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                }

                Spacer(minLength: NickSpacing.xl)

                Button(isScanning ? "Cancel" : scanButtonTitle) {
                    startOrCancelScan()
                }
                .buttonStyle(.borderedProminent)
                .tint(isScanning ? .red : .accentColor)
                .disabled(monitor == nil)
            }

            if case .scanning(let progress, let category) = state {
                VStack(alignment: .leading, spacing: NickSpacing.md) {
                    ProgressView(value: progress)
                    HStack {
                        Text(category.map { "Checking \($0)" } ?? "Checking your Mac")
                        Spacer()
                        Text("\(Int(progress * 100))%")
                            .monospacedDigit()
                    }
                    .font(.caption)
                    .foregroundStyle(.secondary)
                }
                .accessibilityElement(children: .combine)
                .accessibilityLabel("Storage scan \(Int(progress * 100)) percent complete")
            }

            if hasScanResults {
                HStack(spacing: 0) {
                    resultMetric(value: formatted(reclaimableBytes), label: "Can be reviewed")
                    Divider().frame(height: 38).padding(.horizontal, NickSpacing.xl)
                    resultMetric(value: "\(items.count)", label: "Items found")
                    Divider().frame(height: 38).padding(.horizontal, NickSpacing.xl)
                    resultMetric(value: formatted(safeBytes), label: "Safe to clean")
                    Spacer()
                }
            }
        }
        .padding(NickSpacing.xl)
        .nickCard()
    }

    private func resultMetric(value: String, label: String) -> some View {
        VStack(alignment: .leading, spacing: NickSpacing.xs) {
            Text(value)
                .font(.title3.weight(.semibold))
                .monospacedDigit()
            Text(label)
                .font(.caption)
                .foregroundStyle(.secondary)
        }
    }

    private var scanIcon: String {
        switch state {
        case .scanning: return "magnifyingglass"
        case .readyToClean: return "sparkles"
        case .completed: return "checkmark.circle.fill"
        default: return "internaldrive"
        }
    }

    private var scanTint: Color {
        switch state {
        case .readyToClean: return .orange
        case .completed: return .green
        default: return .accentColor
        }
    }

    private var scanTitle: String {
        switch state {
        case .scanning: return "Scanning storage"
        case .readyToClean: return reclaimableBytes > 0 ? "Cleanup suggestions are ready" : "Your storage looks tidy"
        case .completed: return "Cleanup finished"
        default: return "Find space you can safely reclaim"
        }
    }

    private var scanDetail: String {
        switch state {
        case .scanning:
            return "Nick is checking caches, old downloads, backups, recordings, and developer files."
        case .readyToClean:
            return "Nothing is removed until you review it. Nick separates safe cleanup from files that may be valuable."
        case .completed:
            return "Run another scan whenever you want to check for newly created files."
        default:
            if let date = monitor?.lastScanDate {
                return "Last checked \(date.formatted(.relative(presentation: .named)))."
            }
            return "Reviewable files stay selected separately from items that are safe to recreate."
        }
    }

    private var scanButtonTitle: String {
        switch state {
        case .readyToClean, .completed: return "Scan Again"
        default: return "Scan"
        }
    }

    private func startOrCancelScan() {
        if isScanning {
            monitor?.coordinator.cancelScan()
        } else {
            Task { await monitor?.runPerformanceScan() }
        }
    }

    // MARK: - Recommendations

    private var recommendationsSection: some View {
        VStack(alignment: .leading, spacing: NickSpacing.lg) {
            sectionHeading("Recommendations", detail: "Start with safe cleanup, then review personal files separately.")

            VStack(spacing: 0) {
                if safeItems.isEmpty == false {
                    recommendationRow(
                        icon: "checkmark.shield.fill",
                        tint: .green,
                        title: "Clean files macOS and apps can recreate",
                        detail: "\(safeItems.count) safe items can free \(formatted(safeBytes)).",
                        actionTitle: "Clean Safe Items"
                    ) {
                        monitor?.startCleanup(items: safeItems)
                        showingCleanupProgress = true
                    }
                }

                if reviewItems.isEmpty == false {
                    if safeItems.isEmpty == false { Divider().padding(.leading, 52) }
                    recommendationRow(
                        icon: "eye.fill",
                        tint: .orange,
                        title: "Review files that may still matter",
                        detail: "\(reviewItems.count) items include downloads, backups, recordings, or advanced data.",
                        actionTitle: "Review"
                    ) {
                        showingCleanupProgress = true
                    }
                }
            }
            .nickCard()
        }
    }

    private func recommendationRow(
        icon: String,
        tint: Color,
        title: String,
        detail: String,
        actionTitle: String,
        action: @escaping () -> Void
    ) -> some View {
        HStack(spacing: NickSpacing.lg) {
            Image(systemName: icon)
                .font(.title3)
                .foregroundStyle(tint)
                .frame(width: 28)
                .accessibilityHidden(true)

            VStack(alignment: .leading, spacing: NickSpacing.xs) {
                Text(title).font(.subheadline.weight(.semibold))
                Text(detail)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            Spacer(minLength: NickSpacing.xl)
            Button(actionTitle, action: action)
        }
        .padding(NickSpacing.xl)
    }

    // MARK: - Categories

    private var categoriesSection: some View {
        let groups = groupedCategories
        return VStack(alignment: .leading, spacing: NickSpacing.lg) {
            sectionHeading("What Nick found", detail: "\(groups.count) categories, sorted by recoverable space.")

            VStack(spacing: 0) {
                ForEach(Array(groups.enumerated()), id: \.element.category) { index, group in
                    categoryRow(group)
                    if index < groups.count - 1 {
                        Divider().padding(.leading, 52)
                    }
                }
            }
            .nickCard()
        }
    }

    private struct CategorySummary {
        let category: JunkCategory
        let items: [JunkItem]
        let size: Int64
    }

    private var groupedCategories: [CategorySummary] {
        Dictionary(grouping: items, by: \.category)
            .map { CategorySummary(category: $0.key, items: $0.value, size: $0.value.reduce(0) { $0 + $1.size }) }
            .sorted { $0.size > $1.size }
    }

    private func categoryRow(_ group: CategorySummary) -> some View {
        HStack(spacing: NickSpacing.lg) {
            Image(systemName: group.category.systemImage)
                .font(.title3)
                .foregroundStyle(.mint)
                .frame(width: 28)
                .accessibilityHidden(true)

            VStack(alignment: .leading, spacing: NickSpacing.xs) {
                Text(group.category.displayName)
                    .font(.subheadline.weight(.medium))
                Text("\(group.items.count) \(group.items.count == 1 ? "item" : "items")")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            Spacer()

            Text(formatted(group.size))
                .font(.subheadline.monospacedDigit())
                .foregroundStyle(.secondary)
        }
        .padding(NickSpacing.xl)
    }

    // MARK: - Empty and completed

    private var beforeScanSection: some View {
        VStack(alignment: .leading, spacing: NickSpacing.lg) {
            sectionHeading("Nick can check", detail: "The scan only reports findings. You decide what gets removed.")

            HStack(alignment: .top, spacing: NickSpacing.xxl) {
                scanCapability("arrow.triangle.2.circlepath", "Recreatable data", "Caches, logs, temporary builds, and package downloads.")
                scanCapability("externaldrive", "Old large data", "Backups, simulators, installers, archives, and Docker data.")
                scanCapability("person.crop.circle.badge.questionmark", "Personal files", "Downloads, recordings, duplicates, and attachments are review-only.")
            }
            .padding(NickSpacing.xl)
            .nickCard()
        }
    }

    private func scanCapability(_ icon: String, _ title: String, _ detail: String) -> some View {
        VStack(alignment: .leading, spacing: NickSpacing.md) {
            Image(systemName: icon)
                .font(.title2)
                .foregroundStyle(.mint)
                .accessibilityHidden(true)
            Text(title).font(.subheadline.weight(.semibold))
            Text(detail)
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private func completedBanner(freed: Int64, count: Int) -> some View {
        Label("Removed \(count) \(count == 1 ? "item" : "items") and freed \(formatted(freed)).",
              systemImage: "checkmark.circle.fill")
            .foregroundStyle(.green)
            .padding(NickSpacing.xl)
            .frame(maxWidth: .infinity, alignment: .leading)
            .nickCard()
    }

    private func sectionHeading(_ title: String, detail: String) -> some View {
        VStack(alignment: .leading, spacing: NickSpacing.xs) {
            Text(title).font(.headline)
            Text(detail)
                .font(.caption)
                .foregroundStyle(.secondary)
        }
    }

    private func formatted(_ bytes: Int64) -> String {
        ByteCountFormatter.string(fromByteCount: bytes, countStyle: .file)
    }
}
