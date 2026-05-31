// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import SwiftUI

// MARK: - CleanupProgressView

/// Phase 7 — Modal sheet showing cleanup progress or a review list.
struct CleanupProgressView: View {

    @Environment(SecurityEngine.self) private var engine
    @Environment(\.dismiss) private var dismiss

    private var monitor: PerformanceMonitor? { engine.performanceMonitor }

    var body: some View {
        NavigationStack {
            Group {
                switch monitor?.scanState ?? .idle {
                case .cleaning(let progress, let freedSize):
                    cleaningView(progress: progress, freed: freedSize)
                case .completed(let freed, let count):
                    completedView(freed: freed, count: count)
                case .readyToClean(let totalSize, let itemCount):
                    reviewView(totalSize: totalSize, itemCount: itemCount)
                default:
                    idleView
                }
            }
            .navigationTitle("Cleanup")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Close") { dismiss() }
                }
            }
        }
        .frame(minWidth: 480, minHeight: 400)
    }

    // MARK: Cleaning

    @ViewBuilder
    private func cleaningView(progress: Double, freed: Int64) -> some View {
        VStack(spacing: 20) {
            Spacer()
            ProgressView(value: progress)
                .progressViewStyle(.linear)
                .padding(.horizontal, 40)

            Text("Cleaning… \(Int(progress * 100))%")
                .font(.headline)

            Text("\(ByteCountFormatter.string(fromByteCount: freed, countStyle: .file)) freed so far")
                .foregroundStyle(.secondary)

            Button("Cancel") {
                monitor?.coordinator.cancelScan()
                dismiss()
            }
            .buttonStyle(.bordered)
            Spacer()
        }
    }

    // MARK: Completed

    @ViewBuilder
    private func completedView(freed: Int64, count: Int) -> some View {
        VStack(spacing: 20) {
            Spacer()
            Image(systemName: "checkmark.seal.fill")
                .font(.system(size: 64))
                .foregroundStyle(.green)

            Text("All done!")
                .font(.largeTitle.bold())

            Text("Removed \(count) item(s) and freed \(ByteCountFormatter.string(fromByteCount: freed, countStyle: .file)).")
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)

            Button("Done") { dismiss() }
                .buttonStyle(.borderedProminent)
            Spacer()
        }
    }

    // MARK: Review list

    @ViewBuilder
    private func reviewView(totalSize: Int64, itemCount: Int) -> some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                Text("\(itemCount) items · \(ByteCountFormatter.string(fromByteCount: totalSize, countStyle: .file)) total")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .padding()
                Spacer()
            }

            List(monitor?.foundItems ?? [], id: \.id) { item in
                ReviewItemRow(item: item, isSelected: Binding(
                    get: { monitor?.coordinator.selectedItemIDs.contains(item.id) ?? false },
                    set: { selected in
                        if selected {
                            monitor?.coordinator.selectedItemIDs.insert(item.id)
                        } else {
                            monitor?.coordinator.selectedItemIDs.remove(item.id)
                        }
                    }
                ))
            }

            Divider()

            HStack {
                Button("Clean Selected") {
                    monitor?.coordinator.startCleanup()
                }
                .buttonStyle(.borderedProminent)
                .disabled(monitor?.coordinator.selectedItemIDs.isEmpty ?? true)

                Button("Cancel") { dismiss() }
                    .buttonStyle(.bordered)
            }
            .padding()
        }
    }

    // MARK: Idle

    @ViewBuilder
    private var idleView: some View {
        VStack {
            Spacer()
            Text("No scan in progress.")
                .foregroundStyle(.secondary)
            Spacer()
        }
    }
}

// MARK: - ReviewItemRow

private struct ReviewItemRow: View {
    let item: JunkItem
    @Binding var isSelected: Bool

    var body: some View {
        HStack {
            Toggle("", isOn: $isSelected)
                .toggleStyle(.checkbox)
                .labelsHidden()

            VStack(alignment: .leading, spacing: 2) {
                Text(item.name)
                    .lineLimit(1)
                Text(item.reason)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(2)
            }
            Spacer()
            VStack(alignment: .trailing, spacing: 2) {
                Text(ByteCountFormatter.string(fromByteCount: item.size, countStyle: .file))
                    .font(.caption.monospacedDigit())
                riskBadge(item.riskLevel)
            }
        }
    }

    @ViewBuilder
    private func riskBadge(_ level: RiskLevel) -> some View {
        switch level {
        case .safe:
            Text("Safe").font(.caption2).padding(.horizontal, 5).padding(.vertical, 2)
                .background(.green.opacity(0.15)).cornerRadius(4).foregroundStyle(.green)
        case .review:
            Text("Review").font(.caption2).padding(.horizontal, 5).padding(.vertical, 2)
                .background(.orange.opacity(0.15)).cornerRadius(4).foregroundStyle(.orange)
        case .advanced:
            Text("Advanced").font(.caption2).padding(.horizontal, 5).padding(.vertical, 2)
                .background(.red.opacity(0.15)).cornerRadius(4).foregroundStyle(.red)
        }
    }
}
