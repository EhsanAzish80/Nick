// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import SwiftUI

// MARK: - AlertDetailView

/// Full-detail sheet for a single `ThreatAlert`.
///
/// Shows the score, contributing signals, recommended action, and a link
/// to copy the alert JSON for reporting.
struct AlertDetailView: View {

    let alert: ThreatAlert
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            // MARK: Header
            HStack(alignment: .top) {
                VStack(alignment: .leading, spacing: 4) {
                    Text(alert.title)
                        .font(.headline)
                    HStack {
                        SeverityBadge(severity: alert.severity)
                        Text(String(format: "Confidence: %.0f%%", alert.score * 100))
                            .font(.caption)
                            .foregroundStyle(.secondary)
                        Spacer()
                        Text(alert.timestamp.formatted(date: .abbreviated, time: .shortened))
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
                Spacer()
                Button { dismiss() } label: {
                    Image(systemName: "xmark.circle.fill")
                        .foregroundStyle(.secondary)
                }
                .buttonStyle(.plain)
            }
            .padding()

            Divider()

            ScrollView {
                VStack(alignment: .leading, spacing: 16) {

                    // Description
                    GroupBox("Description") {
                        Text(alert.description)
                            .font(.callout)
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }

                    // Recommended action
                    GroupBox {
                        HStack(alignment: .top, spacing: 8) {
                            Image(systemName: "lightbulb.fill")
                                .foregroundStyle(.yellow)
                            Text(alert.recommendedAction)
                                .font(.callout)
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                    } label: {
                        Text("Recommended Action")
                    }

                    // Contributing signals
                    if !alert.contributingSignals.isEmpty {
                        GroupBox("Contributing Signals (\(alert.contributingSignals.count))") {
                            VStack(alignment: .leading, spacing: 6) {
                                ForEach(alert.contributingSignals) { signal in
                                    SignalRow(signal: signal)
                                    if signal.id != alert.contributingSignals.last?.id {
                                        Divider()
                                    }
                                }
                            }
                        }
                    }
                }
                .padding()
            }

            Divider()

            // Footer
            HStack {
                Button("Copy JSON") { copyJSON() }
                    .buttonStyle(.plain)
                    .font(.caption)
                Spacer()
                Button("Dismiss") { dismiss() }
                    .buttonStyle(.borderedProminent)
                    .controlSize(.small)
            }
            .padding()
        }
        .frame(width: 500, height: 520)
        .background(.ultraThinMaterial)
    }

    // MARK: - Private

    private func copyJSON() {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        guard let data = try? encoder.encode(alert),
              let string = String(data: data, encoding: .utf8)
        else { return }
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(string, forType: .string)
    }
}

// MARK: - SeverityBadge

private struct SeverityBadge: View {
    let severity: SignalSeverity

    var body: some View {
        Text(severity.displayName)
            .font(.caption2.bold())
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .background(color.opacity(0.15), in: Capsule())
            .foregroundStyle(color)
    }

    private var color: Color {
        switch severity {
        case .info:             .secondary
        case .low:              .blue
        case .medium:           .orange
        case .high, .critical:  .red
        }
    }
}

// MARK: - SignalRow

private struct SignalRow: View {
    let signal: ThreatSignal

    var body: some View {
        HStack(alignment: .top, spacing: 6) {
            Image(systemName: signal.source.systemImage)
                .foregroundStyle(.secondary)
                .frame(width: 16)
            VStack(alignment: .leading, spacing: 1) {
                Text(signal.title)
                    .font(.caption.bold())
                Text(signal.description)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(2)
            }
        }
    }
}
