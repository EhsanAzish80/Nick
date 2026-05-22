// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import SwiftUI

// MARK: - AlertListView

/// Shows all `ThreatAlert` values produced by `ThreatCorrelator`, sorted by
/// score (highest first).
///
/// Each alert is a flat list row (no card background, no shadow). Rows are
/// separated by a `borderSubtle` divider. Copy JSON and Dismiss actions are
/// inline on every row.
struct AlertListView: View {

    @Environment(SecurityEngine.self) private var engine

    var body: some View {
        if engine.alerts.isEmpty {
            emptyState
        } else {
            ScrollView {
                VStack(spacing: 0) {
                    ForEach(engine.alerts) { alert in
                        AlertRow(alert: alert)
                        if alert.id != engine.alerts.last?.id {
                            Divider()
                                .overlay(Color.borderSubtle)
                        }
                    }
                }
            }
        }
    }

    // MARK: - Empty state

    private var emptyState: some View {
        VStack(spacing: NickSpacing.lg) {
            Image(systemName: "bell.slash")
                .font(.system(size: 32))
                .foregroundStyle(Color.textTertiary)
            Text("No alerts")
                .font(.nickSubtitle)
                .foregroundStyle(Color.textPrimary)
            Text(engine.isScanning
                 ? "Scan in progress…"
                 : "No threats detected in the last scan.")
                .font(.nickBodySmall)
                .foregroundStyle(Color.textSecondary)
                .multilineTextAlignment(.center)
        }
        .padding(NickSpacing.xxl)
    }
}

// MARK: - AlertRow

/// Flat list row for one `ThreatAlert`. No card background — content only.
private struct AlertRow: View {

    let alert: ThreatAlert
    @Environment(SecurityEngine.self) private var engine

    var body: some View {
        VStack(alignment: .leading, spacing: NickSpacing.md) {

            // Line 1 — icon + title
            HStack(alignment: .top, spacing: NickSpacing.md) {
                Image(systemName: alert.severity.systemImage)
                    .font(.system(size: NickLayout.iconSizeLarge))
                    .foregroundStyle(alert.severity.statusColor)
                Text(alert.title)
                    .font(.nickBodyMedium)
                    .foregroundStyle(Color.textPrimary)
                    .fixedSize(horizontal: false, vertical: true)
            }

            // Line 2 — badge · confidence · timestamp
            HStack(spacing: NickSpacing.xs) {
                SeverityBadge(severity: alert.severity)
                Text("·")
                    .font(.nickCaption)
                    .foregroundStyle(Color.textTertiary)
                Text(String(format: "%.0f%% confidence", alert.score * 100))
                    .font(.nickMono)
                    .foregroundStyle(Color.textSecondary)
                Text("·")
                    .font(.nickCaption)
                    .foregroundStyle(Color.textTertiary)
                Text(alert.timestamp.formatted(date: .omitted, time: .shortened))
                    .font(.nickMonoSmall)
                    .foregroundStyle(Color.textTertiary)
                Spacer()
            }

            // Description
            Text(alert.description)
                .font(.nickBody)
                .foregroundStyle(Color.textPrimary)
                .fixedSize(horizontal: false, vertical: true)

            // Contributing signals — flat list, ▸ prefix, 20pt indent
            if !alert.contributingSignals.isEmpty {
                VStack(alignment: .leading, spacing: NickSpacing.sm) {
                    ForEach(alert.contributingSignals.prefix(5)) { signal in
                        HStack(alignment: .top, spacing: NickSpacing.sm) {
                            Text("▸")
                                .font(.nickBodySmall)
                                .foregroundStyle(Color.textTertiary)
                            Text(signal.title)
                                .font(.nickBodySmall)
                                .foregroundStyle(Color.textSecondary)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                    }
                    if alert.contributingSignals.count > 5 {
                        Text("+\(alert.contributingSignals.count - 5) more signals")
                            .font(.nickCaption)
                            .foregroundStyle(Color.textTertiary)
                            .padding(.leading, NickSpacing.lg)
                    }
                }
                .padding(.leading, 20)
            }

            // Buttons
            HStack {
                Button("Copy JSON") { copyJSON() }
                    .buttonStyle(.plain)
                    .font(.nickButton)
                    .foregroundStyle(Color.textSecondary)
                Spacer()
                Button("Dismiss") { engine.dismissAlert(alert.id) }
                    .buttonStyle(.nickPrimary)
            }
        }
        .padding(.horizontal, NickSpacing.lg)
        .padding(.vertical, NickSpacing.lg)
    }

    // MARK: - Private

    private func copyJSON() {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        guard let data = try? encoder.encode(alert),
              let string = String(data: data, encoding: .utf8) else { return }
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(string, forType: .string)
    }
}

// MARK: - SeverityBadge (shared)

/// Pill-shaped severity badge using Nick design tokens.
struct SeverityBadge: View {
    let severity: SignalSeverity

    var body: some View {
        Text(severity.displayName.uppercased())
            .font(.nickCaption)
            .foregroundStyle(severity.statusColor)
            .padding(.horizontal, NickSpacing.md)
            .padding(.vertical, NickSpacing.xs)
            .background(severity.statusBackground, in: Capsule())
    }
}

// MARK: - Preview

#Preview {
    AlertListView()
        .environment(SecurityEngine())
        .frame(width: NickLayout.windowWidth, height: 400)
        .background(Color.backgroundPrimary)
}
