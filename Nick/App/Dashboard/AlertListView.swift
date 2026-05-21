// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import SwiftUI

// MARK: - AlertListView

/// Shows all `ThreatAlert` values produced by the `ThreatCorrelator`,
/// sorted by score (highest first). Tapping an alert navigates to `AlertDetailView`.
struct AlertListView: View {

    @Environment(SecurityEngine.self) private var engine
    @State private var selectedAlert: ThreatAlert?

    var body: some View {
        if engine.alerts.isEmpty {
            ContentUnavailableView(
                "No alerts",
                systemImage: "bell.slash",
                description: Text(engine.isScanning ? "Scan in progress…" : "No threats detected in the last scan.")
            )
            .padding()
        } else {
            ScrollView {
                LazyVStack(spacing: 4) {
                    ForEach(engine.alerts) { alert in
                        AlertRow(alert: alert)
                            .onTapGesture { selectedAlert = alert }
                    }
                }
                .padding(.vertical, 4)
            }
            .sheet(item: $selectedAlert) { alert in
                AlertDetailView(alert: alert)
            }
        }
    }
}

// MARK: - AlertRow

private struct AlertRow: View {

    let alert: ThreatAlert

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: severitySystemImage)
                .foregroundStyle(severityColor)
                .frame(width: 22)
                .padding(.top, 2)

            VStack(alignment: .leading, spacing: 3) {
                HStack {
                    Text(alert.title)
                        .font(.callout.bold())
                        .lineLimit(1)
                    Spacer()
                    Text(String(format: "%.0f%%", alert.score * 100))
                        .font(.caption2.bold())
                        .foregroundStyle(.secondary)
                }
                Text(alert.description)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(2)
            }

            Image(systemName: "chevron.right")
                .font(.caption)
                .foregroundStyle(.tertiary)
                .padding(.top, 4)
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
        .background(hoverBackground, in: RoundedRectangle(cornerRadius: 6))
        .padding(.horizontal, 4)
    }

    @State private var isHovered = false
    private var hoverBackground: some ShapeStyle {
        isHovered ? AnyShapeStyle(.quaternary) : AnyShapeStyle(.clear)
    }

    private var severityColor: Color {
        switch alert.severity {
        case .info:             .secondary
        case .low:              .blue
        case .medium:           .orange
        case .high, .critical:  .red
        }
    }

    private var severitySystemImage: String {
        switch alert.severity {
        case .info:     "info.circle.fill"
        case .low:      "exclamationmark.circle.fill"
        case .medium:   "exclamationmark.triangle.fill"
        case .high:     "xmark.shield.fill"
        case .critical: "exclamationmark.shield.fill"
        }
    }
}
