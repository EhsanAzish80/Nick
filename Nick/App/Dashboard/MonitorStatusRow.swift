// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import SwiftUI

// MARK: - MonitorStatusRow

/// A single row in the Dashboard overview summarising one monitor's status.
///
/// Shows the monitor name, a live/idle indicator, the total item count,
/// and a coloured badge for any issues detected.
struct MonitorStatusRow: View {

    let title: String
    let systemImage: String
    let isRunning: Bool
    let itemCount: Int
    let issueCount: Int

    var body: some View {
        HStack(spacing: 8) {
            Image(systemName: systemImage)
                .frame(width: 20)
                .foregroundStyle(isRunning ? Color.accentColor : Color.secondary)

            Text(title)
                .font(.callout)

            Spacer()

            if isRunning {
                ProgressView().controlSize(.mini)
            } else {
                Text("\(itemCount) items")
                    .font(.caption)
                    .foregroundStyle(.secondary)

                if issueCount > 0 {
                    Text("\(issueCount) issue\(issueCount == 1 ? "" : "s")")
                        .font(.caption.bold())
                        .padding(.horizontal, 6)
                        .padding(.vertical, 2)
                        .background(.red.opacity(0.15), in: Capsule())
                        .foregroundStyle(.red)
                } else {
                    Image(systemName: "checkmark.circle.fill")
                        .foregroundStyle(.green)
                        .font(.caption)
                }
            }
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 6)
    }
}

// MARK: - Preview

#Preview {
    VStack(spacing: 0) {
        MonitorStatusRow(title: "System Audit", systemImage: "checkmark.shield", isRunning: false, itemCount: 8, issueCount: 2)
        Divider()
        MonitorStatusRow(title: "Processes",    systemImage: "cpu",               isRunning: false, itemCount: 245, issueCount: 0)
        Divider()
        MonitorStatusRow(title: "Network",      systemImage: "network",            isRunning: true,  itemCount: 0, issueCount: 0)
    }
    .frame(width: 360)
}
