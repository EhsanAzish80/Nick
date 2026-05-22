// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import SwiftUI

// MARK: - MonitorStatusRow

/// A single row in the Dashboard overview summarising one monitor's status.
///
/// Displays an 8pt status dot (green/yellow/red), monitor name, item count,
/// and an issue pill badge when `issueCount > 0`. Tapping the row triggers
/// `onTap` to navigate to the monitor's detail view.
///
/// All fonts and colors use Nick design tokens — no hardcoded values.
struct MonitorStatusRow: View {

    let title: String
    let systemImage: String
    let isRunning: Bool
    let itemCount: Int
    let issueCount: Int
    var onTap: (() -> Void)? = nil

    var body: some View {
        Button(action: { onTap?() }) {
            HStack(spacing: NickSpacing.md) {
                // Status dot
                Circle()
                    .fill(dotColor)
                    .frame(width: 8, height: 8)

                // Monitor name
                Text(title)
                    .font(.nickBody)
                    .foregroundStyle(Color.textPrimary)

                Spacer()

                // Always show count + status badge — scan state is in the bottom bar
                Text("\(itemCount)")
                    .font(.nickMono)
                    .foregroundStyle(Color.textSecondary)

                // Issues badge or checkmark
                if issueCount > 0 {
                    Text("\(issueCount) issue\(issueCount == 1 ? "" : "s")")
                        .font(.nickCaption)
                        .foregroundStyle(Color.statusRed)
                        .padding(.horizontal, NickSpacing.md)
                        .padding(.vertical, NickSpacing.xs)
                        .background(Color.statusRedBg, in: Capsule())
                } else if !isRunning {
                    Image(systemName: "checkmark.circle.fill")
                        .font(.system(size: NickLayout.iconSize))
                        .foregroundStyle(Color.statusGreen)
                }
            }
            .padding(.horizontal, NickSpacing.lg)
            .frame(minHeight: NickLayout.bottomBarHeight)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }

    // MARK: - Private

    private var dotColor: Color {
        if isRunning { return .statusBlue }
        if issueCount > 0 { return issueCount > 2 ? .statusRed : .statusYellow }
        return .statusGreen
    }
}

// MARK: - Preview

#Preview {
    VStack(spacing: 0) {
        MonitorStatusRow(title: "System Audit", systemImage: "checkmark.shield",
                         isRunning: false, itemCount: 8, issueCount: 3)
        Divider().padding(.leading, NickLayout.separatorInset)
        MonitorStatusRow(title: "Persistence", systemImage: "arrow.triangle.2.circlepath",
                         isRunning: false, itemCount: 15, issueCount: 0)
        Divider().padding(.leading, NickLayout.separatorInset)
        MonitorStatusRow(title: "Processes", systemImage: "cpu",
                         isRunning: false, itemCount: 785, issueCount: 0)
        Divider().padding(.leading, NickLayout.separatorInset)
        MonitorStatusRow(title: "Network", systemImage: "network",
                         isRunning: true, itemCount: 0, issueCount: 0)
    }
    .frame(width: NickLayout.windowWidth)
    .background(Color.backgroundPrimary)
}
