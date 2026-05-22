// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import SwiftUI

// MARK: - DashboardView

/// Root view presented when the user clicks the Nick menu bar icon.
///
/// Hosts the health gauge, a custom underline tab bar (Overview / Audit /
/// Network / Alerts), the active panel content, and the bottom action bar.
/// Fixed at `NickLayout.windowWidth` × `NickLayout.windowHeight`.
///
/// - Note: Uses `@Observable` SecurityEngine via the SwiftUI Environment.
///   All state mutations happen on the `@MainActor`.
struct DashboardView: View {

    @Environment(SecurityEngine.self) private var engine
    @State private var selectedPanel: Panel = .overview

    var body: some View {
        VStack(spacing: 0) {
            // Score gauge
            SystemHealthGauge(score: engine.healthScore, isScanning: engine.isScanning)
            // Tab bar separator
            Rectangle()
                .fill(Color.borderSubtle)
                .frame(height: 0.5)
            // Custom tab bar
            NickTabBar(selected: $selectedPanel, alertCount: engine.alerts.count)
            // Content area — replaced by scan overlay while scanning
            Group {
                if engine.isScanning {
                    ScanProgressView()
                } else {
                    content
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            // Bottom bar separator
            Rectangle()
                .fill(Color.borderSubtle)
                .frame(height: 0.5)
            bottomBar
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Color.backgroundPrimary.ignoresSafeArea())
    }

    // MARK: - Content

    @ViewBuilder
    private var content: some View {
        switch selectedPanel {
        case .overview: overviewPanel
        case .audit:    SystemAuditView()
        case .network:  NetworkConnectionsView()
        case .alerts:   AlertListView()
        }
    }

    private var overviewPanel: some View {
        ScrollView {
            VStack(spacing: 0) {
                MonitorStatusRow(
                    title: "System Audit",
                    systemImage: "checkmark.shield",
                    isRunning: engine.isScanning,
                    itemCount: engine.auditResults.count,
                    issueCount: engine.auditResults.filter { $0.status != .pass }.count,
                    onTap: { selectedPanel = .audit }
                )
                Divider().padding(.leading, NickLayout.separatorInset)
                MonitorStatusRow(
                    title: "Persistence",
                    systemImage: "arrow.triangle.2.circlepath",
                    isRunning: engine.isScanning,
                    itemCount: engine.persistenceItems.count,
                    issueCount: engine.persistenceItems.filter { $0.signingStatus?.isSuspicious == true }.count
                )
                Divider().padding(.leading, NickLayout.separatorInset)
                MonitorStatusRow(
                    title: "Processes",
                    systemImage: "cpu",
                    isRunning: engine.isScanning,
                    itemCount: engine.processes.count,
                    issueCount: engine.processes.filter { $0.signingStatus == .unsigned || $0.signingStatus == .invalid }.count,
                    onTap: { selectedPanel = .audit }
                )
                Divider().padding(.leading, NickLayout.separatorInset)
                MonitorStatusRow(
                    title: "Network",
                    systemImage: "network",
                    isRunning: engine.isScanning,
                    itemCount: engine.connections.count,
                    issueCount: engine.connections.filter { $0.isShellProcess && $0.isOutbound }.count,
                    onTap: { selectedPanel = .network }
                )
            }
        }
    }

    // MARK: - Bottom Bar

    private var bottomBar: some View {
        HStack(spacing: NickSpacing.md) {
            // Cancel during scan / Scan Now when idle
            if engine.isScanning {
                Button(action: { engine.cancelScan() }) {
                    HStack(spacing: NickSpacing.sm) {
                        Image(systemName: "xmark")
                        Text("Cancel")
                    }
                    .font(.nickButton)
                    .foregroundStyle(Color.textSecondary)
                }
                .buttonStyle(.plain)
            } else {
                Button(action: { engine.runFullScan() }) {
                    HStack(spacing: NickSpacing.sm) {
                        Image(systemName: "arrow.clockwise")
                        Text("Scan Now")
                    }
                    .font(.nickButton)
                    .foregroundStyle(Color.textSecondary)
                }
                .buttonStyle(.plain)
            }

            Spacer()

            // Pipeline status
            Label(engine.activePipelineStatus.rawValue,
                  systemImage: engine.activePipelineStatus.systemImage)
                .font(.nickMonoSmall)
                .foregroundStyle(Color.textTertiary)

            Spacer()

            // Quit
            Button("Quit Nick") { NSApp.terminate(nil) }
                .buttonStyle(.plain)
                .font(.nickBodySmall)
                .foregroundStyle(Color.textTertiary)
        }
        .padding(.horizontal, NickSpacing.lg)
        .frame(height: NickLayout.bottomBarHeight)
        .background(Color.backgroundSecondary)
    }
}

// MARK: - NickTabBar

/// Custom underline tab bar matching the Nick design system spec.
///
/// Active tab shows `textPrimary` color with a 2pt `statusBlue` underline.
/// Inactive tabs show `textSecondary`. The Alerts tab gets a red dot when
/// there are unresolved alerts.
private struct NickTabBar: View {

    @Binding var selected: Panel
    let alertCount: Int

    var body: some View {
        HStack(spacing: 0) {
            ForEach(Panel.allCases) { panel in
                tabButton(panel)
            }
        }
        .frame(height: NickLayout.tabBarHeight)
        .background(Color.backgroundPrimary)
    }

    private func tabButton(_ panel: Panel) -> some View {
        Button(action: { withAnimation(.easeInOut(duration: 0.2)) { selected = panel } }) {
            VStack(spacing: 0) {
                Spacer()
                HStack(spacing: NickSpacing.sm) {
                    Text(panel.title)
                        .font(.nickTabLabel)
                        .foregroundStyle(selected == panel ? Color.textPrimary : Color.textSecondary)
                    // Alert dot indicator
                    if panel == .alerts && alertCount > 0 {
                        Circle()
                            .fill(Color.statusRed)
                            .frame(width: 4, height: 4)
                    }
                }
                .padding(.horizontal, NickSpacing.md)
                Spacer(minLength: NickSpacing.xs)
                // Active underline
                Rectangle()
                    .fill(selected == panel ? Color.statusBlue : Color.clear)
                    .frame(height: 2)
            }
        }
        .buttonStyle(.plain)
        .frame(maxWidth: .infinity)
    }
}

// MARK: - Panel

private enum Panel: String, CaseIterable, Identifiable {
    case overview, audit, network, alerts

    var id: String { rawValue }

    var title: String {
        switch self {
        case .overview: "Overview"
        case .audit:    "Audit"
        case .network:  "Network"
        case .alerts:   "Alerts"
        }
    }
}

// MARK: - Preview

#Preview {
    DashboardView()
        .environment(SecurityEngine())
}
