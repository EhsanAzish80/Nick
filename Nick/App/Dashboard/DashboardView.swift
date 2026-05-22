// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import SwiftUI

// MARK: - DashboardView

/// The root view shown when the user clicks the Nick menu bar icon.
///
/// Presents a navigation-based layout with:
/// - `SystemHealthGauge` at the top
/// - A list of `MonitorStatusRow` entries for each active monitor
/// - Tab-like navigation to detailed sub-views (audit, network, alerts)
struct DashboardView: View {

    @Environment(SecurityEngine.self) private var engine
    @State private var selectedPanel: Panel = .overview

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider()
            content
            Divider()
            footer
        }
        .background(.ultraThinMaterial)
        .task {
            if engine.auditResults.isEmpty && !engine.isScanning {
                await engine.runFullScan()
            }
        }
    }

    // MARK: - Sub-views

    private var header: some View {
        HStack {
            SystemHealthGauge(score: engine.healthScore, isScanning: engine.isScanning)
                .padding(.leading)
            Spacer()
            panelPicker
                .padding(.trailing)
        }
        .padding(.vertical, 8)
    }

    private var panelPicker: some View {
        Picker("Panel", selection: $selectedPanel) {
            ForEach(Panel.allCases) { panel in
                Label(panel.title, systemImage: panel.systemImage).tag(panel)
            }
        }
        .pickerStyle(.segmented)
        .frame(width: 280)
        .labelsHidden()
    }

    @ViewBuilder
    private var content: some View {
        switch selectedPanel {
        case .overview:     overviewPanel
        case .audit:        SystemAuditView()
        case .network:      NetworkConnectionsView()
        case .alerts:       AlertListView()
        }
    }

    private var overviewPanel: some View {
        ScrollView {
            LazyVStack(spacing: 4) {
                MonitorStatusRow(
                    title: "System Audit",
                    systemImage: "checkmark.shield",
                    isRunning: engine.isScanning,
                    itemCount: engine.auditResults.count,
                    issueCount: engine.auditResults.filter { $0.status != .pass }.count
                )
                MonitorStatusRow(
                    title: "Persistence",
                    systemImage: "bolt.badge.clock",
                    isRunning: engine.isScanning,
                    itemCount: engine.persistenceItems.count,
                    issueCount: engine.persistenceItems.filter { $0.signingStatus?.isSuspicious == true }.count
                )
                MonitorStatusRow(
                    title: "Processes",
                    systemImage: "cpu",
                    isRunning: engine.isScanning,
                    itemCount: engine.processes.count,
                    issueCount: engine.processes.filter { $0.signingStatus == .unsigned || $0.signingStatus == .invalid }.count
                )
                MonitorStatusRow(
                    title: "Network",
                    systemImage: "network",
                    isRunning: engine.isScanning,
                    itemCount: engine.connections.count,
                    issueCount: engine.connections.filter { $0.isShellProcess && $0.isOutbound }.count
                )
            }
            .padding(.vertical, 4)
        }
    }

    private var footer: some View {
        HStack {
            Button(action: { Task { await engine.runFullScan() } }) {
                Label("Scan Now", systemImage: "arrow.clockwise")
                    .font(.caption)
            }
            .buttonStyle(.plain)
            .disabled(engine.isScanning)
            Spacer()
            if engine.isScanning {
                ProgressView().controlSize(.small)
            }
            // Pipeline status indicator
            Label(engine.activePipelineStatus.rawValue, systemImage: engine.activePipelineStatus.systemImage)
                .font(.caption2)
                .foregroundStyle(.secondary)
            Spacer()
            if let scanDate = engine.lastScanDate {
                Text("Last scan: \(scanDate, style: .relative) ago")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }
            Button("Quit Nick") { NSApp.terminate(nil) }
                .buttonStyle(.plain)
                .font(.caption)
                .foregroundStyle(.secondary)
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 6)
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

    var systemImage: String {
        switch self {
        case .overview: "square.grid.2x2"
        case .audit:    "checkmark.shield"
        case .network:  "network"
        case .alerts:   "bell.badge"
        }
    }
}
