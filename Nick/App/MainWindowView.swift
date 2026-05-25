// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import AppKit
import SwiftUI
import UserNotifications

// MARK: - NickProcessInfo + Identifiable

extension NickProcessInfo: Identifiable {
    public var id: Int32 { pid }
}

// MARK: - MainWindowView

/// Full application window opened from the menu bar "Open Nick" button.
///
/// Uses a `NavigationSplitView` sidebar so every monitoring domain — Overview,
/// Audit, Network, Processes, Persistence, Alerts, and Scanner — is reachable
/// from a persistent list on the left. The main SecurityEngine is injected via
/// the SwiftUI environment from `NickApp`.
///
/// Activation policy: `.regular` (Dock icon) while this window is visible;
/// `.accessory` (menu-bar-only) when it closes.
struct MainWindowView: View {

    @Environment(SecurityEngine.self) private var engine
    @Environment(\.openWindow) private var openWindow
    @State private var selectedSection: SidebarSection? = .overview
    @AppStorage("hasCompletedOnboarding") private var hasCompletedOnboarding = false
    @State private var notificationsDenied = false

    // Alert count for sidebar badge (info-severity are trusted-app activity, not actionable).
    private var activeAlertCount: Int {
        engine.alerts.filter { $0.severity != .info }.count
    }

    var body: some View {
        if !hasCompletedOnboarding {
            WelcomeView(hasCompletedOnboarding: $hasCompletedOnboarding)
        } else {
            VStack(spacing: 0) {
                if notificationsDenied {
                    HStack(spacing: NickSpacing.sm) {
                        Image(systemName: "bell.slash")
                            .foregroundStyle(Color.statusYellow)
                        Text("Notifications are disabled. Nick can't alert you about threats.")
                            .font(.nickBodySmall)
                            .foregroundStyle(Color.textSecondary)
                        Spacer()
                        Button("Enable") {
                            NSWorkspace.shared.open(
                                URL(string: "x-apple.systempreferences:com.apple.Notifications-Settings")!
                            )
                        }
                        .font(.nickCaption)
                        Button("Dismiss") {
                            notificationsDenied = false
                        }
                        .font(.nickCaption)
                        .foregroundStyle(Color.textTertiary)
                    }
                    .padding(NickSpacing.md)
                    .background(Color.statusYellow.opacity(0.12))
                }
                mainContent
            }
            .task {
                // Switch to .regular before calling requestAuthorization — macOS
                // silently drops the dialog for .accessory-policy apps.
                NSApp.setActivationPolicy(.regular)
                NSApp.activate()
                let settings = await UNUserNotificationCenter.current().notificationSettings()
                if settings.authorizationStatus == .denied {
                    notificationsDenied = true
                } else if settings.authorizationStatus == .notDetermined {
                    let granted = await NotificationManager.shared.requestPermission()
                    notificationsDenied = !granted
                }
            }
        }
    }

    @ViewBuilder
    private var mainContent: some View {
        NavigationSplitView {
            VStack(spacing: 0) {
                List(selection: $selectedSection) {
                    ForEach(SidebarSection.mainSections) { section in
                        SidebarNavItem(
                            section:     section,
                            badge:       section == .alerts ? activeAlertCount : 0,
                            isDisabled:  section == .alerts && activeAlertCount == 0
                        )
                        .tag(section)
                    }
                }
                .navigationSplitViewColumnWidth(min: 200, ideal: 220)
                .navigationTitle("Nick")
                .onChange(of: activeAlertCount) { _, count in
                    if count == 0 && selectedSection == .alerts {
                        selectedSection = .overview
                    }
                }

                Divider()

                // Settings — pinned at bottom, outside the scrollable list
                Button { selectedSection = .settings } label: {
                    HStack(spacing: 8) {
                        IconTile(systemImage: "gearshape.fill", tint: Color(NSColor.systemGray), size: 26)
                        Text("Settings")
                            .font(.system(size: 13, weight: selectedSection == .settings ? .semibold : .regular))
                            .foregroundStyle(selectedSection == .settings ? Color.primary : Color.textPrimary)
                        Spacer()
                    }
                    .padding(.horizontal, 10)
                    .padding(.vertical, 7)
                    .background(
                        selectedSection == .settings
                            ? Color(NSColor.selectedContentBackgroundColor).opacity(0.12)
                            : Color.clear,
                        in: RoundedRectangle(cornerRadius: 6)
                    )
                }
                .buttonStyle(.plain)
                .padding(.horizontal, 8)
                .padding(.bottom, 10)
            }
        } detail: {
            switch selectedSection ?? .overview {
            case .overview:    OverviewDetailView(selectedSection: $selectedSection)
            case .audit:       SystemAuditView()
            case .network:     NetworkConnectionsView()
            case .processes:   ProcessListView()
            case .persistence: PersistenceDetailView()
            case .alerts:      AlertListView()
            case .scanner:     ScannerDetailView()
            case .settings:    SettingsView()
            }
        }
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Button(action: { engine.runFullScan() }) {
                    Label("Run Scan", systemImage: "arrow.clockwise")
                }
                .disabled(engine.isScanning)
            }
        }
        // Apple-native Aqua (light) appearance
        .preferredColorScheme(.light)
        .onAppear {
            NSApp.setActivationPolicy(.regular)
            (NSApp.delegate as? AppDelegate)?.openSettingsAction = {
                selectedSection = .settings
            }
            (NSApp.delegate as? AppDelegate)?.openMainWindowAction = { [openWindow] in
                openWindow(id: "main")
            }
        }
        .onDisappear {
            NSApp.setActivationPolicy(.accessory)
        }
    }
}

enum SidebarSection: String, CaseIterable, Identifiable, Hashable {
    case overview    = "Overview"
    case audit       = "System Audit"
    case network     = "Network"
    case processes   = "Processes"
    case persistence = "Persistence"
    case alerts      = "Alerts"
    case scanner     = "Scan"
    case settings    = "Settings"

    var id: String { rawValue }

    var title: String { id }

    /// Sections shown in the main ForEach list (Settings is pinned separately at the bottom)
    static var mainSections: [SidebarSection] {
        allCases.filter { $0 != .settings }
    }

    var icon: String {
        switch self {
        case .overview:    return "shield.checkered"
        case .audit:       return "checkmark.shield"
        case .network:     return "network"
        case .processes:   return "cpu"
        case .persistence: return "arrow.triangle.2.circlepath"
        case .alerts:      return "exclamationmark.triangle.fill"
        case .scanner:     return "doc.text.magnifyingglass"
        case .settings:    return "gearshape.fill"
        }
    }

    /// Accent tint for this section's IconTile in the sidebar.
    var tint: Color {
        switch self {
        case .overview:    return .blue
        case .audit:       return .green
        case .network:     return .blue
        case .processes:   return .purple
        case .persistence: return .orange
        case .alerts:      return .red
        case .scanner:     return Color(NSColor.systemGray)
        case .settings:    return Color(NSColor.systemGray)
        }
    }
}

// MARK: - Focus / DND detection

/// Returns `true` when macOS Do Not Disturb or any Focus mode is active.
///
/// Reads the `doNotDisturb` flag from the notification centre's shared defaults.
/// This covers legacy DND and Focus modes on macOS 12+.
private func isFocusModeActive() -> Bool {
    UserDefaults(suiteName: "com.apple.notificationcenterui")?.bool(forKey: "doNotDisturb") ?? false
}

// MARK: - SidebarNavItem

/// A sidebar list row with an IconTile badge and an optional alert count badge.
private struct SidebarNavItem: View {

    let section:    SidebarSection
    var badge:      Int  = 0
    var isDisabled: Bool = false

    var body: some View {
        Label {
            HStack {
                Text(section.title)
                Spacer()
                if badge > 0 {
                    Text("\(badge)")
                        .font(.nickCaption)
                        .foregroundStyle(.white)
                        .padding(.horizontal, 6)
                        .padding(.vertical, 2)
                        .background(Capsule().fill(Color.statusRed))
                }
            }
        } icon: {
            IconTile(systemImage: section.icon, tint: section.tint, size: 26)
        }
        .disabled(isDisabled)
    }
}

// MARK: - OverviewDetailView

/// Apple-native Overview screen: hero row → score card → status list →
/// protection summary → recent activity.
struct OverviewDetailView: View {

    @Binding var selectedSection: SidebarSection?
    @Environment(SecurityEngine.self) private var engine

    @AppStorage("deepScanIntervalSeconds") private var scanIntervalSeconds: Int = 60
    @State private var now: Date = .now
    @State private var focusModeActive = false

    // MARK: - Derived counts

    private var auditIssues:       Int { engine.auditResults.filter { $0.status != .pass }.count }
    private var persistenceIssues: Int { engine.persistenceItems.filter { $0.signingStatus?.isSuspicious == true }.count }
    private var processIssues:     Int { engine.processes.filter { $0.signingStatus == .unsigned || $0.signingStatus == .invalid }.count }
    private var networkIssues:     Int { engine.connections.filter { $0.isShellProcess && $0.isOutbound }.count }
    private var totalIssues:       Int { auditIssues + persistenceIssues + processIssues + networkIssues }

    private var nextScanIn: Int {
        guard let last = engine.lastScanDate else { return scanIntervalSeconds }
        return max(0, scanIntervalSeconds - Int(now.timeIntervalSince(last)))
    }

    // Sectional scores out of 25 (capped at 0)
    private func sectionScore(_ issues: Int) -> Int { max(0, 25 - issues) }

    var body: some View {
        ScrollView {
            VStack(spacing: 0) {
                heroCard
                    .padding(.horizontal, 20)
                    .padding(.top, 20)
                    .padding(.bottom, 16)

                scoreCard
                    .padding(.horizontal, 20)
                    .padding(.bottom, 16)

                statusGroup
                    .padding(.horizontal, 20)
                    .padding(.bottom, 16)

                protectionSummaryGroup
                    .padding(.horizontal, 20)
                    .padding(.bottom, 16)

                recentActivityGroup
                    .padding(.horizontal, 20)
                    .padding(.bottom, 24)
            }
        }
        .background(Color.backgroundPrimary)
        .navigationTitle("Overview")
        .task {
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(1))
                now = .now
                focusModeActive = isFocusModeActive()
            }
        }
    }

    // MARK: - Hero card

    private var heroCard: some View {
        HStack(spacing: 16) {
            IconTile(
                systemImage: totalIssues == 0 ? "checkmark.shield.fill" : "exclamationmark.shield.fill",
                tint:        totalIssues == 0 ? .green : .orange,
                size: 56
            )

            VStack(alignment: .leading, spacing: 4) {
                HStack(spacing: 8) {
                    Text(totalIssues == 0 ? "Your Mac is protected" : "Attention needed")
                        .font(.system(size: 17, weight: .semibold))
                        .foregroundStyle(Color.textPrimary)
                    // Score pill
                    if engine.healthScore == -1 {
                        Text("Scanning…")
                            .font(.system(size: 12, weight: .semibold))
                            .foregroundStyle(Color.textSecondary)
                            .padding(.horizontal, 8)
                            .padding(.vertical, 3)
                            .background(Capsule().fill(Color.textTertiary.opacity(0.12)))
                    } else {
                        Text("\(engine.healthScore)/100")
                            .font(.system(size: 12, weight: .semibold))
                            .foregroundStyle(totalIssues == 0 ? .green : .orange)
                            .padding(.horizontal, 8)
                            .padding(.vertical, 3)
                            .background(
                                Capsule()
                                    .fill(totalIssues == 0 ? Color.green.opacity(0.12) : Color.orange.opacity(0.12))
                            )
                    }
                }
                Text(engine.isScanning
                     ? "Scan in progress…"
                     : (engine.lastScanDate.map { "Last scan \($0.formatted(.relative(presentation: .named))). No threats found." }
                        ?? "No scan completed yet."))
                    .font(.system(size: 12))
                    .foregroundStyle(Color.textSecondary)
            }

            Spacer()

            Button(engine.isScanning ? "Scanning…" : "Run Scan") {
                engine.runFullScan()
            }
            .buttonStyle(.borderedProminent)
            .disabled(engine.isScanning)
        }
        .padding(16)
        .background(
            RoundedRectangle(cornerRadius: 12, style: .continuous)
                .fill(Color.backgroundSecondary)
        )
        .overlay(
            RoundedRectangle(cornerRadius: 12, style: .continuous)
                .strokeBorder(Color.borderSubtle, lineWidth: 0.5)
        )
    }

    // MARK: - Score card

    private var scoreCard: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("SECURITY SCORE")
                .font(.system(size: 11, weight: .semibold))
                .foregroundStyle(Color.textTertiary)
                .tracking(0.5)

            VStack(alignment: .leading, spacing: 10) {
                HStack(alignment: .firstTextBaseline, spacing: 6) {
                    if engine.healthScore == -1 {
                        Text("—")
                            .font(.system(size: 36, weight: .bold, design: .rounded))
                            .foregroundStyle(Color.textTertiary)
                        Text("Scanning…")
                            .font(.system(size: 15))
                            .foregroundStyle(Color.textSecondary)
                    } else {
                        Text("\(engine.healthScore)")
                            .font(.system(size: 36, weight: .bold, design: .rounded))
                            .foregroundStyle(Color.textPrimary)
                        Text("of 100")
                            .font(.system(size: 15))
                            .foregroundStyle(Color.textSecondary)
                    }
                    Spacer()
                    Text(totalIssues == 0 ? "All four areas healthy" : "\(totalIssues) issue\(totalIssues == 1 ? "" : "s") found")
                        .font(.system(size: 13))
                        .foregroundStyle(Color.textSecondary)
                }

                // Segmented color bar
                GeometryReader { geo in
                    HStack(spacing: 2) {
                        Capsule().fill(Color.green)   .frame(width: geo.size.width * 0.25, height: 6)
                        Capsule().fill(Color.orange)  .frame(width: geo.size.width * 0.25, height: 6)
                        Capsule().fill(Color.purple)  .frame(width: geo.size.width * 0.25, height: 6)
                        Capsule().fill(Color.blue)    .frame(width: geo.size.width * 0.25, height: 6)
                    }
                }
                .frame(height: 6)

                // Legend
                HStack(spacing: 0) {
                    ScoreLegendItem(color: .green,  label: "System Audit", score: sectionScore(auditIssues))
                    ScoreLegendItem(color: .orange, label: "Persistence",  score: sectionScore(persistenceIssues))
                    ScoreLegendItem(color: .purple, label: "Processes",    score: sectionScore(processIssues))
                    ScoreLegendItem(color: .blue,   label: "Network",      score: sectionScore(networkIssues))
                }
            }
            .padding(16)
            .background(
                RoundedRectangle(cornerRadius: 10, style: .continuous)
                    .fill(Color.backgroundSecondary)
            )
            .overlay(
                RoundedRectangle(cornerRadius: 10, style: .continuous)
                    .strokeBorder(Color.borderSubtle, lineWidth: 0.5)
            )
        }
    }

    // MARK: - Status group

    private var statusGroup: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("STATUS")
                .font(.system(size: 11, weight: .semibold))
                .foregroundStyle(Color.textTertiary)
                .tracking(0.5)

            VStack(spacing: 0) {
                OverviewStatusRow(
                    icon: "checkmark.shield", tint: .green,
                    title: "System Audit",
                    subtitle: "\(engine.auditResults.count) settings verified",
                    issues: auditIssues
                ) { selectedSection = .audit }

                Divider().padding(.leading, 58)

                OverviewStatusRow(
                    icon: "arrow.triangle.2.circlepath", tint: .orange,
                    title: "Persistence",
                    subtitle: "\(engine.persistenceItems.count) launch items",
                    issues: persistenceIssues
                ) { selectedSection = .persistence }

                Divider().padding(.leading, 58)

                OverviewStatusRow(
                    icon: "cpu", tint: .purple,
                    title: "Processes",
                    subtitle: "\(engine.processes.count) running",
                    issues: processIssues
                ) { selectedSection = .processes }

                Divider().padding(.leading, 58)

                OverviewStatusRow(
                    icon: "network", tint: .blue,
                    title: "Network",
                    subtitle: "\(engine.connections.count) active connections",
                    issues: networkIssues
                ) { selectedSection = .network }
            }
            .background(
                RoundedRectangle(cornerRadius: 10, style: .continuous)
                    .fill(Color.backgroundSecondary)
            )
            .overlay(
                RoundedRectangle(cornerRadius: 10, style: .continuous)
                    .strokeBorder(Color.borderSubtle, lineWidth: 0.5)
            )
        }
    }

    // MARK: - Protection summary group

    private var protectionSummaryGroup: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("PROTECTION SUMMARY")
                .font(.system(size: 11, weight: .semibold))
                .foregroundStyle(Color.textTertiary)
                .tracking(0.5)

            VStack(spacing: 0) {
                summaryRow(label: "Monitoring since", value: engine.monitoringSince.formatted(date: .abbreviated, time: .omitted))

                Divider().padding(.leading, 16)
                summaryRow(label: "Total scans", value: "\(engine.totalScanCount)")

                Divider().padding(.leading, 16)
                summaryRow(label: "Threats detected", value: "\(engine.totalThreatsDetected)")

                if let last = engine.lastScanDate {
                    Divider().padding(.leading, 16)
                    summaryRow(label: "Last scan", value: last.formatted(date: .abbreviated, time: .shortened))
                }

                Divider().padding(.leading, 16)
                summaryRow(label: "Next scan", value: "In \(nextScanIn) sec")

                if focusModeActive {
                    Divider().padding(.leading, 16)
                    HStack(spacing: 8) {
                        Image(systemName: "moon.fill")
                            .foregroundStyle(Color.statusOrange)
                            .font(.system(size: 12))
                        Text("Focus Mode is on — notifications are silenced")
                            .font(.system(size: 12))
                            .foregroundStyle(Color.textSecondary)
                        Spacer()
                    }
                    .padding(.horizontal, 16)
                    .padding(.vertical, 10)
                }
            }
            .background(
                RoundedRectangle(cornerRadius: 10, style: .continuous)
                    .fill(Color.backgroundSecondary)
            )
            .overlay(
                RoundedRectangle(cornerRadius: 10, style: .continuous)
                    .strokeBorder(Color.borderSubtle, lineWidth: 0.5)
            )
        }
    }

    private func summaryRow(label: String, value: String) -> some View {
        HStack {
            Text(label)
                .font(.system(size: 13))
                .foregroundStyle(Color.textPrimary)
            Spacer()
            Text(value)
                .font(.system(size: 13, design: .monospaced))
                .foregroundStyle(Color.textSecondary)
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 10)
    }

    // MARK: - Recent activity group

    private var recentActivityGroup: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("RECENT ACTIVITY")
                    .font(.system(size: 11, weight: .semibold))
                    .foregroundStyle(Color.textTertiary)
                    .tracking(0.5)
                Spacer()
                Button("View all") { selectedSection = .alerts }
                    .font(.system(size: 12))
                    .foregroundStyle(Color.blue)
                    .buttonStyle(.plain)
            }

            if engine.activityLog.events.isEmpty {
                Text("No recent activity")
                    .font(.system(size: 13))
                    .foregroundStyle(Color.textTertiary)
                    .frame(maxWidth: .infinity, alignment: .center)
                    .padding(.vertical, 20)
                    .background(
                        RoundedRectangle(cornerRadius: 10, style: .continuous)
                            .fill(Color.backgroundSecondary)
                    )
            } else {
                VStack(spacing: 0) {
                    ForEach(Array(engine.activityLog.events.prefix(5).enumerated()), id: \.offset) { idx, event in
                        if idx > 0 { Divider().padding(.leading, 52) }
                        HStack(spacing: 12) {
                            ZStack {
                                Circle()
                                    .fill(activityColor(event.iconColor).opacity(0.12))
                                    .frame(width: 32, height: 32)
                                Image(systemName: event.icon)
                                    .font(.system(size: 14))
                                    .foregroundStyle(activityColor(event.iconColor))
                            }
                            VStack(alignment: .leading, spacing: 2) {
                                Text(event.title)
                                    .font(.system(size: 13))
                                    .foregroundStyle(Color.textPrimary)
                                Text(event.subtitle)
                                    .font(.system(size: 11, design: .monospaced))
                                    .foregroundStyle(Color.textTertiary)
                            }
                            Spacer()
                            Text(event.timestamp, format: .relative(presentation: .named))
                                .font(.system(size: 11))
                                .foregroundStyle(Color.textTertiary)
                        }
                        .padding(.horizontal, 16)
                        .padding(.vertical, 10)
                    }
                }
                .background(
                    RoundedRectangle(cornerRadius: 10, style: .continuous)
                        .fill(Color.backgroundSecondary)
                )
                .overlay(
                    RoundedRectangle(cornerRadius: 10, style: .continuous)
                        .strokeBorder(Color.borderSubtle, lineWidth: 0.5)
                )
            }

            Text("Continuous protection is on.")
                .font(.system(size: 11))
                .foregroundStyle(Color.textTertiary)
                .frame(maxWidth: .infinity, alignment: .center)
                .padding(.top, 4)
        }
    }

    private func activityColor(_ string: String) -> Color {
        switch string {
        case "green":  return .statusGreen
        case "blue":   return .statusBlue
        case "yellow": return .statusYellow
        case "red":    return .statusRed
        default:       return .textTertiary
        }
    }
}

// MARK: - ScoreLegendItem

private struct ScoreLegendItem: View {
    let color: Color
    let label: String
    let score: Int

    var body: some View {
        VStack(alignment: .leading, spacing: 3) {
            HStack(spacing: 4) {
                Circle().fill(color).frame(width: 7, height: 7)
                Text(label)
                    .font(.system(size: 11))
                    .foregroundStyle(Color.textSecondary)
                    .lineLimit(1)
            }
            Text("\(score)/25")
                .font(.system(size: 13, weight: .semibold))
                .foregroundStyle(Color.textPrimary)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

// MARK: - OverviewStatusRow

private struct OverviewStatusRow: View {
    let icon:     String
    let tint:     Color
    let title:    String
    let subtitle: String
    let issues:   Int
    let action:   () -> Void

    private var statusDotKind: StatusDot.Kind {
        issues > 0 ? .bad : .ok
    }

    private var statusLabel: String {
        issues > 0 ? "\(issues) issue\(issues == 1 ? "" : "s")" : "All clear"
    }

    var body: some View {
        Button(action: action) {
            HStack(spacing: 12) {
                IconTile(systemImage: icon, tint: tint, size: 36)

                VStack(alignment: .leading, spacing: 2) {
                    Text(title)
                        .font(.system(size: 13, weight: .medium))
                        .foregroundStyle(Color.textPrimary)
                    Text(subtitle)
                        .font(.system(size: 11))
                        .foregroundStyle(Color.textSecondary)
                }

                Spacer()

                StatusText(kind: statusDotKind, label: statusLabel)

                Image(systemName: "chevron.right")
                    .font(.system(size: 11, weight: .semibold))
                    .foregroundStyle(Color.textTertiary)
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 12)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }
}

// MARK: - Deprecated helpers (kept for compiler — no longer used in Overview)

private struct MonitorCard: View {
    let title:           String
    let count:           Int
    let status:          String
    let statusColor:     Color
    let icon:            String
    let sparklineValues: [Int]
    let sparklineColor:  Color
    let action:          () -> Void

    var body: some View {
        Button(action: action) {
            HStack {
                VStack(alignment: .leading, spacing: NickSpacing.sm) {
                    Image(systemName: icon)
                        .font(.system(size: 20))
                        .foregroundStyle(Color.statusGreen)
                        .padding(8)
                        .background(Color.statusGreen.opacity(0.12))
                        .clipShape(RoundedRectangle(cornerRadius: 8))
                    Text(title).font(.nickBodyMedium).foregroundStyle(Color.textPrimary)
                    HStack(spacing: NickSpacing.sm) {
                        Text("\(count)").font(.nickMono).foregroundStyle(Color.textPrimary)
                        Text("items").font(.nickBodySmall).foregroundStyle(Color.textSecondary)
                    }
                    HStack(spacing: NickSpacing.xs) {
                        Circle().fill(statusColor).frame(width: 6, height: 6)
                        Text(status).font(.nickCaption).foregroundStyle(statusColor)
                    }
                }
                Spacer()
                SparklineView(values: sparklineValues, color: sparklineColor)
                    .frame(width: 80, height: 40)
            }
            .padding(NickSpacing.lg)
            .background(Color.backgroundSecondary)
            .clipShape(RoundedRectangle(cornerRadius: NickLayout.cardCornerRadius))
        }
        .buttonStyle(.plain)
    }
}

private struct ProtectionSummaryView: View {
    let monitoringSince: Date
    let totalScans:      Int
    let threatsDetected: Int
    let lastScanDate:    Date?
    let nextScanIn:      Int
    let focusModeActive: Bool

    var body: some View { EmptyView() }
}

private struct SummaryRow: View {
    let icon:  String
    let label: String
    let value: String
    var body: some View { EmptyView() }
}

private struct RecentActivityView: View {
    let events:    [ActivityEvent]
    let onViewAll: () -> Void
    var body: some View { EmptyView() }
}

/// Full-width table of running processes with sortable columns.
struct ProcessListView: View {

    @Environment(SecurityEngine.self) private var engine
    @State private var sortOrder = [KeyPathComparator<NickProcessInfo>(\NickProcessInfo.name)]
    @State private var searchText = ""

    private var filtered: [NickProcessInfo] {
        let base = searchText.isEmpty
            ? engine.processes
            : engine.processes.filter {
                $0.name.localizedCaseInsensitiveContains(searchText) ||
                $0.path.localizedCaseInsensitiveContains(searchText)
            }
        return base.sorted(using: sortOrder)
    }

    private var flaggedCount: Int {
        engine.processes.filter { ProcessListView.threatLabel($0) != nil }.count
    }

    var body: some View {
        VStack(spacing: 0) {
            // Hero row
            HStack(spacing: 14) {
                IconTile(systemImage: "cpu", tint: Color(NSColor.systemPurple), size: 56)
                VStack(alignment: .leading, spacing: 4) {
                    Text("Processes")
                        .font(.system(size: 18, weight: .semibold))
                        .foregroundStyle(Color.textPrimary)
                    Text("\(engine.processes.count) running · \(flaggedCount) flagged")
                        .font(.system(size: 13))
                        .foregroundStyle(Color.textSecondary)
                }
                Spacer()
            }
            .padding(.horizontal, 20)
            .padding(.top, 20)
            .padding(.bottom, 12)

            Table(filtered, sortOrder: $sortOrder) {
                TableColumn("PID", value: \.pid) { p in
                    Text("\(p.pid)")
                        .font(.system(.body, design: .monospaced))
                        .foregroundStyle(Color.textSecondary)
                }
                .width(60)

                TableColumn("Name", value: \.name) { p in
                    Text(p.name)
                        .foregroundStyle(Color.textPrimary)
                }
                .width(min: 120, ideal: 160)

                TableColumn("Path") { p in
                    Text(p.path.isEmpty ? "—" : p.path)
                        .font(.system(.body, design: .monospaced))
                        .foregroundStyle(Color.textTertiary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                }

                TableColumn("Signing") { p in
                    Text(ProcessListView.signingText(p))
                        .foregroundStyle(ProcessListView.signingColor(p.signingStatus))
                }
                .width(min: 100, ideal: 130)

                TableColumn("Threat") { p in
                    HStack(spacing: 5) {
                        Circle()
                            .fill(ProcessListView.threatDotColor(p))
                            .frame(width: 6, height: 6)
                        Text(ProcessListView.threatDisplayText(p))
                            .font(.system(size: 12))
                            .foregroundStyle(ProcessListView.threatDotColor(p))
                    }
                }
                .width(80)

                TableColumn("Parent PID", value: \.parentPID) { p in
                    if let parentName = p.parentName {
                        Text("\(p.parentPID) (\(parentName))")
                            .foregroundStyle(Color.textSecondary)
                    } else {
                        Text("\(p.parentPID)")
                            .foregroundStyle(Color.textSecondary)
                    }
                }
                .width(min: 80, ideal: 110)
            }
            .searchable(text: $searchText, prompt: "Filter processes…")
        }
        .navigationTitle("Processes")
    }

    // MARK: - Process Helpers (static so Table closures can access them)

    static func signingColor(_ status: SigningStatus) -> Color {
        switch status {
        case .signed:             return .statusGreen
        case .adHoc:              return .statusYellow
        case .unsigned, .invalid: return .statusRed
        case .unknown, .pending:  return .textTertiary
        }
    }

    static func signingText(_ p: NickProcessInfo) -> String {
        guard p.signingStatus == .pending else { return p.signingStatus.displayName }
        if let start = p.startTime, Date().timeIntervalSince(start) > 10 { return "Unknown" }
        return "Checking…"
    }

    static func threatLabel(_ p: NickProcessInfo) -> String? {
        let path = p.path.lowercased()
        if p.signingStatus == .unsigned,
           path.hasPrefix("/tmp") || path.hasPrefix("/var/tmp") || path.hasPrefix("/private/tmp") {
            return "Temp Path"
        }
        let lolBins: Set<String> = ["bash", "sh", "zsh", "python", "python3", "perl",
                                    "ruby", "curl", "wget", "nc", "ncat", "osascript"]
        if lolBins.contains(p.name.lowercased()) && p.signingStatus == .unsigned {
            return "LOLBin"
        }
        return nil
    }

    static func threatDotColor(_ p: NickProcessInfo) -> Color {
        guard let label = threatLabel(p) else {
            return p.signingStatus == .unknown || p.signingStatus == .pending ? Color.textTertiary : Color.statusGreen
        }
        _ = label
        return Color.statusRed
    }

    static func threatDisplayText(_ p: NickProcessInfo) -> String {
        if let label = threatLabel(p) { return label }
        return p.signingStatus == .unknown || p.signingStatus == .pending ? "Unknown" : "Clean"
    }
}

// MARK: - PersistenceDetailView

/// Table of all detected persistence mechanisms.
struct PersistenceDetailView: View {

    @Environment(SecurityEngine.self) private var engine
    @State private var sortOrder    = [KeyPathComparator<PersistenceItem>(\PersistenceItem.name)]
    @State private var searchText   = ""
    @State private var persistenceFilter: PFilter = .all
    @State private var selectedItems = Set<PersistenceItem.ID>()
    @State private var itemToDelete: PersistenceItem? = nil
    @State private var showDeleteConfirmation = false

    enum PFilter: String, CaseIterable {
        case all      = "All"
        case verified = "Verified"
        case missing  = "Missing"
        case broken   = "Broken"
    }

    private var filtered: [PersistenceItem] {
        let base = searchText.isEmpty
            ? engine.persistenceItems
            : engine.persistenceItems.filter {
                $0.name.localizedCaseInsensitiveContains(searchText) ||
                $0.type.displayName.localizedCaseInsensitiveContains(searchText)
            }
        let segmented: [PersistenceItem]
        switch persistenceFilter {
        case .all:      segmented = base
        case .verified: segmented = base.filter { PersistenceDetailView.status(for: $0) == .verified }
        case .missing:  segmented = base.filter { PersistenceDetailView.status(for: $0) == .missing }
        case .broken:   segmented = base.filter { PersistenceDetailView.status(for: $0) == .broken }
        }
        return segmented.sorted(using: sortOrder)
    }

    // Hero subtitle counts
    private var verifiedCount: Int { engine.persistenceItems.filter { PersistenceDetailView.status(for: $0) == .verified }.count }
    private var missingCount:  Int { engine.persistenceItems.filter { PersistenceDetailView.status(for: $0) == .missing  }.count }
    private var brokenCount:   Int { engine.persistenceItems.filter { PersistenceDetailView.status(for: $0) == .broken   }.count }

    var body: some View {
        VStack(spacing: 0) {
            // Hero row — filter picker sits on the right, inline with the title
            HStack(alignment: .center, spacing: 14) {
                IconTile(systemImage: "arrow.triangle.2.circlepath", tint: Color(NSColor.systemOrange), size: 56)
                VStack(alignment: .leading, spacing: 4) {
                    Text("Persistence")
                        .font(.system(size: 18, weight: .semibold))
                        .foregroundStyle(Color.textPrimary)
                    if engine.persistenceItems.isEmpty {
                        Text("Run a scan to check for persistent startup items.")
                            .font(.system(size: 13))
                            .foregroundStyle(Color.textSecondary)
                    } else {
                        Text("\(engine.persistenceItems.count) items · \(verifiedCount) verified · \(missingCount) missing · \(brokenCount) broken")
                            .font(.system(size: 13))
                            .foregroundStyle(Color.textSecondary)
                    }
                }
                Spacer()
                if !engine.persistenceItems.isEmpty {
                    Picker("Filter", selection: $persistenceFilter) {
                        ForEach(PFilter.allCases, id: \.self) { f in
                            Text(f.rawValue).tag(f)
                        }
                    }
                    .pickerStyle(.segmented)
                    .frame(width: 290)
                }
            }
            .padding(.horizontal, 20)
            .padding(.top, 20)
            .padding(.bottom, 12)

            if engine.persistenceItems.isEmpty {
                emptyState
            } else {
                persistenceTable
            }
        }
        .searchable(text: $searchText, placement: .toolbar, prompt: "Filter persistence items…")
        .navigationTitle("Persistence")
        .alert("Remove Launch Item", isPresented: $showDeleteConfirmation, presenting: itemToDelete) { item in
            Button("Remove \"\(item.name)\"", role: .destructive) {
                removeLaunchItem(item)
            }
            Button("Cancel", role: .cancel) {}
        } message: { item in
            Text("This will delete the launch item and prevent it from running at startup. This cannot be undone.")
        }
    }

    // MARK: - Table (extracted to avoid type-checker timeout on complex multi-column Table)

    @ViewBuilder
    private var persistenceTable: some View {
        Table(filtered, selection: $selectedItems, sortOrder: $sortOrder) {
            TableColumn("Type") { (item: PersistenceItem) in
                Text(item.type.displayName)
                    .foregroundStyle(Color.textSecondary)
            }
            .width(min: 110, ideal: 130)

            TableColumn("Name", value: \.name) { (item: PersistenceItem) in
                Text(item.name)
                    .foregroundStyle(Color.textPrimary)
                    .lineLimit(1)
            }

            TableColumn("Executable") { (item: PersistenceItem) in
                let label: String = item.executablePath
                    .map { URL(fileURLWithPath: $0).lastPathComponent } ?? "—"
                Text(label)
                    .font(.system(.body, design: .monospaced))
                    .foregroundStyle(Color.textTertiary)
                    .lineLimit(1)
            }

            TableColumn("Signing") { (item: PersistenceItem) in
                let sigText: String = item.signingStatus?.displayName ?? "—"
                let sigColor: Color = item.signingStatus?.isSuspicious == true
                    ? Color.statusRed : Color.textSecondary
                Text(sigText).foregroundStyle(sigColor)
            }
            .width(min: 100, ideal: 130)

            TableColumn("Status") { (item: PersistenceItem) in
                let s = PersistenceDetailView.status(for: item)
                HStack(spacing: 5) {
                    Circle().fill(s.color).frame(width: 6, height: 6)
                    Text(s.shortLabel)
                        .font(.system(size: 12))
                        .foregroundStyle(s.color)
                }
            }
            .width(min: 90, ideal: 110)

            TableColumn("Scope") { (item: PersistenceItem) in
                let label: String = item.scope == .system ? "System" : "User"
                Text(label).foregroundStyle(Color.textSecondary)
            }
            .width(60)
        }
        .contextMenu(forSelectionType: PersistenceItem.ID.self) { (ids: Set<PersistenceItem.ID>) in
            if let id = ids.first, let item = filtered.first(where: { $0.id == id }) {
                let st = PersistenceDetailView.status(for: item)
                let canDelete = (st == .broken || st == .missing)
                    && item.scope == .user
                    && FileManager.default.isDeletableFile(atPath: item.path)

                Button("Show Plist in Finder") {
                    NSWorkspace.shared.selectFile(item.path, inFileViewerRootedAtPath: "")
                }

                if let exec = item.executablePath, FileManager.default.fileExists(atPath: exec) {
                    Button("Show Executable in Finder") {
                        NSWorkspace.shared.selectFile(exec, inFileViewerRootedAtPath: "")
                    }
                }

                Divider()

                if canDelete {
                    Button("Remove Launch Item", role: .destructive) {
                        itemToDelete = item
                        showDeleteConfirmation = true
                    }
                }

                Divider()

                Button("Copy Path") {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(
                        item.executablePath ?? item.path,
                        forType: .string
                    )
                }
            }
        }
    }

    // MARK: - Helpers

    private func removeLaunchItem(_ item: PersistenceItem) {
        guard item.scope == .user,
              FileManager.default.isDeletableFile(atPath: item.path) else { return }
        try? FileManager.default.removeItem(atPath: item.path)
        Task { @MainActor in engine.runFullScan() }
    }

    // MARK: - Persistence Status

    enum PStatus {
        case verified, missing, unsigned, broken, hidden

        var label: String {
            switch self {
            case .verified: return "✓ Verified"
            case .missing:  return "⚠ Missing"
            case .unsigned: return "⚠ Unsigned"
            case .broken:   return "✕ Broken"
            case .hidden:   return "⚠ Hidden"
            }
        }

        var shortLabel: String {
            switch self {
            case .verified: return "Verified"
            case .missing:  return "Missing"
            case .unsigned: return "Unsigned"
            case .broken:   return "Broken"
            case .hidden:   return "Hidden"
            }
        }

        var color: Color {
            switch self {
            case .verified: return .statusGreen
            case .missing:  return .statusYellow
            case .unsigned: return .statusYellow
            case .broken:   return .statusRed
            case .hidden:   return .statusOrange
            }
        }
    }

    static func status(for item: PersistenceItem) -> PStatus {
        let fm = FileManager.default
        // Hidden directory in path
        if item.path.contains("/.") || (item.executablePath?.contains("/.") == true) {
            return .hidden
        }
        guard let execPath = item.executablePath else { return .missing }
        guard fm.fileExists(atPath: execPath) else { return .broken }
        guard let signing = item.signingStatus else { return .missing }
        if signing.isSuspicious { return .unsigned }
        return .verified
    }

    private var emptyState: some View {
        ScrollView {
            VStack(spacing: 20) {
                Spacer(minLength: 40)
                IconTile(systemImage: "arrow.triangle.2.circlepath", tint: .orange, size: 64)
                VStack(spacing: 6) {
                    Text("No persistence items found")
                        .font(.system(size: 18, weight: .semibold))
                        .foregroundStyle(Color.textPrimary)
                    Text("Run a scan to check for persistent startup items.")
                        .font(.system(size: 13))
                        .foregroundStyle(Color.textSecondary)
                        .multilineTextAlignment(.center)
                }
                Spacer(minLength: 40)
            }
            .frame(maxWidth: .infinity)
            .padding(40)
        }
        .background(Color.backgroundPrimary)
    }
}

// MARK: - ThreatVerdict

/// Verdict assigned to each deep-scan YARA match after path + signature analysis.
enum ThreatVerdict: String {
    case threat              = "Threat"
    case suspicious          = "Suspicious"
    case developmentArtifact = "Development artifact"
    case applicationData     = "Application data"
    case likelySafe          = "Likely safe"
}

// MARK: - ScannerDetailView
// Changes 8, 9, 10: drag-drop Nick Scan, inline Deep Scan, grouped results + export.

struct ScannerDetailView: View {

    @Environment(SecurityEngine.self) private var engine

    // MARK: - Deep scan state
    @State private var scanner      = DeepScanner()
    @State private var hasStarted   = false
    @State private var onlyOnPower  = false
    @State private var showResults  = false
    @AppStorage("scanNotifyOnCompletion") private var notifyOnCompletion = true

    // MARK: - Ignore list (newline-delimited paths persisted in UserDefaults)
    @AppStorage("deepScanIgnoredPaths") private var ignoredPathsRaw: String = ""

    private var ignoredPaths: Set<String> {
        Set(ignoredPathsRaw.split(separator: "\n").map(String.init))
    }

    // MARK: - Body

    var body: some View {
        if showResults {
            DeepScanResultsView(
                scanner:      scanner,
                ignoredPaths: ignoredPaths,
                onIgnore:     { path in addIgnored(path) },
                onNewScan:    { resetDeepScan() }
            )
        } else {
            mainView
        }
    }

    // MARK: - Main Scan View

    private var mainView: some View {
        ScrollView {
            VStack(spacing: 0) {
                // SCAN section — three action rows
                scanActionsGroup
                    .padding(.horizontal, 20)
                    .padding(.top, 20)
                    .padding(.bottom, 16)

                // Deep scan progress / paused state (inline, collapses when idle)
                if scanner.isScanning || scanner.isPaused {
                    deepScanProgressGroup
                        .padding(.horizontal, 20)
                        .padding(.bottom, 16)
                }

                // Options group
                optionsGroup
                    .padding(.horizontal, 20)
                    .padding(.bottom, 24)
            }
        }
        .background(Color.backgroundPrimary)
        .navigationTitle("Nick Scan")
        .onChange(of: scanner.isScanning) { _, isScanning in
            if !isScanning && hasStarted && scanner.totalFiles > 0 {
                engine.recordDeepScan(fileCount: scanner.totalFiles)
                showResults = true
            }
        }
        .onAppear { scanner.engine = engine }
    }

    // MARK: - Scan actions group

    private var scanActionsGroup: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("SCAN")
                .font(.system(size: 11, weight: .semibold))
                .foregroundStyle(Color.textTertiary)
                .tracking(0.5)

            VStack(spacing: 0) {
                // Quick Scan row
                ScanActionRow(
                    icon: "bolt.fill", tint: .green,
                    title: "Quick Scan",
                    subtitle: "Scans Applications, Downloads, and all launch items",
                    buttonLabel: engine.isScanning ? "Scanning…" : "Run Scan",
                    isRunning: engine.isScanning,
                    action: { engine.runFullScan() }
                )

                Divider().padding(.leading, 58)

                // Deep Scan row
                ScanActionRow(
                    icon: "doc.text.magnifyingglass", tint: .blue,
                    title: "Deep Scan",
                    subtitle: "Scans all executables and scripts across the system",
                    buttonLabel: scanner.isScanning ? "Scanning…" : (scanner.isPaused ? "Paused" : "Start"),
                    isRunning: scanner.isScanning || scanner.isPaused,
                    action: {
                        if scanner.isScanning {
                            scanner.cancel(); hasStarted = false
                        } else {
                            hasStarted = true
                            Task { @MainActor in
                                scanner.start(onlyOnPower: onlyOnPower) { [engine] path in
                                    try await engine.scanFile(at: URL(fileURLWithPath: path))
                                }
                            }
                        }
                    }
                )

            }
            .background(
                RoundedRectangle(cornerRadius: 10, style: .continuous)
                    .fill(Color.backgroundSecondary)
            )
            .overlay(
                RoundedRectangle(cornerRadius: 10, style: .continuous)
                    .strokeBorder(Color.borderSubtle, lineWidth: 0.5)
            )
        }
    }

    // MARK: - Deep scan progress (inline, shown while scanning/paused)

    private var deepScanProgressGroup: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("DEEP SCAN PROGRESS")
                .font(.system(size: 11, weight: .semibold))
                .foregroundStyle(Color.textTertiary)
                .tracking(0.5)

            VStack(alignment: .leading, spacing: 10) {
                if scanner.isPaused {
                    HStack(spacing: 8) {
                        Image(systemName: "pause.circle.fill")
                            .foregroundStyle(Color.statusOrange)
                        Text("Paused — connect to AC power to continue")
                            .font(.system(size: 13))
                            .foregroundStyle(Color.textSecondary)
                        Spacer()
                    }
                } else {
                    // Progress bar
                    GeometryReader { proxy in
                        ZStack(alignment: .leading) {
                            Capsule().fill(Color.backgroundTertiary).frame(height: 4)
                            Capsule()
                                .fill(Color.blue)
                                .frame(width: max(4, proxy.size.width * scanner.progress), height: 4)
                                .animation(.linear(duration: 0.3), value: scanner.progress)
                        }
                    }
                    .frame(height: 4)

                    HStack {
                        Text("\(Int(scanner.progress * 100))% · \(scanner.scannedFiles.formatted()) / \(scanner.totalFiles.formatted()) files")
                            .font(.system(size: 12, design: .monospaced))
                            .foregroundStyle(Color.textSecondary)
                        Spacer()
                        if scanner.estimatedRemaining > 0 {
                            Text("~\(formatTime(scanner.estimatedRemaining)) remaining")
                                .font(.system(size: 11, design: .monospaced))
                                .foregroundStyle(Color.textTertiary)
                        }
                    }

                    Text(scanner.currentFile)
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundStyle(Color.textTertiary)
                        .lineLimit(1)
                        .truncationMode(.middle)

                    if scanner.threatsFound > 0 {
                        Label("\(scanner.threatsFound) threats found", systemImage: "exclamationmark.triangle.fill")
                            .font(.system(size: 12))
                            .foregroundStyle(Color.statusRed)
                    }
                }

                Button("Cancel") {
                    scanner.cancel()
                    hasStarted = false
                }
                .buttonStyle(.bordered)
                .controlSize(.small)
            }
            .padding(16)
            .background(
                RoundedRectangle(cornerRadius: 10, style: .continuous)
                    .fill(Color.backgroundSecondary)
            )
            .overlay(
                RoundedRectangle(cornerRadius: 10, style: .continuous)
                    .strokeBorder(Color.borderSubtle, lineWidth: 0.5)
            )
        }
    }

    // MARK: - Options group

    private var optionsGroup: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("OPTIONS")
                .font(.system(size: 11, weight: .semibold))
                .foregroundStyle(Color.textTertiary)
                .tracking(0.5)

            VStack(spacing: 0) {
                // AC power toggle
                HStack(spacing: 12) {
                    IconTile(systemImage: "bolt.fill", tint: .green, size: 36)
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Only scan while on AC power")
                            .font(.system(size: 13, weight: .medium))
                            .foregroundStyle(Color.textPrimary)
                        Text("Save battery during deep scans by pausing on battery power")
                            .font(.system(size: 11))
                            .foregroundStyle(Color.textSecondary)
                    }
                    Spacer()
                    Toggle("", isOn: $onlyOnPower)
                        .toggleStyle(.switch)
                        .labelsHidden()
                }
                .padding(.horizontal, 16)
                .padding(.vertical, 12)

                Divider().padding(.leading, 64)

                // Notify on completion toggle
                HStack(spacing: 12) {
                    IconTile(systemImage: "bell.fill", tint: .red, size: 36)
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Notify when scan completes")
                            .font(.system(size: 13, weight: .medium))
                            .foregroundStyle(Color.textPrimary)
                        Text("Show a Notification Center alert with the results")
                            .font(.system(size: 11))
                            .foregroundStyle(Color.textSecondary)
                    }
                    Spacer()
                    Toggle("", isOn: $notifyOnCompletion)
                        .toggleStyle(.switch)
                        .labelsHidden()
                }
                .padding(.horizontal, 16)
                .padding(.vertical, 12)
            }
            .background(
                RoundedRectangle(cornerRadius: 10, style: .continuous)
                    .fill(Color.backgroundSecondary)
            )
            .overlay(
                RoundedRectangle(cornerRadius: 10, style: .continuous)
                    .strokeBorder(Color.borderSubtle, lineWidth: 0.5)
            )

            Text("YARA-powered scanning. Rules are updated automatically.")
                .font(.system(size: 11))
                .foregroundStyle(Color.textTertiary)
                .padding(.top, 4)
        }
    }

    // MARK: - Drop zone (kept for DeepScanResultsView – no longer used as main UI)

    private var dropZone: some View { EmptyView() }

    // MARK: - Deep Scan section (legacy – replaced by action rows)

    private var deepScanSection: some View { EmptyView() }

    private var deepScanPaused: some View { EmptyView() }

    // MARK: - Helpers

    private func resetDeepScan() {
        showResults = false
        hasStarted  = false
        scanner     = DeepScanner()
        scanner.engine = engine
    }

    private func addIgnored(_ path: String) {
        var paths = ignoredPaths
        paths.insert(path)
        ignoredPathsRaw = paths.joined(separator: "\n")
    }

    private func formatTime(_ t: TimeInterval) -> String {
        let total = Int(t)
        return String(format: "%d:%02d", total / 60, total % 60)
    }
}

// MARK: - ScanActionRow

/// An action row in the Scan view. Shows an IconTile, title, subtitle, and a small button.
private struct ScanActionRow: View {
    let icon:        String
    let tint:        Color
    let title:       String
    let subtitle:    String
    let buttonLabel: String
    let isRunning:   Bool
    let action:      () -> Void

    var body: some View {
        HStack(spacing: 12) {
            IconTile(systemImage: icon, tint: tint, size: 36)

            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                    .font(.system(size: 13, weight: .medium))
                    .foregroundStyle(Color.textPrimary)
                Text(subtitle)
                    .font(.system(size: 11))
                    .foregroundStyle(Color.textSecondary)
            }

            Spacer()

            Button(buttonLabel, action: action)
                .buttonStyle(.bordered)
                .controlSize(.small)
                .disabled(isRunning)
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 12)
    }
}

// MARK: - DeepScanResultsView
// Change 9: grouped results — Threats, Suspicious, Dev Artifacts (collapsed by default).

private struct DeepScanResultsView: View {

    let scanner:      DeepScanner
    let ignoredPaths: Set<String>
    let onIgnore:     (String) -> Void
    let onNewScan:    () -> Void

    @State private var verdicts:         [String: ThreatVerdict] = [:]
    @State private var showDevArtifacts  = false
    @State private var showAppData         = false

    // MARK: - Deduplication

    private var deduplicated: [(match: YARAMatch, count: Int)] {
        var counts:  [String: Int]       = [:]
        var first:   [String: YARAMatch] = [:]
        var ordered: [String]            = []
        for match in scanner.results {
            let key = "\(match.filePath)|\(match.ruleName)"
            if counts[key] == nil { ordered.append(key); first[key] = match }
            counts[key, default: 0] += 1
        }
        return ordered.compactMap { key in
            guard let match = first[key], let count = counts[key] else { return nil }
            return (match, count)
        }
    }

    private var visible: [(match: YARAMatch, count: Int)] {
        deduplicated.filter { !ignoredPaths.contains($0.match.filePath) }
    }

    private var threats:      [(match: YARAMatch, count: Int)] { visible.filter { verdicts[$0.match.filePath] == .threat } }
    private var suspicious:   [(match: YARAMatch, count: Int)] { visible.filter { let v = verdicts[$0.match.filePath]; return v == .suspicious || v == nil } }
    private var devArtifacts: [(match: YARAMatch, count: Int)] { visible.filter { let v = verdicts[$0.match.filePath]; return v == .developmentArtifact || v == .likelySafe } }
    private var appDataItems: [(match: YARAMatch, count: Int)] { visible.filter { verdicts[$0.match.filePath] == .applicationData } }

    // MARK: - Body

    var body: some View {
        VStack(spacing: 0) {
            // Back button + stats header
            VStack(alignment: .leading, spacing: NickSpacing.xs) {
                Button(action: onNewScan) {
                    Label("Back to Scan", systemImage: "chevron.left")
                        .font(.nickBodySmall)
                        .foregroundStyle(Color.statusBlue)
                }
                .buttonStyle(.plain)

                Divider().padding(.vertical, NickSpacing.xs)

                Text("Deep Scan Results")
                    .font(.nickSubtitle)
                    .foregroundStyle(Color.textPrimary)
                Text("\(scanner.totalFiles.formatted()) files · \(scanner.results.count) detection\(scanner.results.count == 1 ? "" : "s") · \(formatTime(scanner.elapsedTime))")
                    .font(.nickCaption)
                    .foregroundStyle(Color.textSecondary)
            }
            .padding(NickSpacing.lg)
            .background(Color.backgroundSecondary)

            Rectangle().fill(Color.borderSubtle).frame(height: 0.5)

            // Results
            ScrollView {
                VStack(alignment: .leading, spacing: NickSpacing.lg) {
                    resultSection(
                        title:   "Threats",
                        items:   threats,
                        color:   .statusRed,
                        emptyMessage: "No actionable threats found ✓"
                    )

                    resultSection(
                        title:   "Suspicious",
                        items:   suspicious,
                        color:   .statusOrange,
                        emptyMessage: nil
                    )

                    // Dev artifacts collapsed by default.
                    VStack(alignment: .leading, spacing: NickSpacing.sm) {
                        Button(action: { showDevArtifacts.toggle() }) {
                            HStack(spacing: NickSpacing.sm) {
                                Text("── Development Artifacts (\(devArtifacts.count))")
                                    .font(.nickCaption)
                                    .foregroundStyle(Color.textTertiary)
                                Image(systemName: showDevArtifacts ? "chevron.up" : "chevron.down")
                                    .font(.system(size: 9))
                                    .foregroundStyle(Color.textTertiary)
                                Spacer()
                            }
                        }
                        .buttonStyle(.plain)

                        if showDevArtifacts {
                            ForEach(devArtifacts, id: \.match.filePath) { item in
                                ResultRow(
                                    match:      item.match,
                                    count:      item.count,
                                    verdict:    verdicts[item.match.filePath],
                                    onIgnore:   { onIgnore(item.match.filePath) }
                                )
                                Divider().padding(.leading, NickSpacing.lg)
                            }
                        }
                    }

                    // Application data collapsed by default.
                    if !appDataItems.isEmpty {
                        VStack(alignment: .leading, spacing: NickSpacing.sm) {
                            Button(action: { showAppData.toggle() }) {
                                HStack(spacing: NickSpacing.sm) {
                                    Text("── Application Data (\(appDataItems.count))")
                                        .font(.nickCaption)
                                        .foregroundStyle(Color.textTertiary)
                                    Image(systemName: showAppData ? "chevron.up" : "chevron.down")
                                        .font(.system(size: 9))
                                        .foregroundStyle(Color.textTertiary)
                                    Spacer()
                                }
                            }
                            .buttonStyle(.plain)

                            if showAppData {
                                ForEach(appDataItems, id: \.match.filePath) { item in
                                    ResultRow(
                                        match:      item.match,
                                        count:      item.count,
                                        verdict:    verdicts[item.match.filePath],
                                        onIgnore:   { onIgnore(item.match.filePath) }
                                    )
                                    Divider().padding(.leading, NickSpacing.lg)
                                }
                            }
                        }
                    }
                }
                .padding(NickSpacing.lg)
            }

            Rectangle().fill(Color.borderSubtle).frame(height: 0.5)

            // Action buttons
            HStack(spacing: NickSpacing.md) {
                Button("New Scan", action: onNewScan).buttonStyle(.borderedProminent)
                Button("Export Report") { exportReport() }.buttonStyle(.bordered)
                Spacer()
            }
            .padding(NickSpacing.lg)
            .background(Color.backgroundSecondary)
        }
        .navigationTitle("Scan Results")
        .task { await classifyResults() }
    }

    // MARK: - Result section builder

    @ViewBuilder
    private func resultSection(
        title:        String,
        items:        [(match: YARAMatch, count: Int)],
        color:        Color,
        emptyMessage: String?
    ) -> some View {
        VStack(alignment: .leading, spacing: NickSpacing.sm) {
            Text("── \(title) (\(items.count))")
                .font(.nickCaption)
                .foregroundStyle(color)

            if items.isEmpty, let msg = emptyMessage {
                Text(msg)
                    .font(.nickBodySmall)
                    .foregroundStyle(Color.textTertiary)
                    .padding(.leading, NickSpacing.lg)
            } else {
                ForEach(items, id: \.match.filePath) { item in
                    ResultRow(
                        match:    item.match,
                        count:    item.count,
                        verdict:  verdicts[item.match.filePath],
                        onIgnore: { onIgnore(item.match.filePath) }
                    )
                    Divider().padding(.leading, NickSpacing.lg)
                }
            }
        }
    }

    // MARK: - Verdict classification

    private func classifyResults() async {
        var result: [String: ThreatVerdict] = [:]
        for match in scanner.results {
            let verdict = await Task.detached(priority: .utility) {
                DeepScanResultsView.classify(match: match)
            }.value
            result[match.filePath] = verdict
        }
        verdicts = result
    }

    nonisolated private static func classify(match: YARAMatch) -> ThreatVerdict {
        let path = match.filePath.lowercased()

        // Category A: Build artifacts — path check is safe (build system output, not app data).
        let buildArtifacts = ["deriveddata", "workspacestorage", ".git/", "node_modules",
                              "__pycache__", ".build/"]
        if buildArtifacts.contains(where: { path.contains($0) }) { return .developmentArtifact }

        // Category B: Application runtime data — verify the parent app is signed before trusting.
        // This replaces all hardcoded cache/app-name exclusions. An attacker cannot gain trusted
        // status by mimicking a known app name without a corresponding signed .app bundle.
        if isInsideSignedAppData(path: match.filePath) { return .applicationData }

        let signing = SignatureValidator.shared.evaluate(binaryPath: match.filePath)
        if case .signed = signing { return .likelySafe }

        let suspiciousPrefixes = ["/tmp", "/var/tmp", "/private/tmp"]
        if suspiciousPrefixes.contains(where: { match.filePath.hasPrefix($0) }) { return .suspicious }

        return .suspicious
    }

    /// Returns `true` when `path` is inside the data container of a signed `.app` bundle.
    ///
    /// Extracts the app name from paths containing `/Application Support/`, `/Caches/`, or
    /// `/WebKit/`, then locates a matching `.app` bundle in standard install directories and
    /// verifies it carries a valid Developer ID signature.
    ///
    /// This replaces all hardcoded path-based exclusions for browser caches, IDE workspaces,
    /// editing sessions, GPU caches, and other app runtime data. An attacker cannot gain
    /// trusted status simply by placing files under a path named after a known application.
    nonisolated private static func isInsideSignedAppData(path: String) -> Bool {
        let markers = ["/Application Support/", "/Caches/", "/WebKit/"]
        guard markers.contains(where: { path.range(of: $0, options: .caseInsensitive) != nil }) else {
            return false
        }

        for marker in markers {
            guard let range = path.range(of: marker, options: .caseInsensitive) else { continue }
            let afterMarker = String(path[range.upperBound...])
            let appName = afterMarker.components(separatedBy: "/").first ?? ""
            guard !appName.isEmpty else { continue }

            // Search standard install locations for a matching signed .app bundle.
            let candidates = [
                "/Applications/\(appName).app",
                "/Applications/\(appName) Desktop.app",
                "/System/Applications/\(appName).app",
                NSHomeDirectory() + "/Applications/\(appName).app"
            ]
            let fm = FileManager.default
            for candidate in candidates {
                guard fm.fileExists(atPath: candidate) else { continue }
                let status = SignatureValidator.shared.evaluate(binaryPath: candidate)
                if case .signed = status { return true }
            }
        }
        return false
    }

    // MARK: - Export (Change 10)

    private func exportReport() {
        struct ExportResult: Encodable {
            var rule_name: String
            var severity: String
            var verdict: String
            var file_path: String
            var file_size: Int64
            var description: String
        }
        struct Report: Encodable {
            var scan_date: String
            var scan_duration_seconds: Int
            var files_scanned: Int
            var nick_version: String
            var yara_version: String
            var results: [ExportResult]
        }

        let fm  = FileManager.default
        let iso = ISO8601DateFormatter()
        let rows: [ExportResult] = visible.map { item in
            let size  = (try? fm.attributesOfItem(atPath: item.match.filePath)[.size] as? Int64) ?? 0
            let sev   = item.match.metadata["severity"] ?? "UNKNOWN"
            let desc  = item.match.metadata["description"] ?? ""
            let verd  = verdicts[item.match.filePath]?.rawValue ?? ThreatVerdict.suspicious.rawValue
            return ExportResult(rule_name: item.match.ruleName, severity: sev, verdict: verd,
                                file_path: item.match.filePath, file_size: size, description: desc)
        }
        let version = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "1.0"
        let report  = Report(
            scan_date:              iso.string(from: Date()),
            scan_duration_seconds:  Int(scanner.elapsedTime),
            files_scanned:          scanner.totalFiles,
            nick_version:           version,
            yara_version:           "4.5.2",
            results:                rows
        )

        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        guard let data = try? encoder.encode(report) else { return }

        let panel = NSSavePanel()
        let today = DateFormatter.localizedString(from: Date(), dateStyle: .short, timeStyle: .none)
            .replacingOccurrences(of: "/", with: "-")
        panel.nameFieldStringValue = "nick-deep-scan-\(today).json"
        panel.allowedContentTypes  = [.json]
        panel.begin { response in
            guard response == .OK, let url = panel.url else { return }
            try? data.write(to: url)
        }
    }

    private func formatTime(_ t: TimeInterval) -> String {
        let total = Int(t); return String(format: "%d:%02d", total / 60, total % 60)
    }
}

// MARK: - ResultRow

private struct ResultRow: View {

    let match:   YARAMatch
    let count:   Int
    let verdict: ThreatVerdict?
    let onIgnore: () -> Void

    var body: some View {
        HStack(alignment: .top, spacing: NickSpacing.sm) {
            Text("▸")
                .font(.nickBodySmall)
                .foregroundStyle(rowColor)
                .padding(.top, 1)
            VStack(alignment: .leading, spacing: NickSpacing.xs) {
                HStack(spacing: NickSpacing.sm) {
                    Text(count > 1 ? "\(match.ruleName) (×\(count))" : match.ruleName)
                        .font(.nickBodyMedium)
                        .foregroundStyle(Color.textPrimary)
                    Spacer()
                    if let sev = match.metadata["severity"],
                       verdict != .applicationData && verdict != .likelySafe && verdict != .developmentArtifact {
                        Text(sev)
                            .font(.nickCaption)
                            .foregroundStyle(sevColor(sev))
                            .padding(.horizontal, NickSpacing.sm)
                            .padding(.vertical, NickSpacing.xs)
                            .background(sevColor(sev).opacity(0.12))
                            .clipShape(RoundedRectangle(cornerRadius: NickLayout.badgeCornerRadius))
                    }
                }
                if let v = verdict {
                    Text(v.rawValue)
                        .font(.nickCaption)
                        .foregroundStyle(Color.textSecondary)
                }
                if let desc = match.metadata["description"] {
                    Text(desc)
                        .font(.nickBodySmall)
                        .foregroundStyle(Color.textSecondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Text(match.filePath)
                    .font(.nickMonoSmall)
                    .foregroundStyle(Color.textTertiary)
                    .lineLimit(1)
                    .truncationMode(.middle)
                HStack(spacing: NickSpacing.lg) {
                    Button("Show in Finder") {
                        NSWorkspace.shared.selectFile(match.filePath, inFileViewerRootedAtPath: "")
                    }
                    .font(.nickCaption)
                    .foregroundStyle(Color.statusBlue)
                    .buttonStyle(.plain)
                    Button("Ignore") { onIgnore() }
                        .font(.nickCaption)
                        .foregroundStyle(Color.textTertiary)
                        .buttonStyle(.plain)
                }
            }
        }
        .padding(.vertical, NickSpacing.sm)
    }

    private var rowColor: Color {
        switch verdict {
        case .threat:              return .statusRed
        case .suspicious, nil:     return .statusOrange
        case .developmentArtifact, .applicationData, .likelySafe: return .textTertiary
        }
    }

    private func sevColor(_ sev: String) -> Color {
        switch sev.uppercased() {
        case "HIGH":   return .statusRed
        case "MEDIUM": return .statusYellow
        case "LOW":    return .statusGreen
        default:       return .textTertiary
        }
    }
}

