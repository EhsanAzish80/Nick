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

// MARK: - System Preferences URLs
// Extracted as constants so they can be updated in one place if Apple changes the scheme.
private enum SystemPrefsURL {
    /// Opens the Notifications pane in System Settings.
    static let notifications = URL(string: "x-apple.systempreferences:com.apple.Notifications-Settings")!
}

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
    @AppStorage("appAppearance") private var appAppearance: AppAppearance = .system
    @State private var notificationsDenied = false

    private var resolvedColorScheme: ColorScheme? {
        switch appAppearance {
        case .dark:   return .dark
        case .light:  return .light
        case .system: return nil
        }
    }

    // Count only alerts that the consumer-facing assessment considers actionable.
    private var activeAlertCount: Int {
        engine.userFacingAlerts.filter { $0.severity != .safe }.count
    }

    var body: some View {
        if !hasCompletedOnboarding {
            WelcomeView(hasCompletedOnboarding: $hasCompletedOnboarding)
        } else {
            ProtectionSetupGate {
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
                                NSWorkspace.shared.open(SystemPrefsURL.notifications)
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
            List(selection: $selectedSection) {
                SidebarNavItem(section: .overview)
                    .tag(SidebarSection.overview)
                SidebarNavItem(section: .smartScan)
                    .tag(SidebarSection.smartScan)

                Section("SECURITY") {
                    SidebarNavItem(
                        section:    .alerts,
                        badge:      activeAlertCount
                    )
                    .tag(SidebarSection.alerts)
                    SidebarNavItem(section: .scan).tag(SidebarSection.scan)
                    SidebarNavItem(section: .quarantine).tag(SidebarSection.quarantine)
                }

                Section("MONITORS") {
                    SidebarNavItem(section: .systemAudit).tag(SidebarSection.systemAudit)
                    SidebarNavItem(section: .network).tag(SidebarSection.network)
                    SidebarNavItem(section: .processes).tag(SidebarSection.processes)
                    SidebarNavItem(section: .persistence).tag(SidebarSection.persistence)
                }

                Section("DIAGNOSTICS") {
                    SidebarNavItem(section: .runtimeCompare).tag(SidebarSection.runtimeCompare)
                    SidebarNavItem(section: .performance).tag(SidebarSection.performance)
                }

                SidebarNavItem(section: .settings)
                    .tag(SidebarSection.settings)
            }
            .navigationSplitViewColumnWidth(min: 210, ideal: 250)
            .navigationTitle("Nick")
        } detail: {
            switch selectedSection ?? .overview {
            case .overview:    OverviewDetailView(selectedSection: $selectedSection)
            case .smartScan:   SmartScanDetailView()
            case .alerts:      AlertListView()
            case .scan:        ScannerDetailView()
            case .quarantine:  QuarantineView()
            case .systemAudit: SystemAuditView()
            case .network:     NetworkConnectionsView()
            case .processes:   ProcessListView()
            case .persistence: PersistenceDetailView()
            case .runtimeCompare: RuntimeCompareView()
            case .performance: PerformanceView()
            case .settings:    SettingsView()
            }
        }
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Button(action: { engine.runFullScan() }) {
                    Label("Run Scan", systemImage: "arrow.clockwise")
                }
                .disabled(engine.isScanning)
                .keyboardShortcut("r", modifiers: .command)
            }
        }
        .preferredColorScheme(resolvedColorScheme)
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
        .onReceive(NotificationCenter.default.publisher(for: .nickScanFileRequest)) { note in
            // Store the URL on the engine so the scanner view can pick it up
            // when it appears — avoids the race where the scanner view's
            // .onReceive hasn't registered yet during sidebar navigation.
            if let url = note.object as? URL {
                engine.pendingFinderScanURL = url
            }
            selectedSection = .scan
        }
    }
}

enum SidebarSection: String, CaseIterable, Identifiable, Hashable {
    case overview    = "Overview"
    case smartScan   = "Smart Scan"
    case alerts      = "Alerts"
    case scan        = "Scan"
    case quarantine  = "Quarantine"
    case systemAudit = "System Audit"
    case network     = "Network"
    case processes   = "Processes"
    case persistence = "Persistence"
    case runtimeCompare = "Runtime Compare"
    case performance = "Performance"
    case settings    = "Settings"

    var id: String { rawValue }

    var title: String { id }

    var icon: String {
        switch self {
        case .overview:    return "shield.checkered"
        case .smartScan:   return "sparkle.magnifyingglass"
        case .alerts:      return "exclamationmark.triangle.fill"
        case .scan:        return "doc.text.magnifyingglass"
        case .quarantine:  return "archivebox.fill"
        case .systemAudit: return "checkmark.shield"
        case .network:     return "network"
        case .processes:   return "cpu"
        case .persistence: return "arrow.triangle.2.circlepath"
        case .runtimeCompare: return "square.split.2x1"
        case .performance: return "gauge.medium"
        case .settings:    return "gearshape.fill"
        }
    }

    /// Accent tint for this section's IconTile in the sidebar.
    var tint: Color {
        switch self {
        case .overview:    return .blue
        case .smartScan:   return .blue
        case .alerts:      return .red
        case .scan:        return Color(NSColor.systemGray)
        case .quarantine:  return .orange
        case .systemAudit: return .green
        case .network:     return .blue
        case .processes:   return .purple
        case .persistence: return .orange
        case .runtimeCompare: return .indigo
        case .performance: return .mint
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

/// A sidebar list row with a plain SF Symbol icon and an optional alert count badge.
private struct SidebarNavItem: View {

    let section:    SidebarSection
    var badge:      Int  = 0
    var isDisabled: Bool = false

    var body: some View {
        Label {
            HStack {
                Text(section.title)
                    .font(.system(size: 13))
                Spacer()
                if badge > 0 {
                    Text("\(badge)")
                        .font(.system(size: 11, weight: .semibold))
                        .foregroundStyle(.white)
                        .padding(.horizontal, 6)
                        .padding(.vertical, 2)
                        .background(Capsule().fill(Color.statusRed))
                }
            }
        } icon: {
            Image(systemName: section.icon)
                .font(.system(size: 14))
                .foregroundStyle(.secondary)
        }
        .disabled(isDisabled)
    }
}

// MARK: - SmartScanDetailView

/// Sidebar detail view for Smart Scan. Uses `SmartScanContentView` which
/// is self-contained: runs the scan on appear, handles individual fixes,
/// Fix All, and shows the summary inline.
private struct SmartScanDetailView: View {
    var body: some View {
        SmartScanContentView()
            .navigationTitle("Smart Scan")
    }
}

// MARK: - OverviewDetailView

/// Apple-native Overview screen: hero row → score card → status list →
/// protection summary → recent activity.
struct OverviewDetailView: View {

    @Binding var selectedSection: SidebarSection?
    @Environment(SecurityEngine.self) private var engine
    @Environment(ExtensionXPCClient.self) private var xpcClient
    @Environment(NetworkProtectionManager.self) private var networkProtection

    @AppStorage("deepScanIntervalSeconds") private var scanIntervalSeconds: Int = 300
    @State private var focusModeActive = false

    // MARK: - Derived

    private var auditIssues:       Int { engine.auditResults.filter { $0.status != .pass }.count }
    private var persistenceIssues: Int { engine.persistenceItems.filter { $0.signingStatus?.isSuspicious == true }.count }
    private var processIssues:     Int { engine.processes.filter { $0.signingStatus == .unsigned || $0.signingStatus == .invalid }.count }
    private var networkIssues:     Int { engine.connections.filter { $0.isShellProcess && $0.isOutbound }.count }
    private var totalIssues: Int {
        auditIssues + persistenceIssues + processIssues + networkIssues
            + (xpcClient.isConnected ? 0 : 1)
    }

    private var statusLine: String {
        guard !engine.isScanning else { return "Scan in progress…" }
        var parts: [String] = []
        if let last = engine.lastScanDate {
            parts.append("Last scan \(last.formatted(.relative(presentation: .named)))")
        }
        let n = engine.totalThreatsDetected
        parts.append(n == 0 ? "No threats blocked" : "\(n) threat\(n == 1 ? "" : "s") blocked")
        parts.append(
            xpcClient.isConnected
                ? "Real-time protection active"
                : "Real-time protection needs attention"
        )
        return parts.joined(separator: " · ")
    }

    /// Uses the same live extension heartbeat as Smart Scan. The former
    /// UserDefaults flag could remain false even after the extension deployed
    /// and verified its sentinels, making Overview contradict Smart Scan.
    private var ransomwareShieldActive: Bool {
        let path = "/Library/Application Support/com.ehsanazish.nick/extension_health.json"
        guard
            let data = FileManager.default.contents(atPath: path),
            let health = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
            health["active"] as? Bool == true,
            (health["canaryCount"] as? Int ?? 0) > 0,
            let updatedAt = health["updatedAt"] as? TimeInterval
        else {
            return false
        }
        let age = Date().timeIntervalSince1970 - updatedAt
        return age >= 0 && age <= 30
    }

    // MARK: - Body

    var body: some View {
        VStack(spacing: 0) {
            // Fixed top: status headline + feature tiles
            VStack(spacing: 12) {
                statusHeader
                    .padding(.horizontal, 20)
                    .padding(.top, 16)
                featureTilesSection
                    .padding(.horizontal, 20)
                    .padding(.bottom, 8)
            }
            .padding(.bottom)

            //Divider()

            // Expanding: activity table + footer
            VStack(spacing: 0) {
                recentActivitySection
                    .padding(.horizontal, 20)
                    .padding(.top, 8)
                protectionFooter
                    .padding(.horizontal, 20)
                    .padding(.top, 4)
                    .padding(.bottom, 12)
            }
        }
        .background(Color(.windowBackgroundColor))
        .navigationTitle("Overview")
        .onAppear {
            focusModeActive = isFocusModeActive()
        }
        .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in
            focusModeActive = isFocusModeActive()
        }
    }

    // MARK: - Section 1: Status Header

    private var statusHeader: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 10) {
                Image(systemName: totalIssues == 0 ? "checkmark.shield.fill" : "exclamationmark.shield.fill")
                    .font(.title2)
                    .foregroundStyle(totalIssues == 0 ? Color.statusGreen : Color.statusOrange)
                Text(totalIssues == 0
                     ? "Your Mac is protected"
                     : "\(totalIssues) issue\(totalIssues == 1 ? "" : "s") need attention")
                    .font(.title2.bold())
                Spacer()
                Button("Smart Scan") {
                    selectedSection = .smartScan
                }
                .buttonStyle(.bordered)
                .controlSize(.small)
                Button("Scan a File") {
                    let panel = NSOpenPanel()
                    panel.prompt = "Scan"
                    panel.allowsMultipleSelection = false
                    panel.begin { result in
                        guard result == .OK, let url = panel.url else { return }
                        engine.pendingFinderScanURL = url
                        selectedSection = .scan
                    }
                }
                .buttonStyle(.plain)
                .font(.system(size: 13))
                .foregroundStyle(Color.blue)
                .controlSize(.small)
            }
            Text(statusLine)
                .font(.subheadline)
                .foregroundStyle(.secondary)
        }
    }

    // MARK: - Section 2: Feature Tiles

    private struct FeatureTileItem {
        let name:     String
        let icon:     String
        let tint:     Color
        let section:  SidebarSection
        let subtitle: String
        let active:   Bool
    }

    private var featureTileItems: [FeatureTileItem] {
        let todayCount = xpcClient.events.filter {
            Calendar.current.isDateInToday($0.timestamp)
        }.count
        let rtpSub = todayCount == 0 ? "Monitoring · no threats" : "\(todayCount) event\(todayCount == 1 ? "" : "s") today"

        let canariesDeployed = ransomwareShieldActive
        let ransomSub = canariesDeployed ? "Sentinels active" : "Not enabled"

        let qCount = xpcClient.quarantineRecords.count
        let qSub = qCount == 0 ? "Empty" : "\(qCount) item\(qCount == 1 ? "" : "s")"

        let connCount = engine.connections.count
        let netSub = connCount == 0
            ? "No active connections"
            : "\(connCount) connection\(connCount == 1 ? "" : "s") active"
        let scamActive = networkProtection.isEnabled
        let scamSub: String
        switch networkProtection.state {
        case .loading:
            scamSub = "Checking filter status"
        case .enabled:
            scamSub = "Monitoring phishing destinations"
        case .awaitingApproval:
            scamSub = "Approval required"
        case .disabled:
            scamSub = "Not enabled"
        case .failed:
            scamSub = "Filter is not running"
        }

        let privCount = xpcClient.privacyAlerts.count
        let privSub = !xpcClient.isConnected
            ? "Waiting for security extension"
            : privCount == 0
                ? "Monitoring · no alerts"
                : "\(privCount) alert\(privCount == 1 ? "" : "s")"

        let emailCount = xpcClient.events.filter { $0.threatFamily == "EmailThreat" }.count
        let emailSub = !xpcClient.isConnected
            ? "Waiting for security extension"
            : emailCount == 0
                ? "Monitoring · no threats"
                : "\(emailCount) threat\(emailCount == 1 ? "" : "s") detected"

        let perfBytes = engine.performanceMonitor?.totalReclaimableBytes ?? 0
        let perfSub: String
        if perfBytes == 0 {
            perfSub = "Tap to scan"
        } else if perfBytes >= 1_000_000_000 {
            perfSub = String(format: "%.1f GB reclaimable", Double(perfBytes) / 1_000_000_000)
        } else {
            perfSub = String(format: "%.0f MB reclaimable", Double(perfBytes) / 1_000_000)
        }

        let smartSub: String
        let smartActive: Bool
        if let last = engine.lastScanDate {
            let mins = Int(Date().timeIntervalSince(last) / 60)
            let result = totalIssues == 0 ? "All clear" : "\(totalIssues) need attention"
            smartSub = mins < 60
                ? "Last: \(mins)m ago · \(result)"
                : "Last: \(mins / 60)h ago · \(result)"
            smartActive = totalIssues == 0
        } else {
            smartSub = "Not run yet"
            smartActive = false
        }

        return [
            FeatureTileItem(name: "Real-Time Protection", icon: "shield.fill",
                            tint: .green,   section: .alerts,      subtitle: rtpSub,        active: xpcClient.isConnected),
            FeatureTileItem(name: "Ransomware Shield",    icon: "lock.shield.fill",
                            tint: .orange,  section: .alerts,      subtitle: ransomSub,     active: canariesDeployed),
            FeatureTileItem(name: "Network Monitor",      icon: "network",
                            tint: .blue,    section: .network,     subtitle: netSub,        active: connCount > 0),
            FeatureTileItem(name: "Scam Guardian",        icon: "globe.badge.chevron.backward",
                            tint: .orange,  section: .smartScan,   subtitle: scamSub,       active: scamActive),
            FeatureTileItem(name: "Privacy Guard",        icon: "hand.raised.fill",
                            tint: .indigo,  section: .systemAudit, subtitle: privSub,       active: xpcClient.isConnected),
            FeatureTileItem(name: "Email Guard",          icon: "envelope.badge.shield.half.filled",
                            tint: .teal,    section: .alerts,      subtitle: emailSub,      active: xpcClient.isConnected),
            FeatureTileItem(name: "Performance",          icon: "gauge.medium",
                            tint: .mint,    section: .performance, subtitle: perfSub,       active: perfBytes > 0),
            FeatureTileItem(name: "Smart Scan",           icon: "sparkle.magnifyingglass",
                            tint: .blue,    section: .smartScan,   subtitle: smartSub,      active: smartActive),
            FeatureTileItem(name: "Quarantine",           icon: "archivebox.fill",
                            tint: .orange,  section: .quarantine,  subtitle: qSub,          active: true),
        ]
    }

    private var featureTilesSection: some View {
        LazyVGrid(
            columns: Array(repeating: GridItem(.flexible(), spacing: 10), count: 4),
            spacing: 10
        ) {
            ForEach(featureTileItems, id: \.name) { tile in
                    Button { selectedSection = tile.section } label: {
                        VStack(alignment: .leading, spacing: 6) {
                            Image(systemName: tile.icon)
                                .font(.title2)
                                .foregroundStyle(tile.tint)
                            Text(tile.name)
                                .font(.headline)
                                .foregroundStyle(Color.textPrimary)
                                .lineLimit(2)
                                .multilineTextAlignment(.leading)
                                .fixedSize(horizontal: false, vertical: true)
                            Text(tile.subtitle)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                                .lineLimit(2)
                                .multilineTextAlignment(.leading)
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(12)
//                        .background(
//                            RoundedRectangle(cornerRadius: 10, style: .continuous)
//                                .fill(Color.backgroundSecondary)
//                        )
//                        .overlay(
//                            RoundedRectangle(cornerRadius: 10, style: .continuous)
//                                .strokeBorder(Color.borderSubtle, lineWidth: 0.5)
//                        )
                    }
                    .buttonStyle(.glass)
                }
            }
    }

    // MARK: - Section 3: Recent Activity

    private var recentActivitySection: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Spacer()
                Button("View all") { selectedSection = .alerts }
                    .font(.system(size: 12))
                    .foregroundStyle(Color.blue)
                    .buttonStyle(.plain)
            }

            if engine.activityLog.events.isEmpty {
                Text("No activity yet — Nick is watching.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.vertical, 8)
            } else {
                Table(engine.activityLog.events) {
                    TableColumn("Time") { entry in
                        Text(compactTimestamp(entry.timestamp))
                            .font(.system(.caption, design: .monospaced))
                            .foregroundStyle(.secondary)
                    }
                    .width(min: 36, ideal: 46, max: 56)

                    TableColumn("Event") { entry in
                        Text(entry.repeatCount > 1 ? "\(entry.title) × \(entry.repeatCount)" : entry.title)
                            .font(.caption)
                    }
                    .width(min: 140, ideal: 180)

                    TableColumn("Detail") { entry in
                        Text(entry.subtitle)
                            .font(.system(.caption, design: .monospaced))
                            .foregroundStyle(.secondary)
                    }

                    TableColumn("") { entry in
                        Image(systemName: entry.icon)
                            .foregroundStyle(activityColor(entry.iconColor))
                            .font(.caption2)
                    }
                    .width(18)
                }
                .tableStyle(.bordered(alternatesRowBackgrounds: true))
            }
        }
    }

    // MARK: - Section 4: Footer Stats

    private var protectionFooter: some View {
        HStack(spacing: 0) {
            footerStat(
                label: "Monitoring since",
                value: engine.monitoringSince.formatted(date: .abbreviated, time: .omitted)
            )
            footerDot()
            footerStat(label: "Total scans", value: engine.totalScanCount.formatted())
            footerDot()
            footerStat(label: "Threats blocked", value: engine.totalThreatsDetected.formatted())
            if focusModeActive {
                footerDot()
                HStack(spacing: 4) {
                    Image(systemName: "moon.fill")
                        .font(.system(size: 10))
                        .foregroundStyle(Color.statusOrange)
                    Text("Focus Mode on")
                        .font(.system(size: 11))
                        .foregroundStyle(Color.statusOrange)
                }
            }
            Spacer()
        }
    }

    private func footerStat(label: String, value: String) -> some View {
        HStack(spacing: 4) {
            Text("\(label):")
                .font(.system(size: 11))
                .foregroundStyle(Color.textTertiary)
            Text(value)
                .font(.system(size: 11, weight: .medium))
                .foregroundStyle(Color.textSecondary)
        }
    }

    private func footerDot() -> some View {
        Text("·")
            .font(.system(size: 11))
            .foregroundStyle(Color.textTertiary)
            .padding(.horizontal, 8)
    }

    // MARK: - Helpers

    private func activityColor(_ string: String) -> Color {
        switch string {
        case "green":  return .statusGreen
        case "blue":   return .statusBlue
        case "yellow": return .statusYellow
        case "red":    return .statusRed
        default:       return .textTertiary
        }
    }

    private func compactTimestamp(_ date: Date) -> String {
        let age = Date().timeIntervalSince(date)
        if age < 60 { return "<1m" }
        let mins = Int(age / 60)
        if mins < 60 { return "\(mins)m" }
        let hrs = mins / 60
        if hrs < 24 { return "\(hrs)h" }
        return "\(hrs / 24)d"
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

    // Deprecated stub — rendering is handled directly inside OverviewDetailView.
    // Retained so that any existing call sites continue to compile without changes.
    var body: some View { EmptyView() }
}

private struct SummaryRow: View {
    let icon:  String
    let label: String
    let value: String
    // Deprecated stub — use the `summaryRow(label:value:)` helper on OverviewDetailView instead.
    var body: some View { EmptyView() }
}

private struct RecentActivityView: View {
    let events:    [ActivityEvent]
    let onViewAll: () -> Void
    // Deprecated stub — rendering is handled directly inside OverviewDetailView.recentActivityGroup.
    var body: some View { EmptyView() }
}

/// Full-width table of running processes with sortable columns.
struct ProcessListView: View {

    @Environment(SecurityEngine.self) private var engine
    @Environment(ExtensionXPCClient.self) private var xpcClient
    @State private var sortOrder = [KeyPathComparator<NickProcessInfo>(\NickProcessInfo.name)]
    @State private var searchText = ""
    @State private var viewMode = 0

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
        Group {
            if viewMode == 1 {
                ProcessTreeView()
            } else if filtered.isEmpty {
                ContentUnavailableView(
                    searchText.isEmpty ? "No Processes Available" : "No Matching Processes",
                    systemImage: searchText.isEmpty ? "cpu" : "magnifyingglass",
                    description: Text(
                        searchText.isEmpty
                            ? "Run a scan to load the current process list."
                            : "No process matches “\(searchText)”."
                    )
                )
            } else {
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
            } // end else (List mode)
        }
        .navigationTitle("Processes")
        .navigationSubtitle("\(engine.processes.count) running · \(flaggedCount) flagged")
        .toolbar {
            ToolbarItem(placement: .automatic) {
                Picker("View", selection: $viewMode) {
                    Text("List").tag(0)
                    Text("Tree").tag(1)
                }
                .pickerStyle(.segmented)
                .frame(width: 140)
            }
        }
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
            Button("Cancel", role: .cancel) {
                ///no need to do anythig
            }
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

    // MARK: - Scan File (specific file/folder picker) state
    @State private var fileScanURL:       URL?          = nil
    @State private var fileScanResults:   [YARAMatch]   = []
    @State private var isFileScanRunning: Bool          = false
    @State private var fileScanError:     String?       = nil
    @State private var fileScanSummary:   FileScanSummary? = nil
    @State private var fileScanDuration:  TimeInterval  = 0
    @State private var showFileScanSheet: Bool          = false

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
        .onAppear {
            scanner.engine = engine
            // Consume any pending Finder "Scan with Nick" URL that was stored
            // before this view appeared (fixes race with notification timing).
            if let pendingURL = engine.pendingFinderScanURL {
                engine.pendingFinderScanURL = nil
                startFileScan(url: pendingURL)
            }
        }
        .onReceive(NotificationCenter.default.publisher(for: .nickScanFileRequest)) { note in
            guard let url = note.object as? URL else { return }
            startFileScan(url: url)
        }
        .sheet(isPresented: $showFileScanSheet) {
            if let url = fileScanURL {
                FileScanResultsView(
                    url:        url,
                    results:    fileScanResults,
                    isScanning: isFileScanRunning,
                    error:      fileScanError,
                    summary:    fileScanSummary,
                    duration:   fileScanDuration
                )
            }
        }
    }

    // MARK: - Scan actions group

    private var scanActionsGroup: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("SCAN")
                .font(.system(size: 11, weight: .semibold))
                .foregroundStyle(Color.textTertiary)
                .tracking(1)

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

                // Scan File row
                ScanActionRow(
                    icon: "doc.viewfinder", tint: .purple,
                    title: "Scan File",
                    subtitle: "Pick any file or folder and scan it with YARA rules",
                    buttonLabel: isFileScanRunning ? "Scanning…" : "Choose…",
                    isRunning: isFileScanRunning,
                    action: { openFilePicker() }
                )

                Divider().padding(.leading, 58)

                // Deep Scan row
                ScanActionRow(
                    icon: "doc.text.magnifyingglass", tint: .blue,
                    title: "Deep Scan",
                    subtitle: "Scans all executables and scripts across the system",
                    buttonLabel: deepScanButtonLabel,
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
                .tracking(1)

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
                .tracking(1)

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
    // Legacy: drag-and-drop target was replaced by the ScanActionRow quick-scan button.
    private var dropZone: some View { EmptyView() }

    // MARK: - Deep Scan section (legacy – replaced by scanActionsGroup)
    // The inline progress bar and action buttons supersede this separate section view.
    private var deepScanSection: some View { Color.clear }

    // MARK: - Deep Scan paused state (legacy – replaced by deepScanProgressGroup)
    // The paused state is now rendered inline inside deepScanProgressGroup.
    private var deepScanPaused: some View { Color.clear }

    // MARK: - Helpers

    private var deepScanButtonLabel: String {
        if scanner.isScanning {
            return "Scanning…"
        } else if scanner.isPaused {
            return "Paused"
        } else {
            return "Start"
        }
    }

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

    // MARK: - Scan File helpers

    private func openFilePicker() {
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = true
        panel.allowsMultipleSelection = false
        panel.message = "Choose a file or folder to scan with YARA rules"
        panel.prompt = "Scan"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        startFileScan(url: url)
    }

    private func startFileScan(url: URL) {
        fileScanURL       = url
        fileScanResults   = []
        fileScanError     = nil
        fileScanSummary   = nil
        fileScanDuration  = 0
        isFileScanRunning = true
        showFileScanSheet = true
        let start = Date()
        Task { @MainActor in
            do {
                async let resultsTask = engine.scanFile(at: url)
                async let summaryTask = FileScanSummary.analyze(url: url)
                let (results, summary) = try await (resultsTask, summaryTask)
                fileScanResults = results
                fileScanSummary = summary
            } catch {
                fileScanError = error.localizedDescription
            }
            fileScanDuration  = Date().timeIntervalSince(start)
            isFileScanRunning = false
        }
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
                DeepScanner.classify(match: match)
            }.value
            result[match.filePath] = verdict
        }
        verdicts = result
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
