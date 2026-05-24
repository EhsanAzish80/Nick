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
    @Environment(\.openSettings) private var openSettings
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
            // Change 2: VStack so we can pin the Settings button below the nav list.
            VStack(spacing: 0) {
                List(selection: $selectedSection) {
                    ForEach(SidebarSection.allCases) { section in
                        if section == .alerts {
                            Label(section.title, systemImage: section.icon)
                                .badge(activeAlertCount)
                                .tag(section)
                                .disabled(activeAlertCount == 0)
                        } else {
                            Label(section.title, systemImage: section.icon)
                                .tag(section)
                        }
                    }
                }
                .navigationSplitViewColumnWidth(min: 180, ideal: 200)
                .navigationTitle("Nick")
                // Navigate away from Alerts when the last alert is dismissed.
                .onChange(of: activeAlertCount) { _, count in
                    if count == 0 && selectedSection == .alerts {
                        selectedSection = .overview
                    }
                }

                Divider()

                // SettingsLink reliably opens the SwiftUI Settings scene.
                SettingsLink {
                    Label("Settings", systemImage: "gearshape")
                        .font(.nickBodySmall)
                        .foregroundStyle(Color.textSecondary)
                }
                .buttonStyle(.plain)
                .padding(.horizontal, NickSpacing.lg)
                .padding(.vertical, NickSpacing.md)
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
        .onAppear {
            NSApp.setActivationPolicy(.regular)
            // Forward openSettings and openWindow actions to AppDelegate so status-bar
            // menu items can open these scenes without private selectors.
            (NSApp.delegate as? AppDelegate)?.openSettingsAction = { [openSettings] in
                openSettings()
            }
            (NSApp.delegate as? AppDelegate)?.openMainWindowAction = { [openWindow] in
                openWindow(id: "main")
            }
        }
        .onDisappear {
            // Return to menu-bar-only mode when the main window closes.
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
    // Change 7: Label in sidebar is "Scan"; title inside the view stays "Nick Scan".
    case scanner     = "Scan"

    var id: String { rawValue }

    var title: String { id }

    var icon: String {
        switch self {
        case .overview:    return "shield.checkered"
        case .audit:       return "checkmark.shield"
        case .network:     return "network"
        case .processes:   return "cpu"
        case .persistence: return "arrow.triangle.2.circlepath"
        case .alerts:      return "exclamationmark.triangle"
        case .scanner:     return "doc.text.magnifyingglass"
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

// MARK: - OverviewDetailView

/// Redesigned overview with circular security gauge, sparkline monitor cards,
/// recent activity feed, and protection summary.
struct OverviewDetailView: View {

    @Binding var selectedSection: SidebarSection?
    @Environment(SecurityEngine.self) private var engine

    @AppStorage("deepScanIntervalSeconds") private var scanIntervalSeconds: Int = 60
    @State private var now: Date = .now
    @State private var focusModeActive = false

    private let columns = [GridItem(.flexible()), GridItem(.flexible())]

    /// Seconds until the next scheduled sweep, counting down live.
    private var nextScanIn: Int {
        guard let last = engine.lastScanDate else { return scanIntervalSeconds }
        let elapsed = Int(now.timeIntervalSince(last))
        return max(0, scanIntervalSeconds - elapsed)
    }

    var body: some View {
        ScrollView {
            VStack(spacing: NickSpacing.xl) {

                // Circular security gauge — shown only after the first scan completes.
                if engine.hasCompletedFirstScan {
                    SecurityGauge(score: engine.healthScore)
                        .padding(.vertical, NickSpacing.lg)
                } else {
                    VStack(spacing: 8) {
                        ProgressView()
                            .scaleEffect(1.5)
                        Text("SCANNING")
                            .font(.system(size: 9, weight: .bold))
                            .tracking(2)
                            .foregroundStyle(Color.textTertiary)
                    }
                    .frame(height: 200)
                    .padding(.vertical, NickSpacing.lg)
                }

                // 2×2 monitor cards with sparklines.
                let auditIssues       = engine.auditResults.filter { $0.status != .pass }.count
                let persistenceIssues = engine.persistenceItems.filter { $0.signingStatus?.isSuspicious == true }.count
                let processIssues     = engine.processes.filter { $0.signingStatus == .unsigned || $0.signingStatus == .invalid }.count
                let networkIssues     = engine.connections.filter { $0.isShellProcess && $0.isOutbound }.count

                LazyVGrid(columns: columns, spacing: NickSpacing.lg) {
                    MonitorCard(
                        title:           "System Audit",
                        count:           engine.auditResults.count,
                        status:          statusLabel(issues: auditIssues),
                        statusColor:     statusColor(issues: auditIssues),
                        icon:            "checkmark.shield",
                        sparklineValues: engine.scanHistory.recentValues(for: \.auditIssueCount),
                        sparklineColor:  .statusGreen,
                        action:          { selectedSection = .audit }
                    )
                    MonitorCard(
                        title:           "Persistence",
                        count:           engine.persistenceItems.count,
                        status:          statusLabel(issues: persistenceIssues),
                        statusColor:     statusColor(issues: persistenceIssues),
                        icon:            "arrow.triangle.2.circlepath",
                        sparklineValues: engine.scanHistory.recentValues(for: \.persistenceCount),
                        sparklineColor:  .statusGreen,
                        action:          { selectedSection = .persistence }
                    )
                    MonitorCard(
                        title:           "Processes",
                        count:           engine.processes.count,
                        status:          statusLabel(issues: processIssues),
                        statusColor:     statusColor(issues: processIssues),
                        icon:            "cpu",
                        sparklineValues: engine.scanHistory.recentValues(for: \.processCount),
                        sparklineColor:  .statusGreen,
                        action:          { selectedSection = .processes }
                    )
                    MonitorCard(
                        title:           "Network",
                        count:           engine.connections.count,
                        status:          statusLabel(issues: networkIssues),
                        statusColor:     statusColor(issues: networkIssues),
                        icon:            "network",
                        sparklineValues: engine.scanHistory.recentValues(for: \.networkCount),
                        sparklineColor:  .statusGreen,
                        action:          { selectedSection = .network }
                    )
                }
                .padding(.horizontal, NickSpacing.xl)

                // Protection Summary + Recent Activity side by side.
                HStack(alignment: .top, spacing: NickSpacing.lg) {
                    ProtectionSummaryView(
                        monitoringSince: engine.monitoringSince,
                        totalScans:      engine.totalScanCount,
                        threatsDetected: engine.totalThreatsDetected,
                        lastScanDate:    engine.lastScanDate,
                        nextScanIn:      nextScanIn,
                        focusModeActive: focusModeActive
                    )
                    .frame(maxWidth: .infinity)

                    RecentActivityView(
                        events:    engine.activityLog.events,
                        onViewAll: { selectedSection = .alerts }
                    )
                    .frame(maxWidth: .infinity)
                }
                .padding(.horizontal, NickSpacing.xl)
                .padding(.bottom, NickSpacing.xl)
            }
            .padding(.top, NickSpacing.xl)
        }
        .background(Color.backgroundPrimary)
        .navigationTitle("Overview")
        .task {
            // Tick every second so the "Next scan" countdown stays live.
            // Also recheck Focus/DND state each tick (cheap UserDefaults read).
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(1))
                now = .now
                focusModeActive = isFocusModeActive()
            }
        }
    }

    // MARK: - Status helpers

    private func statusLabel(issues: Int) -> String {
        if engine.isScanning { return "Scanning…" }
        if issues > 0 { return "\(issues) issue\(issues == 1 ? "" : "s")" }
        return "All clear"
    }

    private func statusColor(issues: Int) -> Color {
        if engine.isScanning { return .textTertiary }
        if issues > 0 { return .statusRed }
        return .statusGreen
    }
}

// MARK: - MonitorCard

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

                    Text(title)
                        .font(.nickBodyMedium)
                        .foregroundStyle(Color.textPrimary)

                    HStack(spacing: NickSpacing.sm) {
                        Text("\(count)")
                            .font(.nickMono)
                            .foregroundStyle(Color.textPrimary)
                        Text("items")
                            .font(.nickBodySmall)
                            .foregroundStyle(Color.textSecondary)
                    }

                    HStack(spacing: NickSpacing.xs) {
                        Circle()
                            .fill(statusColor)
                            .frame(width: 6, height: 6)
                        Text(status)
                            .font(.nickCaption)
                            .foregroundStyle(statusColor)
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

// MARK: - ProtectionSummaryView

private struct ProtectionSummaryView: View {

    let monitoringSince: Date
    let totalScans:      Int
    let threatsDetected: Int
    let lastScanDate:    Date?
    let nextScanIn:      Int
    let focusModeActive: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: NickSpacing.md) {
            HStack {
                Text("Protection Summary")
                    .font(.nickSubtitle)
                    .foregroundStyle(Color.textPrimary)
                Spacer()
                HStack(spacing: NickSpacing.xs) {
                    Circle()
                        .fill(Color.statusGreen)
                        .frame(width: 6, height: 6)
                    Text("LIVE")
                        .font(.system(size: 10, weight: .bold))
                        .foregroundStyle(Color.statusGreen)
                }
            }

            SummaryRow(icon: "clock",
                       label: "Monitoring since",
                       value: monitoringSince.formatted(date: .abbreviated, time: .omitted))
            SummaryRow(icon: "magnifyingglass",
                       label: "Total scans",
                       value: "\(totalScans)")
            SummaryRow(icon: "exclamationmark.triangle",
                       label: "Threats detected",
                       value: "\(threatsDetected)")
            if let lastScan = lastScanDate {
                SummaryRow(icon: "clock.arrow.circlepath",
                           label: "Last scan",
                           value: lastScan.formatted(date: .abbreviated, time: .shortened))
            }
            SummaryRow(icon: "timer",
                       label: "Next scan",
                       value: "\(nextScanIn) sec")

            if focusModeActive {
                HStack(spacing: NickSpacing.sm) {
                    Image(systemName: "moon.fill")
                        .frame(width: 16)
                        .foregroundStyle(Color.statusYellow)
                        .imageScale(.small)
                    Text("Focus Mode is on — notifications are silenced")
                        .font(.nickBodySmall)
                        .foregroundStyle(Color.statusYellow)
                }
            }
        }
        .padding(NickSpacing.lg)
        .background(Color.backgroundSecondary)
        .clipShape(RoundedRectangle(cornerRadius: NickLayout.cardCornerRadius))
    }
}

// MARK: - SummaryRow

private struct SummaryRow: View {
    let icon:  String
    let label: String
    let value: String
    var body: some View {
        HStack(spacing: NickSpacing.sm) {
            Image(systemName: icon)
                .frame(width: 16)
                .foregroundStyle(Color.textTertiary)
                .imageScale(.small)
            Text(label)
                .font(.nickBodySmall)
                .foregroundStyle(Color.textSecondary)
            Spacer()
            Text(value)
                .font(.nickMonoSmall)
                .foregroundStyle(Color.textTertiary)
        }
    }
}

// MARK: - RecentActivityView

private struct RecentActivityView: View {

    let events:    [ActivityEvent]
    let onViewAll: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: NickSpacing.md) {
            HStack {
                Text("Recent Activity")
                    .font(.nickSubtitle)
                    .foregroundStyle(Color.textPrimary)
                Spacer()
                Button("View all ›") { onViewAll() }
                    .font(.nickCaption)
                    .foregroundStyle(Color.textTertiary)
                    .buttonStyle(.plain)
            }

            if events.isEmpty {
                Text("No activity yet")
                    .font(.nickBodySmall)
                    .foregroundStyle(Color.textTertiary)
                    .frame(maxWidth: .infinity, alignment: .center)
                    .padding(.vertical, NickSpacing.lg)
            } else {
                ForEach(events.prefix(5)) { event in
                    HStack(spacing: NickSpacing.md) {
                        Image(systemName: event.icon)
                            .font(.system(size: 12))
                            .foregroundStyle(colorFor(event.iconColor))
                            .frame(width: 20)

                        VStack(alignment: .leading, spacing: 2) {
                            Text(event.title)
                                .font(.nickBodySmall)
                                .foregroundStyle(Color.textPrimary)
                            Text(event.subtitle)
                                .font(.nickMonoSmall)
                                .foregroundStyle(Color.textTertiary)
                        }

                        Spacer()

                        Text(event.timestamp, format: .dateTime.hour().minute().second())
                            .font(.nickMonoSmall)
                            .foregroundStyle(Color.textTertiary)
                    }
                }
            }
        }
        .padding(NickSpacing.lg)
        .background(Color.backgroundSecondary)
        .clipShape(RoundedRectangle(cornerRadius: NickLayout.cardCornerRadius))
    }

    private func colorFor(_ string: String) -> Color {
        switch string {
        case "green":  return .statusGreen
        case "blue":   return .statusBlue
        case "yellow": return .statusYellow
        case "red":    return .statusRed
        default:       return .textTertiary
        }
    }
}

// MARK: - ProcessListView

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

    var body: some View {
        VStack(spacing: 0) {
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

                // Change 5: color-coded dot + display name; pending→Unknown after 10 s.
                TableColumn("Signing") { p in
                    HStack(spacing: NickSpacing.sm) {
                        if p.signingStatus == .pending {
                            Circle()
                                .strokeBorder(Color.textTertiary, lineWidth: 1)
                                .frame(width: 6, height: 6)
                        } else {
                            Circle()
                                .fill(ProcessListView.signingColor(p.signingStatus))
                                .frame(width: 6, height: 6)
                        }
                        Text(ProcessListView.signingText(p))
                            .foregroundStyle(ProcessListView.signingColor(p.signingStatus))
                    }
                }
                .width(min: 120, ideal: 150)

                // Change 5: Threat badge — only shown for flagged processes.
                TableColumn("Threat") { p in
                    if let label = ProcessListView.threatLabel(p) {
                        Text(label)
                            .font(.nickCaption)
                            .foregroundStyle(Color.statusRed)
                            .padding(.horizontal, NickSpacing.sm)
                            .padding(.vertical, NickSpacing.xs)
                            .background(Color.statusRed.opacity(0.12))
                            .clipShape(Capsule())
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
        .navigationTitle("Processes (\(engine.processes.count))")
    }

    // MARK: - Process Helpers (static so Table closures can access them)

    static func signingColor(_ status: SigningStatus) -> Color {
        switch status {
        case .signed:           return .statusGreen
        case .adHoc:            return .statusYellow
        case .unsigned, .invalid: return .statusRed
        case .unknown, .pending:  return .textTertiary
        }
    }

    static func signingText(_ p: NickProcessInfo) -> String {
        guard p.signingStatus == .pending else { return p.signingStatus.displayName }
        // Fix stuck "Checking…": fall back to Unknown after 10 s.
        if let start = p.startTime, Date().timeIntervalSince(start) > 10 {
            return "Unknown"
        }
        return "Checking…"
    }

    static func threatLabel(_ p: NickProcessInfo) -> String? {
        let path = p.path.lowercased()
        // Unsigned binary in a temp directory
        if p.signingStatus == .unsigned {
            if path.hasPrefix("/tmp") || path.hasPrefix("/var/tmp") || path.hasPrefix("/private/tmp") {
                return "Temp Path"
            }
        }
        // Common LOLBin names running without a valid signature
        let lolBins: Set<String> = ["bash", "sh", "zsh", "python", "python3", "perl",
                                    "ruby", "curl", "wget", "nc", "ncat", "osascript"]
        if lolBins.contains(p.name.lowercased()) && p.signingStatus == .unsigned {
            return "LOLBin"
        }
        return nil
    }
}

// MARK: - PersistenceDetailView

/// Table of all detected persistence mechanisms.
struct PersistenceDetailView: View {

    @Environment(SecurityEngine.self) private var engine
    @State private var sortOrder = [KeyPathComparator<PersistenceItem>(\PersistenceItem.name)]

    private var sorted: [PersistenceItem] {
        engine.persistenceItems.sorted(using: sortOrder)
    }

    var body: some View {
        Group {
            if engine.persistenceItems.isEmpty {
                emptyState
            } else {
                Table(sorted, sortOrder: $sortOrder) {
                    TableColumn("Type") { item in
                        Text(item.type.displayName)
                            .foregroundStyle(Color.textSecondary)
                    }
                    .width(min: 110, ideal: 130)

                    TableColumn("Name", value: \.name) { item in
                        Text(item.name)
                            .foregroundStyle(Color.textPrimary)
                            .lineLimit(1)
                    }

                    TableColumn("Executable") { item in
                        Text(item.executablePath.map { URL(fileURLWithPath: $0).lastPathComponent } ?? "—")
                            .font(.system(.body, design: .monospaced))
                            .foregroundStyle(Color.textTertiary)
                            .lineLimit(1)
                    }

                    TableColumn("Signing") { item in
                        Text(item.signingStatus?.displayName ?? "—")
                            .foregroundStyle(
                                item.signingStatus?.isSuspicious == true
                                    ? Color.statusRed
                                    : Color.textSecondary
                            )
                    }
                    .width(min: 100, ideal: 130)

                    // Change 6: Status column.
                    TableColumn("Status") { item in
                        let s = PersistenceDetailView.status(for: item)
                        Text(s.label)
                            .font(.nickCaption)
                            .foregroundStyle(s.color)
                    }
                    .width(min: 90, ideal: 110)

                    TableColumn("Scope") { item in
                        Text(item.scope == .system ? "System" : "User")
                            .foregroundStyle(Color.textSecondary)
                    }
                    .width(60)
                }
            }
        }
        .navigationTitle("Persistence (\(engine.persistenceItems.count))")
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
        VStack(spacing: NickSpacing.lg) {
            Image(systemName: "arrow.triangle.2.circlepath")
                .font(.system(size: 32))
                .foregroundStyle(Color.textTertiary)
            Text("No persistence items found")
                .font(.nickSubtitle)
                .foregroundStyle(Color.textPrimary)
            Text("Run a scan to check for persistent startup items.")
                .font(.nickBodySmall)
                .foregroundStyle(Color.textSecondary)
                .multilineTextAlignment(.center)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Color.backgroundPrimary)
    }
}

// MARK: - ThreatVerdict

/// Verdict assigned to each deep-scan YARA match after path + signature analysis.
enum ThreatVerdict: String {
    case threat              = "Threat"
    case suspicious          = "Suspicious"
    case developmentArtifact = "Development Artifact"
    case likelySafe          = "Likely Safe"
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

    // MARK: - File scan state
    @State private var fileScanURL:      URL?
    @State private var fileScanResults:  [YARAMatch] = []
    @State private var fileScanError:    String?
    @State private var showFileScanSheet = false
    @State private var isFileScanRunning = false
    @State private var fileScanSummary:  FileScanSummary?
    @State private var fileScanDuration: TimeInterval = 0

    // MARK: - Drop zone
    @State private var isDragTargeted = false

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
        // GeometryReader captures the finite bounds offered by NavigationSplitView's
        // detail column, giving the inner VStack a concrete height to work with.
        // Without this, the detail column's implicit NSScrollView host offers
        // infinite height, causing .frame(maxHeight: .infinity) on the drop zone
        // to expand without bound.
        GeometryReader { _ in
            VStack(alignment: .leading, spacing: 0) {
                // Title + YARA explanation
                VStack(alignment: .leading, spacing: NickSpacing.sm) {
                    Text("Nick Scan")
                        .font(.nickBodyMedium)
                        .foregroundStyle(Color.textPrimary)
                    Text("Powered by YARA")
                        .font(.nickCaption)
                        .foregroundStyle(Color.textTertiary)
                    Text("YARA is an open-source pattern matching engine used by security researchers worldwide to identify and classify malware. Nick uses curated macOS-specific rules to detect threats on your system.")
                        .font(.nickBodySmall)
                        .foregroundStyle(Color.textTertiary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                .padding(NickSpacing.xl)

                // Drop zone fills all remaining vertical space.
                dropZone
                    .padding(.horizontal, NickSpacing.xl)
                    .padding(.bottom, NickSpacing.sm)

                Rectangle()
                    .fill(Color.borderSubtle)
                    .frame(height: 0.5)
                    .padding(.horizontal, NickSpacing.xl)

                deepScanSection
                    .padding(NickSpacing.xl)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .background(Color.backgroundPrimary)
        }
        .navigationTitle("Nick Scan")
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
                .frame(minWidth: 480, minHeight: 400)
            }
        }
        .onChange(of: scanner.isScanning) { _, isScanning in
            if !isScanning && hasStarted && scanner.totalFiles > 0 {
                engine.recordDeepScan(fileCount: scanner.totalFiles)
                showResults = true
            }
        }
        .onAppear { scanner.engine = engine }
    }

    // MARK: - Drop zone (fills all available vertical space)

    private var dropZone: some View {
        RoundedRectangle(cornerRadius: NickLayout.cardCornerRadius)
            .strokeBorder(
                isDragTargeted ? Color.statusBlue : Color.borderMedium,
                style: StrokeStyle(lineWidth: 2, dash: [8])
            )
            .background(
                RoundedRectangle(cornerRadius: NickLayout.cardCornerRadius)
                    .fill(isDragTargeted ? Color.statusBlue.opacity(0.07) : Color.backgroundSecondary)
            )
            .overlay {
                VStack(spacing: NickSpacing.lg) {
                    Image(systemName: "doc.text.magnifyingglass")
                        .font(.system(size: 48))
                        .foregroundStyle(isDragTargeted ? Color.statusBlue : Color.textTertiary)
                    Text("Drop files here to scan")
                        .font(.nickBody)
                        .foregroundStyle(isDragTargeted ? Color.statusBlue : Color.textSecondary)
                    Button("Browse Files...") { openFileScanPanel() }
                        .buttonStyle(.borderedProminent)
                        .disabled(isFileScanRunning)
                }
            }
            .frame(maxHeight: .infinity)
            .onDrop(of: [.fileURL], isTargeted: $isDragTargeted) { providers in
                guard let provider = providers.first else { return false }
                _ = provider.loadObject(ofClass: URL.self) { url, _ in
                    guard let url else { return }
                    DispatchQueue.main.async { startFileScan(url: url) }
                }
                return true
            }
    }

    // MARK: - Deep Scan section

    private var deepScanSection: some View {
        VStack(alignment: .leading, spacing: NickSpacing.lg) {
            Text("Deep Scan")
                .font(.nickBodyMedium)
                .foregroundStyle(Color.textPrimary)
            Text("Scan all executables and scripts across Applications, Launch Agents, Downloads, and more.")
                .font(.nickBodySmall)
                .foregroundStyle(Color.textSecondary)
                .fixedSize(horizontal: false, vertical: true)

            if scanner.isScanning {
                deepScanProgress
            } else if scanner.isPaused {
                deepScanPaused
            } else {
                VStack(alignment: .leading, spacing: NickSpacing.sm) {
                    Toggle("Only scan while on AC power", isOn: $onlyOnPower)
                        .toggleStyle(.checkbox)
                        .font(.nickBodySmall)
                        .foregroundStyle(Color.textSecondary)

                    Button("Start Deep Scan") {
                        hasStarted = true
                        Task { @MainActor in
                            scanner.start(onlyOnPower: onlyOnPower) { [engine] path in
                                try await engine.scanFile(at: URL(fileURLWithPath: path))
                            }
                        }
                    }
                    .buttonStyle(.borderedProminent)
                }
            }
        }
    }

    private var deepScanProgress: some View {
        VStack(alignment: .leading, spacing: NickSpacing.sm) {
            GeometryReader { proxy in
                ZStack(alignment: .leading) {
                    Capsule().fill(Color.backgroundTertiary).frame(height: 4)
                    Capsule()
                        .fill(Color.statusBlue)
                        .frame(width: max(4, proxy.size.width * scanner.progress), height: 4)
                        .animation(.linear(duration: 0.3), value: scanner.progress)
                }
            }
            .frame(height: 4)

            HStack {
                Text("\(Int(scanner.progress * 100))% · \(scanner.scannedFiles.formatted()) / \(scanner.totalFiles.formatted()) files")
                    .font(.nickMono)
                    .foregroundStyle(Color.textSecondary)
                Spacer()
                if scanner.estimatedRemaining > 0 {
                    Text("~\(formatTime(scanner.estimatedRemaining)) remaining")
                        .font(.nickMonoSmall)
                        .foregroundStyle(Color.textTertiary)
                }
            }
            Text(scanner.currentFile)
                .font(.nickMonoSmall)
                .foregroundStyle(Color.textTertiary)
                .lineLimit(1)
                .truncationMode(.middle)
            if scanner.threatsFound > 0 {
                Label("\(scanner.threatsFound) threats found", systemImage: "exclamationmark.triangle.fill")
                    .font(.nickBodySmall)
                    .foregroundStyle(Color.statusRed)
            }
            Button("Cancel") { scanner.cancel(); hasStarted = false }
                .buttonStyle(.bordered)
        }
    }

    private var deepScanPaused: some View {
        HStack(spacing: NickSpacing.sm) {
            Image(systemName: "pause.circle.fill").foregroundStyle(Color.statusYellow)
            Text("Paused — connect to AC power to continue")
                .font(.nickBodySmall).foregroundStyle(Color.textSecondary)
            Spacer()
            Button("Cancel") { scanner.cancel(); hasStarted = false }
                .buttonStyle(.bordered)
        }
    }

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

    private func openFileScanPanel() {
        let panel = NSOpenPanel()
        panel.title = "Select a File or Folder to Scan"
        panel.canChooseFiles = true
        panel.canChooseDirectories = true
        panel.allowsMultipleSelection = false
        panel.begin { response in
            guard response == .OK, let url = panel.url else { return }
            startFileScan(url: url)
        }
    }

    private func startFileScan(url: URL) {
        fileScanURL      = url
        fileScanResults  = []
        fileScanError    = nil
        fileScanSummary  = nil
        fileScanDuration = 0
        isFileScanRunning = true
        showFileScanSheet = true
        Task { @MainActor in
            let start = Date()
            async let yaraTask: [YARAMatch]        = engine.scanFile(at: url)
            async let summaryTask: FileScanSummary = FileScanSummary.analyze(url: url)
            do { fileScanResults = try await yaraTask } catch { fileScanError = error.localizedDescription }
            fileScanSummary  = await summaryTask
            fileScanDuration = Date().timeIntervalSince(start)
            isFileScanRunning = false
        }
    }

    private func formatTime(_ t: TimeInterval) -> String {
        let total = Int(t)
        return String(format: "%d:%02d", total / 60, total % 60)
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

        // Development artifacts by directory patterns.
        let devPatterns = ["deriveddata", "workspacestorage", ".git/", "node_modules",
                           "__pycache__", ".build/", "editingsessions", "/history/",
                           "editorsessions", "xcodesupport"]
        if devPatterns.contains(where: { path.contains($0) }) { return .developmentArtifact }

        // Application caches — expected to contain binary data that triggers rules.
        let cachePaths = ["cache/cache_data", "cache_data/", "component_crx_cache",
                          "gpucache", "code cache", "shader cache", "/caches/", "webcache"]
        if cachePaths.contains(where: { path.contains($0) }) { return .likelySafe }

        // Known legitimate binaries that may appear unsigned to static analysis.
        let filename = URL(fileURLWithPath: match.filePath).lastPathComponent.lowercased()
        let knownLegitimate = ["claude", "claude-code-vm"]
        if knownLegitimate.contains(where: { filename.contains($0) }) { return .likelySafe }

        let signing = SignatureValidator.shared.evaluate(binaryPath: match.filePath)
        if case .signed = signing { return .likelySafe }

        let suspiciousPrefixes = ["/tmp", "/var/tmp", "/private/tmp"]
        if suspiciousPrefixes.contains(where: { match.filePath.hasPrefix($0) }) { return .suspicious }

        return .suspicious
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
                    if let sev = match.metadata["severity"] {
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
        case .developmentArtifact, .likelySafe: return .textTertiary
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

