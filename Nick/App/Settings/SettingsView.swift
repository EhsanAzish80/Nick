// SettingsView.swift — redesigned in the Apple System-Settings vocabulary
// used across the rest of the Nick app. Drop this file in place of the
// existing SettingsView.swift.
//
// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import AppKit
import SwiftUI
import ServiceManagement

// ════════════════════════════════════════════════════════════════
// MARK: - SettingsView
// ════════════════════════════════════════════════════════════════

struct SettingsView: View {

    // MARK: Dependencies

    @Environment(SecurityEngine.self) private var engine

    // MARK: App Storage

    @AppStorage("notificationThresholdRaw") private var notificationThresholdRaw: Int = SignalSeverity.high.rawValue
    @AppStorage("deepScanIntervalSeconds") private var deepScanIntervalSeconds: Int = 60

    // MARK: Private State

    @State private var launchAtLogin: Bool = (SMAppService.mainApp.status == .enabled)
    @State private var monitoredDirectories: [String] = {
        (UserDefaults.standard.array(forKey: "monitoredDirectories") as? [String])
            ?? ["/Users", "/Applications", "/Library", "/private/tmp"]
    }()
    @State private var newProcessName: String = ""
    @State private var showRemoveProcessConfirmation = false
    @State private var nameToRemove: String?
    @State private var showClearAlertsConfirmation = false
    @State private var showResetHistoryConfirmation = false
    @State private var showRemoveHelperConfirmation = false

    // MARK: Body

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 0) {
                header

                Form {
                    generalSection
                    notificationsSection
                    scanningSection
                    monitoredDirectoriesSection
                    trustedProcessesSection
                    finderIntegrationSection
                    dataSection
                    maintenanceSection
                }
                .formStyle(.grouped)
                .scrollDisabled(true)

                footer
            }
            .frame(maxWidth: 720)
            .frame(maxWidth: .infinity)
        }
    }

    // MARK: Header

    private var header: some View {
        HStack(spacing: 14) {
            iconTile(color: .gray, size: 48, radius: 11) {
                Image(systemName: "gearshape.fill")
                    .font(.system(size: 26, weight: .regular))
                    .foregroundStyle(.white)
            }
            VStack(alignment: .leading, spacing: 2) {
                Text("Settings")
                    .font(.system(size: 18, weight: .semibold))
                    .tracking(-0.005 * 18)
                Text("Notifications, scanning, monitored locations, and trusted processes.")
                    .font(.system(size: 12.5))
                    .foregroundStyle(.secondary)
            }
            Spacer()
        }
        .padding(.horizontal, 4)
        .padding(.top, 22)
        .padding(.bottom, 18)
    }

    // MARK: Sections

    private var generalSection: some View {
        Section("General") {
            LabeledTile(
                icon: "power", tint: .green,
                title: "Launch at login",
                subtitle: "Start Nick automatically when you log in."
            ) {
                Toggle("", isOn: $launchAtLogin)
                    .labelsHidden()
                    .toggleStyle(.switch)
                    .onChange(of: launchAtLogin) { _, newValue in toggleLaunchAtLogin(newValue) }
            }
        }
    }

    private var notificationsSection: some View {
        Section {
            LabeledTile(
                icon: "bell.fill", tint: .red,
                title: "Minimum severity"
            ) {
                Picker("", selection: $notificationThresholdRaw) {
                    ForEach(SignalSeverity.allCases.filter { $0 != .info }, id: \.rawValue) { sev in
                        Text(sev.displayName).tag(sev.rawValue)
                    }
                }
                .labelsHidden()
                .frame(width: 130)
            }
        } header: {
            Text("Notifications")
        } footer: {
            Text("Alerts below this severity are logged but won't trigger a notification.")
                .font(.system(size: 11.5))
                .foregroundStyle(.secondary)
        }
    }

    private var scanningSection: some View {
        Section {
            LabeledTile(
                icon: "arrow.triangle.2.circlepath", tint: .blue,
                title: "Background sweep interval"
            ) {
                Picker("", selection: $deepScanIntervalSeconds) {
                    Text("30 seconds").tag(30)
                    Text("1 minute").tag(60)
                    Text("5 minutes").tag(300)
                    Text("15 minutes").tag(900)
                    Text("30 minutes").tag(1800)
                }
                .labelsHidden()
                .frame(width: 150)
            }
        } header: {
            Text("Scanning")
        } footer: {
            Text("How often Nick performs a background sweep. Shorter intervals increase detection sensitivity but consume more CPU.")
                .font(.system(size: 11.5))
                .foregroundStyle(.secondary)
        }
    }

    private var monitoredDirectoriesSection: some View {
        Section {
            ForEach(monitoredDirectories, id: \.self) { path in
                HStack(spacing: 10) {
                    Image(systemName: "folder.fill")
                        .foregroundStyle(Color.blue)
                        .imageScale(.small)
                    Text(path)
                        .font(.system(size: 12.5, design: .monospaced))
                        .foregroundStyle(.primary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                    Spacer()
                    Button {
                        monitoredDirectories.removeAll { $0 == path }
                        saveDirectories()
                    } label: {
                        Image(systemName: "minus.circle.fill")
                            .foregroundStyle(.red)
                    }
                    .buttonStyle(.plain)
                }
            }

            Button {
                selectDirectory()
            } label: {
                HStack(spacing: 8) {
                    Image(systemName: "plus.circle.fill")
                        .foregroundStyle(.blue)
                    Text("Add Folder…")
                        .foregroundStyle(.blue)
                        .fontWeight(.medium)
                }
            }
            .buttonStyle(.plain)
        } header: {
            Text("Monitored Directories")
        } footer: {
            Text("Persistence and filesystem watchers scan these directories for suspicious changes.")
                .font(.system(size: 11.5))
                .foregroundStyle(.secondary)
        }
    }

    private var trustedProcessesSection: some View {
        Section {
            HStack(spacing: 8) {
                Image(systemName: "person.crop.circle.badge.checkmark")
                    .foregroundStyle(.white)
                    .padding(5)
                    .background(Color.green, in: RoundedRectangle(cornerRadius: 6))
                TextField("Process name (e.g. MyApp)", text: $newProcessName)
                    .textFieldStyle(.roundedBorder)
                    .onSubmit { addProcess() }
                Button("Add", action: addProcess)
                    .disabled(newProcessName.trimmingCharacters(in: .whitespaces).isEmpty)
                    .buttonStyle(.borderedProminent)
                    .controlSize(.small)
            }

            userListContent

            DisclosureGroup {
                LazyVGrid(
                    columns: [GridItem(.flexible()), GridItem(.flexible())],
                    alignment: .leading, spacing: 4
                ) {
                    ForEach(TrustedProcessList.builtIn.sorted(), id: \.self) { name in
                        HStack(spacing: 6) {
                            Image(systemName: "lock.fill")
                                .foregroundStyle(.tertiary)
                                .imageScale(.small)
                            Text(name)
                                .font(.system(size: 12, design: .monospaced))
                                .foregroundStyle(.secondary)
                        }
                    }
                }
                .padding(.top, 6)
            } label: {
                HStack(spacing: 4) {
                    Text("Built-in Trusted Processes")
                        .font(.system(size: 12.5))
                    Text("(\(TrustedProcessList.builtIn.count))")
                        .font(.system(size: 12))
                        .foregroundStyle(.secondary)
                }
            }
            .confirmationDialog(
                "Remove \"\(nameToRemove ?? "")\" from trusted processes?",
                isPresented: $showRemoveProcessConfirmation,
                titleVisibility: .visible
            ) {
                Button("Remove", role: .destructive) {
                    if let n = nameToRemove { removeProcess(n) }
                }
                Button("Cancel", role: .cancel) {}
            }
        } header: {
            Text("Trusted Processes")
        } footer: {
            Text("Alerts where all contributing processes are trusted are downgraded to Info severity and suppressed from notifications.")
                .font(.system(size: 11.5))
                .foregroundStyle(.secondary)
        }
    }

    @ViewBuilder
    private var userListContent: some View {
        let userNames = engine.trustedProcessList.userTrustedNames()
        if userNames.isEmpty {
            Text("No user-added entries yet.")
                .font(.system(size: 12))
                .italic()
                .foregroundStyle(.secondary)
        } else {
            ForEach(userNames, id: \.self) { name in
                HStack(spacing: 10) {
                    Image(systemName: "checkmark.circle.fill")
                        .foregroundStyle(.green)
                        .imageScale(.small)
                    Text(name)
                        .font(.system(size: 12.5))
                    Spacer()
                    Button {
                        nameToRemove = name
                        showRemoveProcessConfirmation = true
                    } label: {
                        Image(systemName: "trash")
                            .foregroundStyle(.red)
                    }
                    .buttonStyle(.plain)
                }
            }
        }
    }

    private var finderIntegrationSection: some View {
        Section {
            LabeledTile(
                icon: "filemenu.and.cursorarrow", tint: .indigo,
                title: "Scan with Nick",
                subtitle: "Adds \"Scan with Nick\" to Finder's right-click Services menu."
            ) {
                HStack(spacing: 6) {
                    Image(systemName: "exclamationmark.triangle.fill")
                        .foregroundStyle(.orange)
                        .font(.system(size: 13))
                    Text("Not enabled")
                        .font(.system(size: 12, weight: .medium))
                        .foregroundStyle(.orange)
                }
            }

            LabeledTile(
                icon: "keyboard", tint: .gray,
                title: "Enable in Keyboard Settings",
                subtitle: "Go to System Settings → Keyboard → Keyboard Shortcuts → Services → Files and Folders, then tick \"Scan with Nick\"."
            ) {
                Button("Open Keyboard Settings") {
                    if let url = URL(string: "x-apple.systempreferences:com.apple.preference.keyboard?Shortcuts") {
                        NSWorkspace.shared.open(url)
                    }
                }
                .controlSize(.small)
            }
        } header: {
            Text("Finder Integration")
        } footer: {
            Text("macOS does not allow apps to enable Services entries automatically. You must enable it once in System Settings.")
                .font(.system(size: 11.5))
                .foregroundStyle(.secondary)
        }
    }

    private var dataSection: some View {
        Section("Data") {
            LabeledTile(
                icon: "exclamationmark.triangle.fill", tint: .red,
                title: "Clear alert history",
                subtitle: "Remove all stored threat alerts and reset the threats-detected counter. Monitoring continues uninterrupted."
            ) {
                Button("Clear…", role: .destructive) {
                    showClearAlertsConfirmation = true
                }
                .controlSize(.small)
            }
            .confirmationDialog(
                "Clear all alert history?",
                isPresented: $showClearAlertsConfirmation,
                titleVisibility: .visible
            ) {
                Button("Clear", role: .destructive) { engine.clearAlertHistory() }
                Button("Cancel", role: .cancel) {}
            }

            LabeledTile(
                icon: "chart.bar.fill", tint: .orange,
                title: "Reset scan history",
                subtitle: "Clear the sparkline chart data in Overview. Does not affect threat alerts."
            ) {
                Button("Reset…", role: .destructive) {
                    showResetHistoryConfirmation = true
                }
                .controlSize(.small)
            }
            .confirmationDialog(
                "Reset scan history?",
                isPresented: $showResetHistoryConfirmation,
                titleVisibility: .visible
            ) {
                Button("Reset", role: .destructive) { engine.scanHistory.clear() }
                Button("Cancel", role: .cancel) {}
            }
        }
    }

    private var maintenanceSection: some View {
        Section {
            LabeledTile(
                icon: "gearshape.2.fill", tint: .gray,
                title: "Remove privileged helper",
                subtitle: "Unregisters and removes the Nick privileged helper from the system."
            ) {
                Button("Remove…", role: .destructive) {
                    showRemoveHelperConfirmation = true
                }
                .controlSize(.small)
            }
            .confirmationDialog(
                "Remove privileged helper?",
                isPresented: $showRemoveHelperConfirmation,
                titleVisibility: .visible
            ) {
                Button("Remove", role: .destructive) { removeHelper() }
                Button("Cancel", role: .cancel) {}
            }
        } header: {
            Text("Maintenance")
        } footer: {
            Text("Nick's monitoring capabilities will be reduced until the helper is reinstalled at next launch.")
                .font(.system(size: 11.5))
                .foregroundStyle(.secondary)
        }
    }

    // MARK: Footer

    private var footer: some View {
        HStack(spacing: 4) {
            Text("Nick · Version 2026.05 · ")
            Link("Open Source on GitHub",
                 destination: URL(string: "https://github.com/EhsanAzish80/Nick")!)
        }
        .font(.system(size: 11.5))
        .foregroundStyle(.secondary)
        .frame(maxWidth: .infinity)
        .padding(.top, 8)
        .padding(.bottom, 20)
    }

    // MARK: Actions

    private func removeHelper() {
        Task {
            try? await SMAppService.daemon(plistName: "com.ehsanazish.nick.helper.plist").unregister()
        }
    }

    private func addProcess() {
        let trimmed = newProcessName.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty else { return }
        @Bindable var bindableEngine = engine
        bindableEngine.trustedProcessList.addUserTrusted(trimmed)
        newProcessName = ""
    }

    private func removeProcess(_ name: String) {
        @Bindable var bindableEngine = engine
        bindableEngine.trustedProcessList.removeUserTrusted(name)
        nameToRemove = nil
    }

    private func selectDirectory() {
        let panel = NSOpenPanel()
        panel.canChooseFiles = false
        panel.canChooseDirectories = true
        panel.canCreateDirectories = false
        panel.allowsMultipleSelection = false
        panel.title = "Select Directory to Monitor"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        let path = url.path
        guard !monitoredDirectories.contains(path) else { return }
        monitoredDirectories.append(path)
        saveDirectories()
    }

    private func saveDirectories() {
        UserDefaults.standard.set(monitoredDirectories, forKey: "monitoredDirectories")
    }

    private func toggleLaunchAtLogin(_ enable: Bool) {
        do {
            if enable {
                try SMAppService.mainApp.register()
            } else {
                try SMAppService.mainApp.unregister()
            }
        } catch {
            launchAtLogin = !enable
        }
    }

    // MARK: Icon-tile helper (gradient app-icon style square)

    @ViewBuilder
    private func iconTile<Content: View>(color: Color, size: CGFloat, radius: CGFloat, @ViewBuilder content: () -> Content) -> some View {
        RoundedRectangle(cornerRadius: radius, style: .continuous)
            .fill(LinearGradient(
                colors: [color.opacity(0.85).mix(with: .white, by: 0.18), color],
                startPoint: .top, endPoint: .bottom))
            .frame(width: size, height: size)
            .overlay(content())
            .shadow(color: color.opacity(0.27), radius: 7, x: 0, y: 6)
            .overlay(
                RoundedRectangle(cornerRadius: radius, style: .continuous)
                    .stroke(Color.white.opacity(0.35), lineWidth: 0.5)
                    .blendMode(.plusLighter)
            )
    }
}

// ════════════════════════════════════════════════════════════════
// MARK: - LabeledTile
//
// A standard row: 26×26 colored glyph tile · two-line label/subtitle ·
// right-side control. Mirrors the prototype's ControlRow / ActionRow.
// ════════════════════════════════════════════════════════════════

struct LabeledTile<Trailing: View>: View {

    let icon: String
    let tint: Color
    let title: String
    let subtitle: String?
    @ViewBuilder let trailing: () -> Trailing

    init(icon: String, tint: Color, title: String, subtitle: String? = nil,
         @ViewBuilder trailing: @escaping () -> Trailing) {
        self.icon = icon
        self.tint = tint
        self.title = title
        self.subtitle = subtitle
        self.trailing = trailing
    }

    var body: some View {
        HStack(spacing: 12) {
            RoundedRectangle(cornerRadius: 6, style: .continuous)
                .fill(tint)
                .frame(width: 26, height: 26)
                .overlay(
                    Image(systemName: icon)
                        .font(.system(size: 14, weight: .regular))
                        .foregroundStyle(.white)
                )
            VStack(alignment: .leading, spacing: 1) {
                Text(title)
                    .font(.system(size: 13))
                if let subtitle {
                    Text(subtitle)
                        .font(.system(size: 11.5))
                        .foregroundStyle(.secondary)
                }
            }
            Spacer()
            trailing()
        }
        .padding(.vertical, 2)
    }
}

// ════════════════════════════════════════════════════════════════
// MARK: - Preview
// ════════════════════════════════════════════════════════════════

#if DEBUG
#Preview {
    SettingsView()
        .environment(SecurityEngine())
        .frame(width: 760, height: 900)
}
#endif
