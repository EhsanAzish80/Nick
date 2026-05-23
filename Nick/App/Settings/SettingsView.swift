// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import AppKit
import SwiftUI
import ServiceManagement

// MARK: - SettingsView

/// Application-level settings panel presented as a single scrollable pane.
///
/// Sections: Notifications, Scanning, System, Monitored Directories, Trusted Processes.
/// Access via the gear icon in the dashboard bottom bar or the Settings scene.
struct SettingsView: View {

    // MARK: - Dependencies

    @Environment(SecurityEngine.self) private var engine

    // MARK: - App Storage

    @AppStorage("notificationThresholdRaw") private var notificationThresholdRaw: Int = SignalSeverity.high.rawValue
    @AppStorage("deepScanIntervalSeconds") private var deepScanIntervalSeconds: Int = 60

    // MARK: - Private State

    @State private var launchAtLogin: Bool = (SMAppService.mainApp.status == .enabled)
    @State private var monitoredDirectories: [String] = {
        (UserDefaults.standard.array(forKey: "monitoredDirectories") as? [String])
            ?? ["/Users", "/Applications", "/Library", "/private/tmp"]
    }()
    @State private var newProcessName: String = ""
    @State private var showRemoveProcessConfirmation = false
    @State private var nameToRemove: String?

    // MARK: - Body

    var body: some View {
        Form {
            Section("Notifications") {
                LabeledContent("Minimum severity") {
                    Picker("", selection: $notificationThresholdRaw) {
                        ForEach(SignalSeverity.allCases.filter { $0 != .info }, id: \.rawValue) { sev in
                            Text(sev.displayName).tag(sev.rawValue)
                        }
                    }
                    .labelsHidden()
                    .frame(width: 150)
                }
                Text("Alerts below this severity are logged but won't trigger a notification.")
                    .font(.nickBodySmall)
                    .foregroundStyle(.secondary)
            }

            Section("Scanning") {
                LabeledContent("Background sweep interval") {
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
                Text("How often Nick performs a background sweep. Shorter intervals increase detection sensitivity but consume more CPU.")
                    .font(.nickBodySmall)
                    .foregroundStyle(.secondary)
            }

            Section("System") {
                Toggle("Launch at login", isOn: $launchAtLogin)
                    .onChange(of: launchAtLogin) { _, newValue in toggleLaunchAtLogin(newValue) }
                Text("Start Nick automatically when you log in.")
                    .font(.nickBodySmall)
                    .foregroundStyle(.secondary)
            }

            Section("Maintenance") {
                GroupBox {
                    VStack(alignment: .leading, spacing: NickSpacing.sm) {
                        Text("Remove Privileged Helper")
                            .font(.nickBodyMedium)
                            .foregroundStyle(Color.textPrimary)
                        Text("Unregisters and removes the Nick privileged helper. Nick's monitoring capabilities will be reduced until the helper is reinstalled at next launch.")
                            .font(.nickBodySmall)
                            .foregroundStyle(.secondary)
                        Button("Remove Helper…") { removeHelper() }
                            .buttonStyle(NickDestructiveButtonStyle())
                    }
                    .padding(NickSpacing.sm)
                }
            }

            Section("Data") {
                GroupBox {
                    VStack(alignment: .leading, spacing: NickSpacing.sm) {
                        Button("Clear Alert History") {
                            engine.clearAlertHistory()
                        }
                        .buttonStyle(NickDestructiveButtonStyle())
                        Text("Removes all stored threat alerts and resets the threats-detected counter. Monitoring continues uninterrupted.")
                            .font(.nickBodySmall)
                            .foregroundStyle(.secondary)
                    }
                    .padding(NickSpacing.sm)
                }

                GroupBox {
                    VStack(alignment: .leading, spacing: NickSpacing.sm) {
                        Button("Reset Scan History") {
                            engine.scanHistory.clear()
                        }
                        .buttonStyle(NickDestructiveButtonStyle())
                        Text("Clears the sparkline chart data in the Overview. Does not affect threat alerts.")
                            .font(.nickBodySmall)
                            .foregroundStyle(.secondary)
                    }
                    .padding(NickSpacing.sm)
                }
            }

            Section("Monitored Directories") {
                Text("Persistence and filesystem watchers scan these directories for suspicious changes.")
                    .font(.nickBodySmall)
                    .foregroundStyle(.secondary)
                ForEach(monitoredDirectories, id: \.self) { path in
                    HStack {
                        Image(systemName: "folder")
                            .foregroundStyle(Color.textTertiary)
                            .imageScale(.small)
                        Text(path)
                            .font(.nickBodySmall)
                            .foregroundStyle(Color.textSecondary)
                        Spacer()
                        Button {
                            monitoredDirectories.removeAll { $0 == path }
                            saveDirectories()
                        } label: {
                            Image(systemName: "minus.circle")
                                .foregroundStyle(Color.statusRed)
                        }
                        .buttonStyle(.plain)
                    }
                }
                Button("Add Folder...") { selectDirectory() }
            }

            Section("Trusted Processes") {
                Text("Alerts where all contributing processes are trusted are downgraded to Info severity and suppressed from notifications.")
                    .font(.nickBodySmall)
                    .foregroundStyle(.secondary)
                addProcessRow
                userListSection
            }
        }
        .formStyle(.grouped)
        .frame(width: 500)
    }

    private var addProcessRow: some View {
        HStack(spacing: NickSpacing.sm) {
            TextField("Process name (e.g. MyApp)", text: $newProcessName)
                .textFieldStyle(.roundedBorder)
                .onSubmit { addProcess() }
            Button("Add", action: addProcess)
                .disabled(newProcessName.trimmingCharacters(in: .whitespaces).isEmpty)
                .buttonStyle(NickPrimaryButtonStyle())
        }
    }

    @ViewBuilder
    private var userListSection: some View {
        let userNames = engine.trustedProcessList.userTrustedNames()

        if userNames.isEmpty {
            Text("No user-added entries yet.")
                .font(.nickBodySmall)
                .foregroundStyle(Color.textTertiary)
        } else {
            VStack(spacing: 0) {
                ForEach(userNames, id: \.self) { name in
                    HStack {
                        Image(systemName: "checkmark.seal")
                            .foregroundStyle(.green)
                            .imageScale(.small)
                        Text(name)
                            .font(.nickBodySmall)
                            .foregroundStyle(Color.textSecondary)
                        Spacer()
                        Button {
                            nameToRemove = name
                            showRemoveProcessConfirmation = true
                        } label: {
                            Image(systemName: "trash")
                                .foregroundStyle(Color.statusRed)
                        }
                        .buttonStyle(.plain)
                    }
                    .padding(.vertical, NickSpacing.sm)
                    if name != userNames.last {
                        Divider()
                    }
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
        }

        builtInListDisclosure
    }

    private var builtInListDisclosure: some View {
        DisclosureGroup("Built-in Trusted Processes (\(TrustedProcessList.builtIn.count))") {
            let sorted = TrustedProcessList.builtIn.sorted()
            LazyVStack(alignment: .leading, spacing: NickSpacing.xs) {
                ForEach(sorted, id: \.self) { name in
                    HStack(spacing: NickSpacing.xs) {
                        Image(systemName: "lock.fill")
                            .foregroundStyle(.secondary)
                            .imageScale(.small)
                        Text(name)
                            .font(.nickBodySmall)
                            .foregroundStyle(Color.textTertiary)
                    }
                }
            }
            .padding(.top, NickSpacing.xs)
        }
        .font(.nickBodySmall)
        .foregroundStyle(Color.textSecondary)
    }

    // MARK: - Actions

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
            // Revert toggle if OS registration fails
            launchAtLogin = !enable
        }
    }
}

// MARK: - Preview

#if DEBUG
#Preview {
    SettingsView()
        .environment(SecurityEngine())
}
#endif
