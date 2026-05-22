// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

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
    @State private var newDirectoryPath: String = ""
    @State private var newProcessName: String = ""
    @State private var showRemoveProcessConfirmation = false
    @State private var nameToRemove: String?

    // MARK: - Body

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: NickSpacing.xxl) {
                notificationsSection
                Divider()
                scanningSection
                Divider()
                systemSection
                Divider()
                directoriesSection
                Divider()
                trustedProcessesSection
            }
            .padding(NickSpacing.xl)
        }
        .frame(minWidth: 540, minHeight: 420)
    }

    // MARK: - Notifications Section

    private var notificationsSection: some View {
        VStack(alignment: .leading, spacing: NickSpacing.lg) {
            Text("Notifications")
                .font(.nickSubtitle)
                .foregroundStyle(Color.textPrimary)

            HStack {
                Text("Minimum severity")
                    .font(.nickBodySmall)
                    .foregroundStyle(Color.textSecondary)
                Spacer()
                Picker("", selection: $notificationThresholdRaw) {
                    ForEach(SignalSeverity.allCases.filter { $0 != .info }, id: \.rawValue) { sev in
                        Text(sev.displayName).tag(sev.rawValue)
                    }
                }
                .labelsHidden()
                .frame(width: 120)
            }

            Text("Alerts below this severity are logged but will not trigger a system notification.")
                .font(.nickCaption)
                .foregroundStyle(Color.textTertiary)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    // MARK: - Scanning Section

    private var scanningSection: some View {
        VStack(alignment: .leading, spacing: NickSpacing.lg) {
            Text("Scanning")
                .font(.nickSubtitle)
                .foregroundStyle(Color.textPrimary)

            HStack {
                Text("Deep scan interval")
                    .font(.nickBodySmall)
                    .foregroundStyle(Color.textSecondary)
                Spacer()
                Picker("", selection: $deepScanIntervalSeconds) {
                    Text("30 seconds").tag(30)
                    Text("1 minute").tag(60)
                    Text("5 minutes").tag(300)
                    Text("15 minutes").tag(900)
                    Text("30 minutes").tag(1800)
                }
                .labelsHidden()
                .frame(width: 140)
            }

            Text("How often Nick performs a full system sweep. More frequent scans increase CPU and battery usage.")
                .font(.nickCaption)
                .foregroundStyle(Color.textTertiary)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    // MARK: - System Section

    private var systemSection: some View {
        VStack(alignment: .leading, spacing: NickSpacing.lg) {
            Text("System")
                .font(.nickSubtitle)
                .foregroundStyle(Color.textPrimary)

            Toggle(isOn: $launchAtLogin) {
                VStack(alignment: .leading, spacing: NickSpacing.xs) {
                    Text("Launch at login")
                        .font(.nickBodySmall)
                        .foregroundStyle(Color.textSecondary)
                    Text("Start Nick automatically when you log in.")
                        .font(.nickCaption)
                        .foregroundStyle(Color.textTertiary)
                }
            }
            .onChange(of: launchAtLogin) { _, newValue in
                toggleLaunchAtLogin(newValue)
            }
        }
    }

    // MARK: - Monitored Directories Section

    private var directoriesSection: some View {
        VStack(alignment: .leading, spacing: NickSpacing.lg) {
            Text("Monitored Directories")
                .font(.nickSubtitle)
                .foregroundStyle(Color.textPrimary)

            Text("Persistence and filesystem watchers scan these directories for suspicious changes.")
                .font(.nickCaption)
                .foregroundStyle(Color.textTertiary)
                .fixedSize(horizontal: false, vertical: true)

            HStack(spacing: NickSpacing.sm) {
                TextField("/path/to/directory", text: $newDirectoryPath)
                    .textFieldStyle(.roundedBorder)
                    .onSubmit { addDirectory() }
                Button("Add", action: addDirectory)
                    .disabled(newDirectoryPath.trimmingCharacters(in: .whitespaces).isEmpty)
                    .buttonStyle(NickPrimaryButtonStyle())
            }

            VStack(spacing: 0) {
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
                    .padding(.vertical, NickSpacing.sm)
                    if path != monitoredDirectories.last {
                        Divider()
                    }
                }
            }
        }
    }

    // MARK: - Trusted Processes Section

    private var trustedProcessesSection: some View {
        VStack(alignment: .leading, spacing: NickSpacing.lg) {
            Text("Trusted Processes")
                .font(.nickSubtitle)
                .foregroundStyle(Color.textPrimary)

            Text("Alerts where all contributing processes are trusted are downgraded to Info severity and suppressed from notifications. Only add software you have personally verified. Built-in entries cover common developer tools and cannot be removed.")
                .font(.nickCaption)
                .foregroundStyle(Color.textTertiary)
                .fixedSize(horizontal: false, vertical: true)

            addProcessRow

            userListSection
        }
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

    private func addDirectory() {
        let trimmed = newDirectoryPath.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty, !monitoredDirectories.contains(trimmed) else { return }
        monitoredDirectories.append(trimmed)
        newDirectoryPath = ""
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
