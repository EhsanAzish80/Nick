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
// MARK: - System Preferences URLs
// Extracted as a single location so scheme changes affect all buttons at once.
// ════════════════════════════════════════════════════════════════

private enum SettingsPrefsURL {
    /// Opens the Keyboard Shortcuts pane so the user can enable the Services entry.
    static let keyboardShortcuts = URL(string: "x-apple.systempreferences:com.apple.preference.keyboard?Shortcuts")!
}

enum SettingsTab: String, CaseIterable, Identifiable {
    case general, protection, network, privacy, advanced, exceptions, logging, about

    var id: String { rawValue }

    var title: String {
        switch self {
        case .general: "General"
        case .protection: "Protection"
        case .network: "Network"
        case .privacy: "Privacy & Data"
        case .advanced: "Advanced"
        case .exceptions: "Exceptions"
        case .logging: "Logging"
        case .about: "About"
        }
    }

    var icon: String {
        switch self {
        case .general: "gearshape"
        case .protection: "checkmark.shield"
        case .network: "globe"
        case .privacy: "lock"
        case .advanced: "slider.horizontal.3"
        case .exceptions: "person.badge.shield.checkmark"
        case .logging: "terminal"
        case .about: "info.circle"
        }
    }

    var subtitle: String {
        switch self {
        case .general: "How Nick starts, looks, alerts you and stays up to date."
        case .protection: "What Nick checks, how often, and when it steps in."
        case .network: "Stop scam and malware sites, and choose what's always allowed."
        case .privacy: "What Nick remembers on this Mac, and how to clear it."
        case .advanced: "Exceptions, monitored folders, logging and integrations."
        case .exceptions: "Trusted processes, suppression rules, developer repositories and watched folders."
        case .logging: "Send alerts to log files, a SIEM webhook or standard output."
        case .about: "Version, licences, update diagnostics and removal."
        }
    }

    static func visible(for mode: InterfaceMode) -> [SettingsTab] {
        mode == .simple
            ? [.general, .protection, .network, .privacy, .advanced, .about]
            : [.general, .protection, .network, .privacy, .exceptions, .logging, .about]
    }
}

private struct SettingsSearchEntry: Identifiable {
    let title: String
    let keywords: String
    let tab: SettingsTab
    var id: String { "\(tab.rawValue).\(title)" }
}

// ════════════════════════════════════════════════════════════════
// MARK: - SettingsView
// ════════════════════════════════════════════════════════════════

struct SettingsView: View {

    // MARK: Dependencies

    @Environment(SecurityEngine.self) private var engine
    @Environment(NetworkProtectionManager.self) private var networkProtection
    @Environment(ExtensionXPCClient.self) private var xpcClient

    // MARK: App Storage

    @AppStorage("deepScanIntervalSeconds") private var deepScanIntervalSeconds: Int = 300
    @AppStorage("logFormatter") private var logFormatter: String = "kv"
    @AppStorage("fileLoggingEnabled") private var fileLoggingEnabled: Bool = false
    @AppStorage("stdoutLoggingEnabled") private var stdoutLoggingEnabled: Bool = false
    @AppStorage("allowInsecureLocalWebhook") private var allowInsecureLocalWebhook: Bool = false
    @AppStorage("scheduledDeepScanInterval") private var scheduledDeepScanInterval: Int = 0
    @AppStorage("telemetryEnabled") private var telemetryEnabled: Bool = false
    @AppStorage("appAppearance") private var appAppearance: AppAppearance = .system
    /// Simple vs Advanced presentation for the whole app.
    @AppStorage(InterfaceMode.storageKey) private var interfaceMode: InterfaceMode = .simple
    private var simpleAlertMode: Bool { interfaceMode == .simple }

    // MARK: Private State

    @State private var webhookURLString: String = ""
    @State private var webhookTestStatus: String? = nil
    @State private var newSuppressionType: SuppressionType = .processName
    @State private var newSuppressionValue: String = ""
    @State private var newSuppressionNote: String = ""

    @State private var launchAtLogin: Bool = (SMAppService.mainApp.status == .enabled)
    @State private var monitoredDirectories: [String] = {
        (UserDefaults.standard.array(forKey: "monitoredDirectories") as? [String])
            ?? ["/Users", "/Applications", "/Library", "/private/tmp"]
    }()
    @State private var newProcessName: String = ""
    @State private var trustedProcessStatus: String?
#if DEBUG
    @State private var authorizationHarnessStatus: String?
    @State private var retentionHarnessStatus: String?
#endif
    @State private var newAllowedDomain: String = ""
    @State private var newAllowedApp: String = ""
    @State private var showRemoveProcessConfirmation = false
    @State private var nameToRemove: String?
    @State private var showClearAlertsConfirmation = false
    @State private var showResetHistoryConfirmation = false
    @State private var showRemoveHelperConfirmation = false
    @State private var updateCheckStatus: String?
    @State private var showsAcknowledgements = false
    @State private var showsLearnedReviewEntries = false
    @State private var showsLegacyDismissals = false
    @State private var verdictLearningStatus: String?
    @State private var strictBlockingStatus: String?
    @State private var protectionUpdateStatus: String?
    @AppStorage("nickUpdateLastCheckTime") private var updateLastCheckTime: Double = 0
    @AppStorage("nickUpdateLastCheckResult") private var updateLastCheckResult: String = "Never checked"
    @AppStorage("nickUpdateAvailable") private var updateAvailable = false
    @AppStorage("nickUpdateAvailableVersion") private var updateAvailableVersion = ""
    /// Simple mode keeps the technical sections behind this disclosure.
    @State private var showsAdvancedSettings = false
    @AppStorage("autoCheckUpdates") private var autoCheckUpdates: Bool = true
    @SceneStorage("settings.selectedTab") private var selectedTabRawValue = SettingsTab.general.rawValue
    @State private var settingsSearch = ""

    private var selectedTab: SettingsTab {
        get { SettingsTab(rawValue: selectedTabRawValue) ?? .general }
        nonmutating set { selectedTabRawValue = newValue.rawValue }
    }

    // MARK: Body

    var body: some View {
        VStack(spacing: 0) {
            SettingsHeader(
                tab: selectedTab,
                mode: interfaceMode,
                searchText: $settingsSearch
            )
            SettingsTabBar(
                tabs: SettingsTab.visible(for: interfaceMode),
                selection: Binding(get: { selectedTab }, set: { selectedTab = $0 })
            )
            Divider()
            if settingsSearch.isEmpty {
                settingsTabContent
            } else {
                settingsSearchResults
            }
        }
        .background(Color(nsColor: .windowBackgroundColor))
        .onAppear {
            refreshLaunchAtLogin()
            webhookURLString = engine.webhookURLString ?? ""
        }
        .task { await networkProtection.refresh() }
        .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in
            refreshLaunchAtLogin()
        }
        .onChange(of: interfaceMode) { oldMode, newMode in
            guard oldMode != newMode else { return }
            if newMode == .simple, selectedTab == .exceptions || selectedTab == .logging {
                selectedTab = .advanced
            } else if newMode == .advanced, selectedTab == .advanced {
                selectedTab = .exceptions
            }
        }
        .sheet(isPresented: $showsAcknowledgements) {
            AcknowledgementsView()
        }
        .sheet(isPresented: $showsLearnedReviewEntries) {
            LearnedReviewEntriesView()
                .environment(engine)
        }
        .sheet(isPresented: $showsLegacyDismissals) {
            LegacyDismissalsView()
                .environment(engine)
        }
    }

    @ViewBuilder
    private var settingsTabContent: some View {
        ScrollView {
            Form {
                switch selectedTab {
                case .general:
                    generalSection
                    appearanceSection
                    notificationsSection
                    updatesSection
                case .protection:
                    scanningSection
                    finderIntegrationSection
                    protectionDataSection
                case .network:
                    networkProtectionSection
                case .privacy:
                    privacyDataSection
                case .advanced:
                    advancedSettingsDisclosure
                    if showsAdvancedSettings { technicalSections }
                case .exceptions:
                    monitoredDirectoriesSection
                    trustedProcessesSection
                    suppressionRulesSection
                case .logging:
                    integrationsSection
#if DEBUG
                    debugValidationSection
#endif
                case .about:
                    aboutAppSection
                    updateDiagnosticsSection
                    maintenanceSection
                    acknowledgementsSection
                }
            }
            .formStyle(.grouped)
            .scrollDisabled(true)
            .environment(\.layoutDirection, .leftToRight)
            .frame(maxWidth: 680)
            .padding(.horizontal, 40)
            .padding(.bottom, 32)
            .frame(maxWidth: .infinity)
        }
    }

    private var searchEntries: [SettingsSearchEntry] {
        [
            .init(title: "Launch at login", keywords: "startup open", tab: .general),
            .init(title: "Appearance", keywords: "theme system light dark", tab: .general),
            .init(title: "Minimum severity", keywords: "alerts notifications", tab: .general),
            .init(title: "Updates", keywords: "automatic check version", tab: .general),
            .init(title: "Scheduled deep scan", keywords: "full scan background sweep", tab: .protection),
            .init(title: "Automatic protection updates", keywords: "signed threat intelligence", tab: .protection),
            .init(title: "Strict blocking", keywords: "block malware strict mode", tab: .protection),
            .init(title: "Emergency stop blocking", keywords: "kill switch pause", tab: .protection),
            .init(title: "Network Protection", keywords: "filter websites apps", tab: .network),
            .init(title: "Allowed websites and apps", keywords: "allowlist temporary access", tab: .network),
            .init(title: "Learn from my decisions", keywords: "review learning dismissed", tab: .privacy),
            .init(title: "Clear alert history", keywords: "reset scan history", tab: .privacy),
            .init(title: "Trusted processes", keywords: "exceptions approved repositories", tab: .exceptions),
            .init(title: "Suppression rules", keywords: "exceptions monitored folders", tab: .exceptions),
            .init(title: "Logging and integrations", keywords: "webhook json cef stdout", tab: .logging),
            .init(title: "Acknowledgements", keywords: "version licence github", tab: .about),
            .init(title: "Uninstall Nick", keywords: "remove helper maintenance", tab: .about)
        ]
    }

    private var settingsSearchResults: some View {
        let query = settingsSearch.trimmingCharacters(in: .whitespacesAndNewlines)
        let matches = searchEntries.filter {
            "\($0.title) \($0.keywords) \($0.tab.title)".localizedCaseInsensitiveContains(query)
        }
        return ScrollView {
            LazyVStack(spacing: 1) {
                ForEach(matches) { entry in
                    Button {
                        settingsSearch = ""
                        selectedTab = entry.tab == .advanced && interfaceMode == .advanced ? .exceptions : entry.tab
                    } label: {
                        HStack {
                            VStack(alignment: .leading, spacing: 3) {
                                Text(entry.title).font(.system(size: 13, weight: .medium))
                                Text(entry.tab.title).font(.system(size: 11.5)).foregroundStyle(.secondary)
                            }
                            Spacer()
                            Image(systemName: "chevron.right").foregroundStyle(.tertiary)
                        }
                        .padding(14)
                        .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                    Divider()
                }
            }
            .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 10))
            .overlay(RoundedRectangle(cornerRadius: 10).stroke(.separator.opacity(0.6)))
            .frame(maxWidth: 680)
            .padding(40)
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
                Text(interfaceMode == .simple
                     ? "Notifications, scanning, updates and your data."
                     : "Notifications, scanning, monitored locations, and trusted processes.")
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

    /// Integrations and logging, monitored folders, trusted processes and
    /// suppression rules. Always shown in Advanced; opt-in in Simple.
    @ViewBuilder
    private var technicalSections: some View {
        integrationsSection
        monitoredDirectoriesSection
        trustedProcessesSection
#if DEBUG
        debugValidationSection
#endif
        suppressionRulesSection
    }

    private var advancedSettingsDisclosure: some View {
        Section {
            VStack(spacing: 14) {
                Image(systemName: "slider.horizontal.3")
                    .font(.system(size: 34))
                    .foregroundStyle(.secondary)
                    .frame(height: 64)
                Text("Settings for experienced users")
                    .font(.system(size: 15, weight: .semibold))
                Text("Nick's defaults are safe, and most people never need to change these. Changing them can hide alerts or reduce what Nick watches.")
                    .font(.system(size: 12.5))
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .frame(maxWidth: 500)
                Button(showsAdvancedSettings ? "Hide Advanced Settings" : "Show Advanced Settings") {
                    withAnimation { showsAdvancedSettings.toggle() }
                }
                .buttonStyle(.borderedProminent)
                Text("Want the full technical app? Switch to Advanced view in General, or press ⇧⌘A.")
                    .font(.system(size: 11.5))
                    .foregroundStyle(.secondary)
            }
            .frame(maxWidth: .infinity)
            .padding(.vertical, 10)
        } footer: {
            Text("What's inside: Exceptions, monitored folders, logging and integrations.")
                .font(.system(size: 11.5))
                .foregroundStyle(.secondary)
        }
    }

    @ViewBuilder
    private var generalSection: some View {
        Section("View") {
            ViewModeChooser(selection: $interfaceMode)
        }
        Section("Startup & appearance") {
            LabeledTile(
                icon: "power", tint: .green,
                title: interfaceMode == .simple ? "Open Nick when I log in" : "Launch at login",
                subtitle: interfaceMode == .simple
                    ? "Recommended, so protection is running from the start."
                    : "Start Nick automatically when you log in."
            ) {
                Toggle("", isOn: $launchAtLogin)
                    .labelsHidden()
                    .accessibilityLabel("Launch Nick at login")
                    .toggleStyle(.switch)
                    .onChange(of: launchAtLogin) { _, newValue in toggleLaunchAtLogin(newValue) }
            }
        }
    }

    private var appearanceSection: some View {
        Section("Appearance") {
            LabeledTile(
                icon: "circle.lefthalf.filled", tint: .purple,
                title: "Theme",
                subtitle: "System follows your macOS appearance setting."
            ) {
                Picker("", selection: $appAppearance) {
                    ForEach(AppAppearance.allCases, id: \.self) { mode in
                        Text(mode.rawValue).tag(mode)
                    }
                }
                .pickerStyle(.segmented)
                .fixedSize()
                .labelsHidden()
            }
        }
    }

    private var notificationsSection: some View {
        Section {
            LabeledTile(
                icon: "bell.fill", tint: .red,
                title: "Minimum severity"
            ) {
                Picker("", selection: Binding(
                    get: { engine.notificationThreshold.rawValue },
                    set: { newValue in
                        guard let severity = SignalSeverity(rawValue: newValue) else { return }
                        // Raising the threshold hides more notifications and is
                        // therefore a protection-reducing change.
                        if severity > engine.notificationThreshold {
                            guard let authorization = xpcClient.requestProtectionModificationAuthorization()
                            else { return }
                            engine.authorizeNextSecuritySettingsWrite(with: authorization)
                        }
                        engine.notificationThreshold = severity
                    }
                )) {
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
            Text(
                simpleAlertMode
                    ? "Alerts explain what happened in plain words. Open “Technical details” in an alert to see more."
                    : "Alerts show full technical details inline, including process paths, PIDs, and confidence scores."
            )
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
                    Text("5 minutes").tag(300)
                    Text("15 minutes").tag(900)
                    Text("30 minutes").tag(1800)
                }
                .labelsHidden()
                .frame(width: 150)
            }
            LabeledTile(
                icon: "calendar.badge.clock", tint: .teal,
                title: "Scheduled Deep Scan"
            ) {
                Picker("", selection: $scheduledDeepScanInterval) {
                    Text("Disabled").tag(0)
                    Text("Daily").tag(86400)
                    Text("Weekly").tag(604800)
                    Text("Monthly").tag(2592000)
                }
                .labelsHidden()
                .frame(width: 120)
            }
            DisclosureGroup("Approved development repositories (\(engine.approvedDevelopmentRoots.count))") {
                ForEach(engine.approvedDevelopmentRoots.sorted(), id: \.self) { path in
                    HStack {
                        Text(path).font(.caption).textSelection(.enabled)
                        Spacer()
                        Button("Remove", role: .destructive) {
                            engine.approvedDevelopmentRoots.remove(path)
                        }
                    }
                }
                Button("Add Repository…", action: approveDevelopmentRepository)
            }
        } header: {
            Text("Scanning")
        } footer: {
            Text("How often Nick performs a background sweep. Approved repositories keep unsigned build tools alert-only; protected detections remain visible and are never suppressed.")
                .font(.system(size: 11.5))
                .foregroundStyle(.secondary)
        }
    }

    private func approveDevelopmentRepository() {
        let panel = NSOpenPanel()
        panel.canChooseFiles = false
        panel.canChooseDirectories = true
        panel.allowsMultipleSelection = false
        panel.prompt = "Approve Repository"
        guard panel.runModal() == .OK, let selected = panel.url else { return }
        let root = selected.standardizedFileURL
        guard FileManager.default.fileExists(atPath: root.appendingPathComponent(".git").path),
              let authorization = xpcClient.requestProtectionModificationAuthorization() else { return }
        engine.authorizeNextSecuritySettingsWrite(with: authorization)
        engine.approvedDevelopmentRoots.insert(root.path)
    }

    private var networkProtectionSection: some View {
        Section {
            LabeledTile(
                icon: "network.badge.shield.half.filled",
                tint: networkProtection.isEnabled ? .green : .orange,
                title: "Network Protection",
                subtitle: networkProtectionStatusText
            ) {
                Toggle("", isOn: Binding(
                    get: { networkProtection.isEnabled },
                    set: { enabled in
                        Task { await networkProtection.setEnabled(enabled) }
                    }
                ))
                .labelsHidden()
                .accessibilityLabel("Network Protection")
                .toggleStyle(.switch)
            }

            if case .awaitingApproval = networkProtection.state {
                LabeledTile(
                    icon: "gearshape.fill", tint: .orange,
                    title: "Approval required",
                    subtitle: "Allow Nick under Login Items & Extensions → Network Extensions."
                ) {
                    Button("Open Settings") {
                        networkProtection.openNetworkExtensionSettings()
                    }
                    .controlSize(.small)
                }
            }

            if case .failed(let message) = networkProtection.state {
                Text(message)
                    .font(.caption)
                    .foregroundStyle(.red)
                    .textSelection(.enabled)
            }

            DisclosureGroup("Allowed Websites (\(networkProtection.allowedDomains.count))") {
                HStack {
                    TextField("example.com", text: $newAllowedDomain)
                        .textFieldStyle(.roundedBorder)
                        .onSubmit { addAllowedDomain() }
                    Button("Add", action: addAllowedDomain)
                        .disabled(newAllowedDomain.trimmingCharacters(in: .whitespaces).isEmpty)
                }
                ForEach(networkProtection.allowedDomains, id: \.self) { domain in
                    allowlistRow(domain) {
                        Task { await networkProtection.removeAllowedDomain(domain) }
                    }
                }
            }

            DisclosureGroup("Allowed Apps (\(networkProtection.allowedAppIdentifiers.count))") {
                HStack {
                    TextField("com.example.app", text: $newAllowedApp)
                        .textFieldStyle(.roundedBorder)
                        .onSubmit { addAllowedApp() }
                    Button("Add", action: addAllowedApp)
                        .disabled(newAllowedApp.trimmingCharacters(in: .whitespaces).isEmpty)
                }
                ForEach(networkProtection.allowedAppIdentifiers, id: \.self) { identifier in
                    allowlistRow(identifier) {
                        Task { await networkProtection.removeAllowedApp(identifier) }
                    }
                }
            }

            if !networkProtection.temporaryAllowedDomains.isEmpty
                || !networkProtection.temporaryAllowedAppIdentifiers.isEmpty {
                DisclosureGroup(
                    "Temporary Access (\(networkProtection.temporaryAllowedDomains.count + networkProtection.temporaryAllowedAppIdentifiers.count))"
                ) {
                    ForEach(
                        networkProtection.temporaryAllowedDomains.keys.sorted(),
                        id: \.self
                    ) { domain in
                        temporaryAllowlistRow(
                            domain,
                            expiry: networkProtection.temporaryAllowedDomains[domain]
                        ) {
                            Task {
                                await networkProtection.removeTemporaryAllowedDomain(domain)
                            }
                        }
                    }
                    ForEach(
                        networkProtection.temporaryAllowedAppIdentifiers.keys.sorted(),
                        id: \.self
                    ) { identifier in
                        temporaryAllowlistRow(
                            identifier,
                            expiry: networkProtection.temporaryAllowedAppIdentifiers[identifier]
                        ) {
                            Task {
                                await networkProtection.removeTemporaryAllowedApp(identifier)
                            }
                        }
                    }
                }
            }

            LabeledTile(
                icon: "exclamationmark.octagon.fill", tint: .red,
                title: "Emergency disable",
                subtitle: "Immediately stop network filtering if a site or app cannot connect."
            ) {
                Button("Disable Now", role: .destructive) {
                    Task { await networkProtection.emergencyDisable() }
                }
                .controlSize(.small)
                .disabled(!networkProtection.isEnabled)
            }
        } header: {
            Text("Network Protection")
        } footer: {
            Text("Allowed websites and apps always take priority. Nick interrupts only verified signed blocklist matches; heuristic findings remain review-only. Nick never stores page contents or browsing history.")
                .font(.system(size: 11.5))
                .foregroundStyle(.secondary)
        }
    }

    private func temporaryAllowlistRow(
        _ value: String,
        expiry: Date?,
        remove: @escaping () -> Void
    ) -> some View {
        HStack {
            VStack(alignment: .leading, spacing: 2) {
                Text(value)
                    .textSelection(.enabled)
                if let expiry {
                    Text("Allowed until \(expiry.formatted(date: .abbreviated, time: .shortened))")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            Spacer()
            Button("Remove", role: .destructive, action: remove)
                .controlSize(.small)
        }
    }

    private var networkProtectionStatusText: String {
        switch networkProtection.state {
        case .loading: return "Checking the Network Filter…"
        case .enabled: return "Scam Guardian is checking connection destinations."
        case .disabled: return "Filtering is off. Passive network monitoring continues."
        case .awaitingApproval: return "Waiting for approval in System Settings."
        case .failed: return "Nick could not verify the Network Filter."
        }
    }

    private func allowlistRow(_ value: String, remove: @escaping () -> Void) -> some View {
        HStack {
            Image(systemName: "checkmark.shield.fill")
                .foregroundStyle(.green)
            Text(value)
                .font(.system(.caption, design: .monospaced))
                .textSelection(.enabled)
            Spacer()
            Button(role: .destructive, action: remove) {
                Image(systemName: "minus.circle")
            }
            .buttonStyle(.plain)
            .accessibilityLabel("Remove \(value)")
        }
        .padding(.vertical, 2)
    }

    private var integrationsSection: some View {
        Section {
            LabeledTile(
                icon: "doc.badge.gearshape", tint: .indigo,
                title: "Log Format",
                subtitle: "Applies to all enabled outputs."
            ) {
                Picker("", selection: $logFormatter) {
                    Text("Key=Value").tag("kv")
                    Text("JSON").tag("json")
                    Text("CEF").tag("cef")
                }
                .pickerStyle(.segmented)
                .labelsHidden()
                .frame(width: 200)
            }
            LabeledTile(
                icon: "doc.text.fill", tint: .blue,
                title: "Write to log file",
                subtitle: "~/Library/Logs/Nick/nick-YYYY-MM-DD.log — rotated daily, kept 30 days."
            ) {
                Toggle("", isOn: $fileLoggingEnabled)
                    .labelsHidden()
                    .toggleStyle(.switch)
            }
            VStack(alignment: .leading, spacing: 8) {
                HStack(spacing: 12) {
                    RoundedRectangle(cornerRadius: 6, style: .continuous)
                        .fill(Color.orange)
                        .frame(width: 26, height: 26)
                        .overlay(
                            Image(systemName: "network.badge.shield.half.filled")
                                .font(.system(size: 14, weight: .regular))
                                .foregroundStyle(.white)
                        )
                    Text("Webhook endpoint")
                        .font(.system(size: 13))
                    Spacer()
                }
                TextField(text: $webhookURLString,
                          prompt: Text("https://splunk:8088/services/collector/event")) { EmptyView() }
                    .textFieldStyle(.roundedBorder)
                    .frame(maxWidth: .infinity)
                    .labelsHidden()
                    .multilineTextAlignment(.leading)
                    .onSubmit { saveWebhookURL() }
                    .onChange(of: webhookURLString) { _, _ in saveWebhookURL() }
                HStack(spacing: 4) {
                    if !webhookURLString.isEmpty {
                        if isValidWebhookURL {
                            Image(systemName: "checkmark.circle.fill")
                                .imageScale(.small)
                                .foregroundStyle(.green)
                        } else {
                            Image(systemName: "exclamationmark.circle.fill")
                                .imageScale(.small)
                                .foregroundStyle(.red)
                            Text("Invalid URL")
                                .font(.system(size: 11.5))
                                .foregroundStyle(.red)
                        }
                    }
                }
                .animation(.easeInOut(duration: 0.15), value: webhookURLString)
                if webhookUsesRejectedHTTP {
                    Text("HTTP webhooks are disabled. Use HTTPS, or enable HTTP for localhost only.")
                        .font(.system(size: 11.5))
                        .foregroundStyle(.orange)
                }
                Toggle("Allow HTTP for localhost only", isOn: $allowInsecureLocalWebhook)
                    .font(.system(size: 11.5))
                    .onChange(of: allowInsecureLocalWebhook) { _, _ in saveWebhookURL() }
                Text("Remote webhook endpoints must use HTTPS.")
                    .font(.system(size: 11.5))
                    .foregroundStyle(.secondary)
                if isValidWebhookURL {
                    HStack(spacing: 8) {
                        Button("Send test alert") {
                            Task { await sendTestWebhook(to: URL(string: webhookURLString)!) }
                        }
                        .font(.nickCaption)
                        .buttonStyle(.borderless)
                        if let status = webhookTestStatus {
                            Text(status)
                                .font(.system(size: 11.5))
                                .foregroundStyle(status == "Sent" ? Color.green : Color.red)
                                .transition(.opacity)
                        }
                    }
                    .animation(.easeInOut(duration: 0.2), value: webhookTestStatus)
                }
            }
            .padding(.vertical, 2)
            LabeledTile(
                icon: "terminal.fill", tint: .gray,
                title: "Standard output",
                subtitle: "For debugging and pipe-based integrations."
            ) {
                Toggle("", isOn: $stdoutLoggingEnabled)
                    .labelsHidden()
                    .toggleStyle(.switch)
            }
        } header: {
            Text("Integrations")
        } footer: {
            Text("Pick a formatter and one or more outputs. The pipeline is rebuilt on every alert.")
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
                    .onSubmit { authorizeAndAddProcess() }
                Button("Add") { authorizeAndAddProcess() }
                    .disabled(newProcessName.trimmingCharacters(in: .whitespaces).isEmpty)
                    .buttonStyle(.borderedProminent)
                    .controlSize(.small)
            }

            if let trustedProcessStatus {
                Text(trustedProcessStatus)
                    .font(.system(size: 11.5))
                    .foregroundStyle(.secondary)
            }

            legacyTrustedProcessContent

            userListContent
            .confirmationDialog(
                "Remove \"\(nameToRemove ?? "")\" from trusted processes?",
                isPresented: $showRemoveProcessConfirmation,
                titleVisibility: .visible
            ) {
                Button("Remove", role: .destructive) {
                    if let n = nameToRemove { removeProcess(n) }
                }
                Button("Cancel", role: .cancel) {
                    // SwiftUI dismisses a confirmation dialog for its cancel role.
                }
            }
        } header: {
            Text("Trusted Processes")
        } footer: {
            Text("Add a currently running, signed process. Trust is bound to its exact Team ID and signing identifier; its name alone is never trusted.")
                .font(.system(size: 11.5))
                .foregroundStyle(.secondary)
        }
    }

#if DEBUG
    private var debugValidationSection: some View {
        Section("DEBUG Validation") {
            Button("Test Refused Authorization Form") {
                xpcClient.debugSendNeverAuthorizedProtectionCall { result in
                    authorizationHarnessStatus = result.statusText
                }
            }
            .buttonStyle(.bordered)
            if let authorizationHarnessStatus {
                Text(authorizationHarnessStatus)
                    .font(.system(size: 11.5, design: .monospaced))
                    .foregroundStyle(authorizationHarnessStatus.hasPrefix("Passed") ? .green : .red)
            }
            Button("Run Retention Flood Harness") {
                retentionHarnessStatus = engine.debugRunRetentionFlood()
                Task { @MainActor in
                    try? await Task.sleep(for: .seconds(2))
                    retentionHarnessStatus = (retentionHarnessStatus ?? "")
                        + " | " + engine.debugRetentionFloodPersistenceStatus()
                }
            }
            .buttonStyle(.bordered)
            Button("Clean Retention Flood Harness") {
                retentionHarnessStatus = engine.debugCleanRetentionFlood()
                Task { @MainActor in
                    try? await Task.sleep(for: .seconds(2))
                    retentionHarnessStatus = (retentionHarnessStatus ?? "")
                        + " | " + engine.debugRetentionFloodPersistenceStatus()
                }
            }
            .buttonStyle(.bordered)
            if let retentionHarnessStatus {
                Text(retentionHarnessStatus)
                    .font(.system(size: 11.5, design: .monospaced))
                    .foregroundStyle(retentionHarnessStatus.contains("FAILED") ? .red : .green)
            }
        }
    }
#endif

    @ViewBuilder
    private var legacyTrustedProcessContent: some View {
        let names = engine.trustedProcessList.userTrustedNames()
        if !names.isEmpty {
            VStack(alignment: .leading, spacing: 8) {
                Label("Previous name-only trust entries need approval", systemImage: "exclamationmark.triangle.fill")
                    .font(.system(size: 12, weight: .semibold))
                    .foregroundStyle(.orange)
                Text("Names alone are no longer trusted. Run each app, then approve its verified signing identity.")
                    .font(.system(size: 11.5))
                    .foregroundStyle(.secondary)
                ForEach(names, id: \.self) { name in
                    HStack {
                        Text(name).font(.system(size: 12.5))
                        Spacer()
                        Button("Re-approve") { reapproveLegacyProcess(name) }
                            .controlSize(.small)
                    }
                }
            }
            .padding(.vertical, 4)
        }
    }

    @ViewBuilder
    private var userListContent: some View {
        let entries = engine.trustedProcessList.userTrustedEntries()
        if entries.isEmpty {
            Text("No user-added entries yet.")
                .font(.system(size: 12))
                .italic()
                .foregroundStyle(.secondary)
        } else {
            ForEach(entries, id: \.self) { entry in
                HStack(spacing: 10) {
                    Image(systemName: "checkmark.circle.fill")
                        .foregroundStyle(.green)
                        .imageScale(.small)
                    VStack(alignment: .leading, spacing: 1) {
                        Text(entry.displayName).font(.system(size: 12.5))
                        Text("\(entry.identity.teamID) · \(entry.identity.signingID)")
                            .font(.system(size: 10.5, design: .monospaced))
                            .foregroundStyle(.secondary)
                    }
                    Spacer()
                    Button {
                        nameToRemove = entry.displayName
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

    // MARK: - Suppression Rules Section

    private var suppressionRulesSection: some View {
        Section {
            ForEach(engine.suppressionRuleMigrationNotices, id: \.self) { notice in
                Label(notice, systemImage: "exclamationmark.triangle.fill")
                    .font(.system(size: 11.5))
                    .foregroundStyle(.orange)
            }
            if !engine.suppressionRules.isEmpty {
                ForEach(engine.suppressionRules) { rule in
                    HStack(spacing: 10) {
                        VStack(alignment: .leading, spacing: 2) {
                            HStack(spacing: 6) {
                                Text(rule.type.displayName)
                                    .font(.system(size: 11, weight: .semibold))
                                    .foregroundStyle(Color.textTertiary)
                                Text(rule.value)
                                    .font(.system(size: 13, weight: .medium))
                                    .foregroundStyle(Color.textPrimary)
                            }
                            if !rule.note.isEmpty {
                                Text(rule.note)
                                    .font(.system(size: 11))
                                    .foregroundStyle(Color.textSecondary)
                            }
                            Text(rule.createdAt, style: .date)
                                .font(.system(size: 10))
                                .foregroundStyle(Color.textTertiary)
                        }
                        Spacer()
                        Button(role: .destructive) {
                            engine.suppressionRules.removeAll { $0.id == rule.id }
                        } label: {
                            Image(systemName: "trash")
                                .foregroundStyle(.red)
                        }
                        .buttonStyle(.plain)
                    }
                    .padding(.vertical, 2)
                }

                Divider()
            }

            VStack(alignment: .leading, spacing: NickSpacing.md) {
                HStack(spacing: NickSpacing.md) {
                    Picker("Type", selection: $newSuppressionType) {
                        ForEach(SuppressionType.allCases, id: \.self) { type in
                            Text(type.displayName).tag(type)
                        }
                    }
                    .labelsHidden()
                    .frame(width: 140)

                    TextField(placeholderFor(newSuppressionType), text: $newSuppressionValue)
                        .textFieldStyle(.roundedBorder)
                        .frame(maxWidth: .infinity)
                }

                HStack {
                    TextField("Note (optional)", text: $newSuppressionNote)
                        .textFieldStyle(.roundedBorder)
                        .frame(maxWidth: .infinity)

                    Button("Add Rule") { authorizeAndAddSuppressionRule() }
                        .disabled(newSuppressionValue.trimmingCharacters(in: .whitespaces).isEmpty)
                }
            }
            .padding(.top, 4)
        } header: {
            Text("Suppression Rules")
        } footer: {
            Text("Suppression rules prevent specific alerts from firing. Alerts from matching processes, paths, or rule names are silently discarded.")
                .font(.system(size: 11.5))
                .foregroundStyle(.secondary)
        }
    }

    private func placeholderFor(_ type: SuppressionType) -> String {
        switch type {
        case .processName: return "e.g. xcodebuild"
        case .path:        return "e.g. /usr/local/bin/tool"
        case .ruleName:    return "e.g. raw_ip_outbound"
        case .signedProcess: return "Team ID | signing identifier"
        }
    }

    private func authorizeAndAddSuppressionRule() {
        guard let authorization = xpcClient.requestProtectionModificationAuthorization() else { return }
        let trimmed = newSuppressionValue.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty else { return }
        engine.authorizeNextSecuritySettingsWrite(with: authorization)
        let rule = SuppressionRule(
            type: newSuppressionType,
            value: trimmed,
            note: newSuppressionNote.trimmingCharacters(in: .whitespaces)
        )
        engine.suppressionRules.append(rule)
        newSuppressionValue = ""
        newSuppressionNote = ""
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
                    NSWorkspace.shared.open(SettingsPrefsURL.keyboardShortcuts)
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

    private var protectionDataSection: some View {
        Section("Updates to protection") {
            LabeledTile(
                icon: "shield.lefthalf.filled.badge.checkmark", tint: .blue,
                title: "Automatic protection updates",
                subtitle: "Download and verify Nick's signed protection intelligence. On by default; Strict Mode remains separate and off by default."
            ) {
                Toggle("", isOn: Binding(
                    get: { engine.automaticProtectionUpdatesEnabled },
                    set: { updateAutomaticProtectionUpdates($0) }
                ))
                .labelsHidden()
                .toggleStyle(.switch)
            }
            HStack {
                Button("Check now") { Task { await xpcClient.checkThreatBundleNow() } }
                    .controlSize(.small)
                Spacer()
                Text(protectionUpdateSummary)
                    .font(.system(size: 11.5))
                    .foregroundStyle(.secondary)
            }
            if let protectionUpdateStatus {
                Text(protectionUpdateStatus).font(.system(size: 11.5)).foregroundStyle(.secondary)
            }
            LabeledTile(
                icon: "lock.shield.fill", tint: .red,
                title: "Strict blocking",
                subtitle: "Allow only high-confidence rules authorized by Nick's signed intelligence bundle to block. Off by default; exact known-malware hashes remain protected."
            ) {
                Toggle("", isOn: Binding(
                    get: { engine.strictModeEnabled },
                    set: { updateStrictMode($0) }
                ))
                    .labelsHidden()
                    .toggleStyle(.switch)
            }
            LabeledTile(
                icon: "hand.raised.slash.fill", tint: .orange,
                title: "Emergency stop blocking",
                subtitle: "Immediately allow all Endpoint Security authorization requests while keeping detection and reporting active."
            ) {
                Toggle("", isOn: Binding(
                    get: { engine.blockingKillSwitch },
                    set: { updateBlockingKillSwitch($0) }
                ))
                    .labelsHidden()
                    .toggleStyle(.switch)
            }
            if let strictBlockingStatus {
                Text(strictBlockingStatus)
                    .font(.system(size: 11.5))
                    .foregroundStyle(.secondary)
            }
        }
    }

    @ViewBuilder
    private var privacyDataSection: some View {
        Section("Learning") {
            LabeledTile(
                icon: "brain.head.profile", tint: .purple,
                title: "Learn from my review decisions",
                subtitle: "Lower the priority of matching review-only findings on this Mac. Malware signatures and protected detections are never affected."
            ) {
                Toggle("", isOn: Binding(
                    get: { engine.verdictLearningEnabled },
                    set: { updateVerdictLearning($0) }
                ))
                    .labelsHidden()
                    .toggleStyle(.switch)
            }
            if let verdictLearningStatus {
                Text(verdictLearningStatus)
                    .font(.system(size: 11.5))
                    .foregroundStyle(.secondary)
            }
            LabeledTile(
                icon: "list.bullet.rectangle", tint: .purple,
                title: "What Nick learned",
                subtitle: "Review, export, or reset local verdict-learning entries."
            ) {
                Button("View…") { showsLearnedReviewEntries = true }
                    .controlSize(.small)
            }
            if !engine.legacyDismissalTombstones.isEmpty {
                LabeledTile(
                    icon: "clock.arrow.circlepath", tint: .orange,
                    title: "Dismissed in Nick 4.x",
                    subtitle: "Review or reset dismissals imported during the upgrade."
                ) {
                    Button("View…") { showsLegacyDismissals = true }
                        .controlSize(.small)
                }
            }
        }
        Section("Help improve detection") {
            LabeledTile(
                icon: "brain", tint: .blue,
                title: "Contribute to detection improvements",
                subtitle: "Locally records dismissed/confirmed alerts as training data. Never transmitted — export manually to contribute."
            ) {
                Toggle("", isOn: $telemetryEnabled)
                    .labelsHidden()
                    .toggleStyle(.switch)
            }
            if telemetryEnabled {
                LabeledTile(
                    icon: "square.and.arrow.up", tint: .blue,
                    title: "Export training data",
                    subtitle: "Save local signal telemetry as JSONL for optional manual submission."
                ) {
                    Button("Export…") { exportTelemetryData() }
                        .controlSize(.small)
                }
            }
        }
        Section("Clear history") {
            LabeledTile(
                icon: "exclamationmark.triangle.fill", tint: .red,
                title: "Clear alert history",
                subtitle: "Remove incident history and reset its counter. Keeps learned decisions, dismissals, suppression rules, trusted processes, cooldowns, quarantine records, and settings."
            ) {
                Button("Clear…", role: .destructive) {
                    showClearAlertsConfirmation = true
                }
                .controlSize(.small)
            }
            .alert(
                "Remove incident history?",
                isPresented: $showClearAlertsConfirmation
            ) {
                Button("Remove Incident History", role: .destructive) { engine.clearIncidentHistory() }
                
                Button("Cancel", role: .cancel) {
                    // .cancel role: SwiftUI dismisses the dialog automatically — no action body needed.
                }
            } message: {
                Text("Removes incident history and resets its counter. Learned decisions, dismissals, suppression rules, trusted processes, cooldowns, quarantine records, and settings stay unchanged.")
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
                
                Button("Cancel", role: .cancel) {
                    // .cancel role: SwiftUI dismisses the dialog automatically — no action body needed.
                }
            }
        }
    }

    private func updateVerdictLearning(_ enabled: Bool) {
        if enabled {
            guard let authorization = xpcClient.requestProtectionModificationAuthorization() else {
                verdictLearningStatus = "Approval was cancelled. Learning remains off."
                return
            }
            engine.setVerdictLearningEnabled(true, authorizationExternalForm: authorization)
            verdictLearningStatus = "Enabled with user approval."
        } else {
            engine.setVerdictLearningEnabled(false)
            verdictLearningStatus = "Learning is off. Existing entries remain available to review or reset."
        }
    }

    private func updateStrictMode(_ enabled: Bool) {
        if !enabled {
            guard let authorization = xpcClient.requestProtectionModificationAuthorization() else {
                strictBlockingStatus = "Approval was cancelled. Strict blocking remains on."
                return
            }
            engine.setStrictModeEnabled(false, authorizationExternalForm: authorization)
            strictBlockingStatus = "Strict blocking is off. Detection remains active."
        } else {
            engine.setStrictModeEnabled(true)
            strictBlockingStatus = "Strict blocking is on for signed high-confidence rules."
        }
    }

    private func updateAutomaticProtectionUpdates(_ enabled: Bool) {
        if !enabled {
            guard let authorization = xpcClient.requestProtectionModificationAuthorization() else {
                protectionUpdateStatus = "Approval was cancelled. Automatic protection updates remain on."
                return
            }
            engine.setAutomaticProtectionUpdatesEnabled(false, authorizationExternalForm: authorization)
        } else {
            engine.setAutomaticProtectionUpdatesEnabled(true)
        }
        xpcClient.configureThreatBundleUpdates(enabled: enabled)
        protectionUpdateStatus = enabled ? "Automatic protection updates are on." : "Automatic protection updates are off."
    }

    private var protectionUpdateSummary: String {
        if let expiry = xpcClient.threatBundleExpiresAt, expiry <= Date() {
            return "Protection updates expired"
        }
        let version = xpcClient.threatBundleInstalledVersion.map { "v\($0)" } ?? "No installed bundle"
        return "\(version) · \(xpcClient.threatBundleLastResult)"
    }

    private func updateBlockingKillSwitch(_ enabled: Bool) {
        if enabled {
            guard let authorization = xpcClient.requestProtectionModificationAuthorization() else {
                strictBlockingStatus = "Approval was cancelled. Blocking remains active."
                return
            }
            engine.setBlockingKillSwitch(true, authorizationExternalForm: authorization)
            strictBlockingStatus = "All blocking is stopped. Detection and reporting remain active."
        } else {
            engine.setBlockingKillSwitch(false)
            strictBlockingStatus = "Blocking has resumed under the current protection policy."
        }
    }

    // MARK: Updates Section

    private var updatesSection: some View {
        Section {
            if updateAvailable {
                LabeledTile(
                    icon: "arrow.down.circle.fill", tint: .blue,
                    title: updateAvailableVersion.isEmpty
                        ? "A Nick update is available"
                        : "Nick \(updateAvailableVersion) is available",
                    subtitle: "Open the updater to review and install it."
                ) {
                    Button("View Update") {
                        _ = (NSApp.delegate as? AppDelegate)?.checkForUpdates()
                    }
                    .controlSize(.small)
                }
            }
            LabeledTile(
                icon: "arrow.down.circle.fill", tint: .blue,
                title: "Automatically check for updates",
                subtitle: "Nick will check for new versions periodically."
            ) {
                Toggle("", isOn: $autoCheckUpdates)
                    .toggleStyle(.switch)
                    .labelsHidden()
            }
            LabeledTile(
                icon: "network", tint: .indigo,
                title: "Check for Updates Now",
                subtitle: "Fetch the latest available version from the server."
            ) {
                Button("Check Now") {
                    updateCheckStatus = "Checking for updates…"
                    if (NSApp.delegate as? AppDelegate)?.checkForUpdates() != true {
                        updateCheckStatus = "Update service is not ready. Please try again."
                    }
                }
                .controlSize(.small)
            }
            if updateLastCheckTime > 0 {
                Text("Last checked \(Date(timeIntervalSince1970: updateLastCheckTime).formatted(date: .abbreviated, time: .shortened)): \(updateLastCheckResult)")
                    .font(.system(size: 11.5))
                    .foregroundStyle(.secondary)
            }
        } header: {
            Text("Updates")
        } footer: {
            if let updateCheckStatus {
                Text(updateCheckStatus)
                    .font(.system(size: 11.5, weight: .medium))
                    .foregroundStyle(.secondary)
            }
        }
        .onReceive(NotificationCenter.default.publisher(for: .nickUpdateCheckStatus)) { note in
            guard let status = note.object as? String else { return }
            updateCheckStatus = status
        }
    }

    private var aboutAppSection: some View {
        Section {
            LabeledTile(
                icon: "checkmark.shield.fill", tint: .green,
                title: "Nick",
                subtitle: "Version \(appVersion) · Build \(appBuild) · AGPL-3.0"
            ) {
                Link("Open Source on GitHub", destination: URL(string: "https://github.com/EhsanAzish80/Nick")!)
                    .controlSize(.small)
            }
        }
    }

    private var updateDiagnosticsSection: some View {
        Section("Update diagnostics") {
            LabeledTile(
                icon: "clock.arrow.circlepath", tint: .blue,
                title: "Last check",
                subtitle: updateLastCheckTime > 0
                    ? "\(Date(timeIntervalSince1970: updateLastCheckTime).formatted(date: .abbreviated, time: .shortened)) · \(updateLastCheckResult)"
                    : "Never checked"
            ) {
                Button("Copy Update Diagnostics") {
                    let version = "\(appVersion) (\(appBuild))"
                    let checked = updateLastCheckTime > 0
                        ? Date(timeIntervalSince1970: updateLastCheckTime).formatted(.iso8601)
                        : "never"
                    let text = "Nick \(version)\nFeed: \(updateFeedURL)\nLast check: \(checked)\nResult: \(updateLastCheckResult)\nUpdate available: \(updateAvailable)"
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(text, forType: .string)
                }
                .controlSize(.small)
            }
            if interfaceMode == .advanced {
                LabeledTile(
                    icon: "network", tint: .indigo,
                    title: "Update feed",
                    subtitle: updateFeedURL
                ) { EmptyView() }
            }
        }
    }

    private var maintenanceSection: some View {
        Section {
            LabeledTile(
                icon: "trash.slash.fill", tint: .red,
                title: "Uninstall Nick",
                subtitle: "Removes Nick, its protection components, quarantine, history, settings, and all data."
            ) {
                Button("Open Uninstaller…", role: .destructive) {
                    openUninstaller()
                }
                .controlSize(.small)
            }

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
                
                Button("Cancel", role: .cancel) {
                    // .cancel role: SwiftUI dismisses the dialog automatically — no action body needed.
                }
            }
        } header: {
            Text("Maintenance")
        } footer: {
            Text("Nick's monitoring capabilities will be reduced until the helper is reinstalled at next launch.")
                .font(.system(size: 11.5))
                .foregroundStyle(.secondary)
        }
    }

    private var acknowledgementsSection: some View {
        Section("About") {
            LabeledTile(
                icon: "doc.text.fill", tint: .gray,
                title: "Acknowledgements",
                subtitle: "Open-source software and detection-data licences included with Nick."
            ) {
                Button("View…") { showsAcknowledgements = true }
                    .controlSize(.small)
            }
        }
    }

    // MARK: Footer

    private var appVersion: String {
        Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "Unknown"
    }

    private var appBuild: String {
        Bundle.main.object(forInfoDictionaryKey: kCFBundleVersionKey as String) as? String ?? "Unknown"
    }

    private var updateFeedURL: String {
#if DEBUG
        if let value = Bundle.main.object(forInfoDictionaryKey: "NickDebugUpdateFeedURL") as? String,
           !value.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            return value
        }
#endif
        return Bundle.main.object(forInfoDictionaryKey: "SUFeedURL") as? String ?? "Unknown"
    }

    private var footer: some View {
        HStack(spacing: 4) {
            Text("Nick · Version \(appVersion) · Build \(appBuild) · ")
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

    private func openUninstaller() {
        let url = Bundle.main.bundleURL
            .appendingPathComponent("Contents/Applications/Nick Uninstaller.app", isDirectory: true)
        guard FileManager.default.fileExists(atPath: url.path) else { return }
        NSWorkspace.shared.openApplication(
            at: url,
            configuration: NSWorkspace.OpenConfiguration()
        )
    }

    private func removeHelper() {
        Task {
            try? await SMAppService.daemon(plistName: "com.ehsanazish.nick.helper.plist").unregister()
        }
    }

    private func authorizeAndAddProcess() {
        let trimmed = newProcessName.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty else { return }
        let matches = engine.processes.filter {
            $0.name.caseInsensitiveCompare(trimmed) == .orderedSame
                && SigningIdentity(status: $0.signingStatus) != nil
        }
        let identities = Set(matches.compactMap { SigningIdentity(status: $0.signingStatus) })
        guard identities.count == 1, let process = matches.first else {
            trustedProcessStatus = identities.isEmpty
                ? "Run the signed app first and wait for its signature check to finish."
                : "More than one signing identity uses that name. Enter a more specific running process name."
            return
        }
        if let reason = TrustedProcessList.trustRejectionReason(for: process) {
            trustedProcessStatus = reason
            return
        }
        guard let authorization = xpcClient.requestProtectionModificationAuthorization() else {
            trustedProcessStatus = "Approval was cancelled. Settings were not changed."
            return
        }
        engine.authorizeNextSecuritySettingsWrite(with: authorization)
        @Bindable var bindableEngine = engine
        guard bindableEngine.trustedProcessList.addUserTrusted(process) else {
            trustedProcessStatus = "Nick could not approve this process."
            return
        }
        trustedProcessStatus = "Trusted \(process.name) by its verified signing identity."
        newProcessName = ""
    }

    private func reapproveLegacyProcess(_ name: String) {
        newProcessName = name
        authorizeAndAddProcess()
    }

    private func addAllowedDomain() {
        let value = newAllowedDomain
        Task {
            if await networkProtection.allowDomain(value) {
                newAllowedDomain = ""
            }
        }
    }

    private func addAllowedApp() {
        let value = newAllowedApp
        Task {
            if await networkProtection.allowApp(value) {
                newAllowedApp = ""
            }
        }
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

    private var isValidWebhookURL: Bool {
        guard !webhookURLString.isEmpty,
              let url = URL(string: webhookURLString) else { return false }
        return WebhookURLPolicy.permits(url, allowInsecureLocalhost: allowInsecureLocalWebhook)
    }

    private var webhookUsesRejectedHTTP: Bool {
        guard let url = URL(string: webhookURLString),
              url.scheme?.lowercased() == "http" else { return false }
        return !WebhookURLPolicy.permits(url, allowInsecureLocalhost: allowInsecureLocalWebhook)
    }

    private func saveWebhookURL() {
        let trimmed = webhookURLString.trimmingCharacters(in: .whitespaces)
        if trimmed.isEmpty {
            engine.webhookURLString = nil
        } else if let url = URL(string: trimmed),
                  WebhookURLPolicy.permits(url, allowInsecureLocalhost: allowInsecureLocalWebhook) {
            engine.webhookURLString = trimmed
        } else {
            engine.webhookURLString = nil
        }
    }

    private func sendTestWebhook(to url: URL) async {
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        let payload: [String: Any] = [
            "event": "Nick test alert",
            "severity": "info",
            "source": "Nick Security",
            "time": Date().timeIntervalSince1970
        ]
        request.httpBody = try? JSONSerialization.data(withJSONObject: payload)
        do {
            let (_, response) = try await URLSession.shared.data(for: request)
            let code = (response as? HTTPURLResponse)?.statusCode ?? 0
            webhookTestStatus = (200...299).contains(code) ? "Sent" : "Failed"
        } catch {
            webhookTestStatus = "Failed"
        }
        try? await Task.sleep(for: .seconds(3))
        webhookTestStatus = nil
    }

    private func exportTelemetryData() {
        guard let data = SignalTelemetry.shared.exportData() else { return }
        let panel = NSSavePanel()
        panel.title = "Export Training Data"
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd"
        panel.nameFieldStringValue = "nick-telemetry-\(formatter.string(from: Date())).jsonl"
        panel.canCreateDirectories = true
        guard panel.runModal() == .OK, let url = panel.url else { return }
        try? data.write(to: url, options: .atomic)
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

    private func refreshLaunchAtLogin() {
        launchAtLogin = SMAppService.mainApp.status == .enabled
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

private struct SettingsHeader: View {
    let tab: SettingsTab
    let mode: InterfaceMode
    @Binding var searchText: String

    var body: some View {
        HStack(spacing: 18) {
            VStack(alignment: .leading, spacing: 3) {
                Text("Settings")
                    .font(.system(size: 22, weight: .bold))
                Text(tab.subtitle)
                    .font(.system(size: 12.5))
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
            Spacer(minLength: 16)
            if mode == .advanced {
                HStack(spacing: 7) {
                    Image(systemName: "magnifyingglass").foregroundStyle(.secondary)
                    TextField("Search settings", text: $searchText)
                        .textFieldStyle(.plain)
                        .onExitCommand { searchText = "" }
                }
                .padding(.horizontal, 10)
                .frame(width: 220, height: 30)
                .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 7))
                .overlay(RoundedRectangle(cornerRadius: 7).stroke(.separator.opacity(0.6)))
            } else {
                Text("Simple view")
                    .font(.system(size: 11.5, weight: .medium))
                    .foregroundStyle(.secondary)
                    .padding(.horizontal, 9)
                    .padding(.vertical, 5)
                    .background(.secondary.opacity(0.10), in: Capsule())
            }
        }
        .padding(.horizontal, 28)
        .padding(.vertical, 16)
        .background(Color(nsColor: .controlBackgroundColor).opacity(0.55))
        .overlay(alignment: .bottom) { Divider() }
    }
}

private struct ViewModeChooser: View {
    @Binding var selection: InterfaceMode

    var body: some View {
        HStack(spacing: 12) {
            choice(
                .simple,
                icon: "checkmark.shield.fill",
                name: "Simple",
                badge: "Recommended",
                detail: "The essentials, with alerts explained in plain words."
            )
            choice(
                .advanced,
                icon: "slider.horizontal.3",
                name: "Advanced",
                badge: "⇧⌘A",
                detail: "Processes, network, persistence, rule details, diagnostics and every technical setting."
            )
        }
    }

    private func choice(
        _ mode: InterfaceMode,
        icon: String,
        name: String,
        badge: String,
        detail: String
    ) -> some View {
        Button { selection = mode } label: {
            VStack(alignment: .leading, spacing: 9) {
                Image(systemName: icon)
                    .font(.system(size: 26))
                    .foregroundStyle(selection == mode ? Color.accentColor : Color.secondary)
                    .frame(maxWidth: .infinity, minHeight: 48)
                    .background(.secondary.opacity(0.08), in: RoundedRectangle(cornerRadius: 9))
                HStack {
                    Image(systemName: selection == mode ? "largecircle.fill.circle" : "circle")
                        .foregroundStyle(selection == mode ? Color.accentColor : Color.secondary)
                    Text(name).font(.system(size: 14, weight: .semibold))
                    Spacer()
                    Text(badge)
                        .font(.system(size: 10.5, weight: .medium))
                        .foregroundStyle(.secondary)
                        .padding(.horizontal, 6)
                        .padding(.vertical, 3)
                        .background(.secondary.opacity(0.10), in: Capsule())
                }
                Text(detail)
                    .font(.system(size: 11.5))
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.leading)
                    .lineLimit(2)
            }
            .padding(14)
            .frame(maxWidth: .infinity, minHeight: 142, alignment: .topLeading)
            .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 12))
            .overlay {
                RoundedRectangle(cornerRadius: 12)
                    .stroke(selection == mode ? Color.accentColor : Color.secondary.opacity(0.25),
                            lineWidth: selection == mode ? 2 : 1)
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityLabel("\(name) view")
        .accessibilityAddTraits(selection == mode ? .isSelected : [])
    }
}

private struct SettingsTabBar: View {
    let tabs: [SettingsTab]
    @Binding var selection: SettingsTab

    var body: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 3) {
                ForEach(tabs) { tab in
                    Button { selection = tab } label: {
                        VStack(spacing: 3) {
                            Image(systemName: tab.icon).font(.system(size: 18))
                            Text(tab.title).font(.system(size: 11.5, weight: selection == tab ? .semibold : .regular))
                        }
                        .foregroundStyle(selection == tab ? Color.accentColor : Color.secondary)
                        .frame(minWidth: 72)
                        .padding(.horizontal, 10)
                        .padding(.vertical, 7)
                        .background(selection == tab ? Color.accentColor.opacity(0.10) : .clear,
                                    in: RoundedRectangle(cornerRadius: 8))
                        .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                    .accessibilityAddTraits(selection == tab ? .isSelected : [])
                }
            }
            .padding(.horizontal, 18)
            .padding(.vertical, 8)
        }
        .frame(maxWidth: .infinity)
    }
}

private struct AcknowledgementsView: View {
    @Environment(\.dismiss) private var dismiss

    private var esetNotice: String {
        guard let url = Bundle.main.url(
            forResource: "eset",
            withExtension: "txt",
            subdirectory: "Rules/families/LICENSES"
        ), let text = try? String(contentsOf: url, encoding: .utf8) else {
            return "The bundled ESET BSD-2-Clause notice is unavailable in this build."
        }
        return text
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack {
                Text("Acknowledgements").font(.title2.weight(.semibold))
                Spacer()
                Button("Done") { dismiss() }.keyboardShortcut(.defaultAction)
            }
            Text("ESET malware-ioc data")
                .font(.headline)
            Text("Nick includes a small, pinned set of macOS SHA-256 indicators from ESET's malware-ioc repository under the BSD-2-Clause licence.")
                .foregroundStyle(.secondary)
            ScrollView {
                Text(esetNotice)
                    .font(.system(.caption, design: .monospaced))
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
            .padding(12)
            .background(.background.secondary, in: RoundedRectangle(cornerRadius: 8))
        }
        .padding(24)
        .frame(minWidth: 640, minHeight: 520)
    }
}

private struct LearnedReviewEntriesView: View {
    @Environment(SecurityEngine.self) private var engine
    @Environment(\.dismiss) private var dismiss
    @State private var entries: [LearnedReviewEntry] = []
    @State private var confirmsResetAll = false

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack {
                VStack(alignment: .leading, spacing: 3) {
                    Text("What Nick learned").font(.title2.weight(.semibold))
                    Text("Local review decisions only. Entries lower priority; they never hide detections.")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                Button("Done") { dismiss() }.keyboardShortcut(.defaultAction)
            }

            if entries.isEmpty {
                ContentUnavailableView(
                    "Nothing learned yet",
                    systemImage: "brain.head.profile",
                    description: Text("When learning is enabled, authenticated false-positive decisions can create expiring review-only entries.")
                )
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                List(entries) { entry in
                    VStack(alignment: .leading, spacing: 5) {
                        HStack {
                            Text(entry.ruleID).font(.headline)
                            Spacer()
                            Button("Reset", role: .destructive) {
                                engine.resetLearnedEntry(id: entry.id)
                                refresh()
                            }
                            .controlSize(.small)
                        }
                        Text("\(entry.teamID) · \(entry.signingIdentifier)")
                            .font(.caption.monospaced())
                            .textSelection(.enabled)
                        Text(entry.reason).font(.callout)
                        Text("Context: \(entry.contextKey)")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                        Text(entry.confirmationCount < 2
                             ? "Pending (\(entry.confirmationCount)/2) · expires \(entry.expiresAt.formatted(date: .abbreviated, time: .shortened))"
                             : "Active · confirmed \(entry.confirmationCount) times · expires \(entry.expiresAt.formatted(date: .abbreviated, time: .shortened))")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    .padding(.vertical, 4)
                }
            }

            HStack {
                Button("Export…") { exportEntries() }
                    .disabled(entries.isEmpty)
                Button("Reset learned decisions…", role: .destructive) { confirmsResetAll = true }
                .disabled(entries.isEmpty)
                Spacer()
                Text("Stored in Nick's root-owned incident store")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
        .padding(24)
        .frame(minWidth: 720, minHeight: 540)
        .onAppear(perform: refresh)
        .alert(
            "Reset learned decisions?",
            isPresented: $confirmsResetAll
        ) {
            Button("Reset Learned Decisions", role: .destructive) {
                engine.resetLearnedDecisions()
                refresh()
            }
            Button("Cancel", role: .cancel) {
                // SwiftUI dismisses an alert for its cancel role.
            }
        } message: {
            Text("Removes learned review entries only. Incident history, dismissals, suppression rules, trusted processes, cooldowns, quarantine records, and settings stay unchanged.")
        }
    }

    private func refresh() {
        entries = engine.learnedReviewEntries
    }

    private func exportEntries() {
        guard let data = try? engine.exportLearnedEntries() else { return }
        let panel = NSSavePanel()
        panel.title = "Export What Nick Learned"
        panel.nameFieldStringValue = "nick-learned-review-entries.json"
        panel.canCreateDirectories = true
        guard panel.runModal() == .OK, let url = panel.url else { return }
        try? data.write(to: url, options: .atomic)
    }
}

private struct LegacyDismissalsView: View {
    @Environment(SecurityEngine.self) private var engine
    @Environment(\.dismiss) private var dismiss
    @State private var entries: [IncidentDismissalTombstone] = []

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack {
                VStack(alignment: .leading, spacing: 3) {
                    Text("Dismissed in Nick 4.x").font(.title2.weight(.semibold))
                    Text("These review-only dismissals were imported during the upgrade. Protected detections are never hidden by them.")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                Button("Done") { dismiss() }.keyboardShortcut(.defaultAction)
            }

            if entries.isEmpty {
                ContentUnavailableView(
                    "No imported dismissals",
                    systemImage: "clock.arrow.circlepath",
                    description: Text("All Nick 4.x dismissals have been reset.")
                )
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                List(entries, id: \.incidentKey) { entry in
                    VStack(alignment: .leading, spacing: 5) {
                        HStack {
                            Text(displayTitle(for: entry)).font(.headline)
                            Spacer()
                            Button("Reset", role: .destructive) {
                                engine.resetLegacyDismissal(incidentKey: entry.incidentKey)
                                refresh()
                            }
                            .controlSize(.small)
                        }
                        Text(entry.alertDeduplicationKey)
                            .font(.caption.monospaced())
                            .foregroundStyle(.secondary)
                            .textSelection(.enabled)
                        Text("Imported \(entry.dismissedAt.formatted(date: .abbreviated, time: .shortened))")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    .padding(.vertical, 4)
                }
            }
        }
        .padding(24)
        .frame(minWidth: 720, minHeight: 480)
        .onAppear(perform: refresh)
    }

    private func refresh() {
        entries = engine.legacyDismissalTombstones
    }

    private func displayTitle(for entry: IncidentDismissalTombstone) -> String {
        let title = entry.alertDeduplicationKey.components(separatedBy: "||").first ?? "Imported dismissal"
        return title.isEmpty ? "Imported dismissal" : title.localizedCapitalized
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
        .environment(NetworkProtectionManager())
        .frame(width: 760, height: 900)
}
#endif
