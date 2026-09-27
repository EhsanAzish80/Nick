// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import AppKit
import SwiftUI
import UserNotifications

// MARK: - SimpleProtectionView

/// Simple ▸ Protection: the four protection groups with a one-line
/// explanation each, a switch where Nick has one, "Fix" rows for anything
/// paused, and the Mac security settings in plain words.
struct SimpleProtectionView: View {

    @Environment(SecurityEngine.self) private var engine
    @Environment(ExtensionXPCClient.self) private var xpcClient
    @Environment(NetworkProtectionManager.self) private var networkProtection
    @Environment(\.openURL) private var openURL

    @State private var endpointHealth: [String: Any]?
    @State private var healthLoaded = false
    @State private var settingUpRansomwareWatch = false
    @State private var setupFailed = false

    private var endpointActive: Bool {
        !healthLoaded || EndpointHealth.isProtectionActive(endpointHealth)
    }

    private var cards: [ProtectionCard] {
        ProtectionCard.cards(
            endpointActive: endpointActive,
            networkState: networkProtection.state,
            ransomwareShieldActive: EndpointHealth.isRansomwareShieldActive(endpointHealth)
        )
    }

    private var macSettings: [SimpleMacSetting] {
        SimpleMacSetting.settings(from: engine.auditResults)
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 22) {
                NotificationPermissionRow()

                VStack(alignment: .leading, spacing: 10) {
                    sectionHeader("What Nick protects")
                    VStack(spacing: 0) {
                        ForEach(Array(cards.enumerated()), id: \.element.id) { index, card in
                            if index > 0 { Divider().opacity(0.5).padding(.leading, 70) }
                            groupRow(card)
                        }
                    }
                    .padding(.vertical, 4)
                    .nickSurface()
                }

                VStack(alignment: .leading, spacing: 10) {
                    sectionHeader("Mac security settings")
                    if macSettings.isEmpty {
                        Text("Nick hasn’t checked your Mac’s settings yet. Run a Quick Check from Scan.")
                            .font(.system(size: 13))
                            .foregroundStyle(Color.nickSecondaryText)
                            .padding(18)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .nickSurface()
                    } else {
                        VStack(spacing: 0) {
                            ForEach(Array(macSettings.enumerated()), id: \.element.id) { index, setting in
                                if index > 0 { Divider().opacity(0.5).padding(.leading, 18) }
                                macSettingRow(setting)
                            }
                        }
                        .padding(.vertical, 4)
                        .nickSurface()
                    }
                }
            }
            .padding(.horizontal, 24)
            .padding(.top, 8)
            .padding(.bottom, 28)
            .frame(maxWidth: 900, alignment: .leading)
            .frame(maxWidth: .infinity)
        }
        .background(Color.nickWindow)
        .navigationTitle("Protection")
        .navigationSubtitle(SimpleProtectionCopy.subtitle(for: cards))
        .task { await networkProtection.refresh() }
        .task { await refreshHealth() }
        .alert("Nick couldn’t set up ransomware watch", isPresented: $setupFailed) {
            Button("OK", role: .cancel) {}
        } message: {
            Text("Make sure Nick’s security extension is allowed, then try again.")
        }
    }

    // MARK: Rows

    private func sectionHeader(_ text: String) -> some View {
        Text(text)
            .font(.system(size: 13, weight: .semibold))
            .foregroundStyle(Color.nickSecondaryText)
            .padding(.horizontal, 4)
            .accessibilityAddTraits(.isHeader)
    }

    private func statusColors(_ status: ProtectionCard.Status) -> (Color, Color) {
        switch status {
        case .on:     (.nickAccent, .nickAccentTint)
        case .paused: (.nickWarningText, .nickWarningBackground)
        case .off:    (.nickSecondaryText, .nickNeutralTile)
        }
    }

    private func groupRow(_ card: ProtectionCard) -> some View {
        let colors = statusColors(card.status)
        let fix = ProtectionFix.fix(for: card, networkState: networkProtection.state)

        return VStack(alignment: .leading, spacing: 12) {
            HStack(alignment: .top, spacing: 14) {
                Image(systemName: card.icon)
                    .font(.system(size: 17, weight: .medium))
                    .foregroundStyle(colors.0)
                    .frame(width: 38, height: 38)
                    .background(
                        RoundedRectangle(cornerRadius: NickLayout.iconTileCornerRadius, style: .continuous)
                            .fill(colors.1)
                    )
                    .accessibilityHidden(true)
                VStack(alignment: .leading, spacing: 4) {
                    HStack(spacing: 8) {
                        Text(card.title)
                            .font(.system(size: 14, weight: .semibold))
                        StatusChip(text: card.status.rawValue, textColor: colors.0, fillColor: colors.1)
                    }
                    Text(SimpleProtectionCopy.explanation(for: card.group))
                        .font(.system(size: 12))
                        .foregroundStyle(Color.nickSecondaryText)
                        .fixedSize(horizontal: false, vertical: true)
                }
                .accessibilityElement(children: .combine)
                Spacer(minLength: 8)
                if card.group == .websitesAndEmail {
                    Toggle("Websites & Email", isOn: Binding(
                        get: { networkProtection.isEnabled },
                        set: { enabled in Task { await networkProtection.setEnabled(enabled) } }
                    ))
                    .labelsHidden()
                    .toggleStyle(.switch)
                    .tint(.nickAccent)
                    .disabled(networkProtection.state == .loading)
                    .accessibilityLabel("Websites & Email protection")
                }
            }

            if let fix {
                fixRow(fix)
                    .padding(.leading, 52)
            }
        }
        .padding(.horizontal, 18)
        .padding(.vertical, 14)
    }

    private func fixRow(_ fix: ProtectionFix) -> some View {
        HStack(spacing: 10) {
            Image(systemName: "exclamationmark.triangle.fill")
                .foregroundStyle(Color.nickWarningText)
                .accessibilityHidden(true)
            Text(fix.message)
                .font(.system(size: 12, weight: .medium))
                .foregroundStyle(Color.nickWarningText)
                .fixedSize(horizontal: false, vertical: true)
            Spacer(minLength: 8)
            Button(fix.buttonTitle) { perform(fix.action) }
                .buttonStyle(.bordered)
                .buttonBorderShape(.capsule)
                .disabled(fix.action == .setUpRansomwareWatch && settingUpRansomwareWatch)
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 9)
        .background(
            RoundedRectangle(cornerRadius: NickLayout.insetCornerRadius, style: .continuous)
                .fill(Color.nickWarningBackground)
        )
    }

    private func macSettingRow(_ setting: SimpleMacSetting) -> some View {
        let colors: (Color, Color) = switch setting.state {
        case .ok:          (.nickAccent, .nickAccentTint)
        case .needsFixing: (.nickDangerText, .nickDangerBackground)
        case .check:       (.nickWarningText, .nickWarningBackground)
        case .unknown:     (.nickSecondaryText, .nickNeutralTile)
        }

        return HStack(alignment: .center, spacing: 12) {
            VStack(alignment: .leading, spacing: 2) {
                Text(setting.title)
                    .font(.system(size: 13, weight: .semibold))
                Text(setting.explanation)
                    .font(.system(size: 12))
                    .foregroundStyle(Color.nickSecondaryText)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 8)
            StatusChip(text: setting.state.rawValue, textColor: colors.0, fillColor: colors.1)
            if let fix = setting.fix, let url = fix.url.flatMap(URL.init(string:)) {
                Button(fix.title) { openURL(url) }
                    .buttonStyle(.bordered)
                    .buttonBorderShape(.capsule)
            }
        }
        .padding(.horizontal, 18)
        .padding(.vertical, 11)
        .accessibilityElement(children: .contain)
    }

    // MARK: Actions

    private func perform(_ action: ProtectionFix.Action) {
        switch action {
        case .allowSecurityExtension:
            if let url = URL(string: ProtectionFix.securityExtensionURL) { openURL(url) }
        case .allowWebFilter:
            networkProtection.openNetworkExtensionSettings()
        case .restartWebFilter:
            Task { await networkProtection.setEnabled(true) }
        case .setUpRansomwareWatch:
            settingUpRansomwareWatch = true
            // The XPC reply arrives on the connection's queue, so hop to the main actor.
            xpcClient.requestDeployCanaries { @Sendable success in
                Task { @MainActor in
                    settingUpRansomwareWatch = false
                    if success {
                        endpointHealth = await EndpointHealth.load()
                    } else {
                        setupFailed = true
                    }
                }
            }
        }
    }

    private func refreshHealth() async {
        while !Task.isCancelled {
            endpointHealth = await EndpointHealth.load()
            healthLoaded = true
            try? await Task.sleep(for: .seconds(5))
        }
    }
}

// MARK: - NotificationPermissionRow

/// Amber inset row shown when macOS notifications are turned off for Nick.
/// Replaces the full-width banner in Simple mode.
struct NotificationPermissionRow: View {
    @State private var denied = false
    @Environment(\.openURL) private var openURL

    private static let settingsURL = URL(string: "x-apple.systempreferences:com.apple.Notifications-Settings")!

    var body: some View {
        Group {
            if denied {
                HStack(spacing: 12) {
                    Image(systemName: "bell.slash.fill")
                        .font(.system(size: 15, weight: .medium))
                        .foregroundStyle(Color.nickWarningText)
                        .accessibilityHidden(true)
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Notifications are off")
                            .font(.system(size: 13, weight: .semibold))
                            .foregroundStyle(Color.nickWarningText)
                        Text("Nick can’t tell you about threats until you allow notifications.")
                            .font(.system(size: 12))
                            .foregroundStyle(Color.nickWarningText)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    .accessibilityElement(children: .combine)
                    Spacer(minLength: 8)
                    Button("Turn On") { openURL(Self.settingsURL) }
                        .buttonStyle(.bordered)
                        .buttonBorderShape(.capsule)
                }
                .padding(.horizontal, 16)
                .padding(.vertical, 12)
                .background(
                    RoundedRectangle(cornerRadius: NickLayout.insetCornerRadius, style: .continuous)
                        .fill(Color.nickWarningBackground)
                )
            }
        }
        .task { await refresh() }
        .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in
            Task { await refresh() }
        }
    }

    private func refresh() async {
        let settings = await UNUserNotificationCenter.current().notificationSettings()
        denied = settings.authorizationStatus == .denied
    }
}
