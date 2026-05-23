// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import AppKit
import SwiftUI
import UserNotifications

// MARK: - WelcomeView

/// First-run onboarding screen shown to new users.
///
/// Explains what Nick does, lists the permissions it uses, and lets the user
/// grant notification access before proceeding. Tapping "Get Started" sets
/// `hasCompletedOnboarding` in `UserDefaults` via `@AppStorage`, which causes
/// `MainWindowView` to replace this screen with the main navigation UI.
struct WelcomeView: View {

    @Binding var hasCompletedOnboarding: Bool

    var body: some View {
        VStack(spacing: NickSpacing.xl) {

            // App icon + headline
            VStack(spacing: NickSpacing.md) {
                Image(systemName: "shield.checkered")
                    .font(.system(size: 64, weight: .thin))
                    .foregroundStyle(Color.statusGreen)

                Text("Welcome to Nick")
                    .font(.system(size: 28, weight: .semibold))
                    .foregroundStyle(Color.textPrimary)

                Text("Open-source macOS security monitoring with on-device AI.\nAll analysis runs entirely on your Mac — nothing leaves your machine.")
                    .font(.nickBody)
                    .foregroundStyle(Color.textSecondary)
                    .multilineTextAlignment(.center)
            }

            Divider()

            // What Nick monitors
            VStack(alignment: .leading, spacing: NickSpacing.sm) {
                Text("What Nick monitors")
                    .font(.nickSubtitle)
                    .foregroundStyle(Color.textPrimary)
                    .frame(maxWidth: .infinity, alignment: .leading)

                OnboardingRow(icon: "cpu",                       text: "Processes — detects unsigned or suspicious executables")
                OnboardingRow(icon: "network",                   text: "Network — flags unexpected outbound connections")
                OnboardingRow(icon: "arrow.triangle.2.circlepath", text: "Persistence — watches launch agents and daemons for changes")
                OnboardingRow(icon: "checkmark.shield",          text: "System — audits SIP, firewall, and Gatekeeper status")
                OnboardingRow(icon: "camera",                    text: "Camera & Microphone — alerts if activated unexpectedly")
            }

            Divider()

            // Permissions
            VStack(alignment: .leading, spacing: NickSpacing.sm) {
                Text("Permissions")
                    .font(.nickSubtitle)
                    .foregroundStyle(Color.textPrimary)
                    .frame(maxWidth: .infinity, alignment: .leading)

                PermissionRow(
                    icon: "bell",
                    title: "Notifications",
                    description: "Nick sends alerts when it detects a threat. You can adjust the severity threshold in Settings."
                )

                PermissionRow(
                    icon: "lock.shield",
                    title: "Privileged Helper",
                    description: "Nick installs a small helper tool to read system state (SIP, firewall, launch daemons) that requires administrator approval."
                )
            }

            Spacer()

            // CTA
            Button {
                // Permission is requested by MainWindowView's .task once the main
                // navigation UI is on screen — do not call requestPermission() here.
                hasCompletedOnboarding = true
            } label: {
                Text("Get Started")
                    .font(.nickBodyMedium)
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, NickSpacing.sm)
            }
            .buttonStyle(NickPrimaryButtonStyle())
        }
        .padding(NickSpacing.xxl)
        .frame(maxWidth: 520, maxHeight: .infinity)
        .background(Color.backgroundPrimary)
    }
}

// MARK: - OnboardingRow

private struct OnboardingRow: View {
    let icon: String
    let text: String

    var body: some View {
        HStack(spacing: NickSpacing.md) {
            Image(systemName: icon)
                .frame(width: 20)
                .foregroundStyle(Color.statusGreen)
                .imageScale(.medium)
            Text(text)
                .font(.nickBodySmall)
                .foregroundStyle(Color.textSecondary)
        }
    }
}

// MARK: - PermissionRow

private struct PermissionRow: View {
    let icon:        String
    let title:       String
    let description: String

    var body: some View {
        HStack(alignment: .top, spacing: NickSpacing.md) {
            Image(systemName: icon)
                .frame(width: 20)
                .foregroundStyle(Color.textTertiary)
                .imageScale(.medium)
                .padding(.top, 2)
            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                    .font(.nickBodyMedium)
                    .foregroundStyle(Color.textPrimary)
                Text(description)
                    .font(.nickBodySmall)
                    .foregroundStyle(Color.textSecondary)
            }
        }
    }
}
