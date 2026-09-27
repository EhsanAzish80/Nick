// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import AppKit
import SwiftUI

// MARK: - WelcomeView

/// First-run onboarding screen shown to new users.
///
/// Presents the Doberman app icon, a 2-column feature grid, and a single CTA
/// that requests notification permission before handing off to the main window.
struct WelcomeView: View {

    @Binding var hasCompletedOnboarding: Bool

    var body: some View {
        VStack(spacing: 0) {
            Spacer()

            // Hero — app icon + name
            VStack(spacing: NickSpacing.lg) {
                Image(nsImage: NSApp.applicationIconImage)
                    .resizable()
                    .frame(width: 96, height: 96)

                Text("Nick")
                    .font(.system(size: 36, weight: .bold))

                Text("Local Mac security, explained clearly")
                    .font(.system(size: 16, weight: .medium))
                    .foregroundStyle(Color.textSecondary)
            }

            Spacer().frame(height: 40)

            // Feature grid — 2 columns. Lead with user outcomes; technical
            // subsystem names remain available in Advanced mode.
            LazyVGrid(
                columns: [GridItem(.flexible()), GridItem(.flexible())],
                spacing: 20
            ) {
                FeatureCard(icon: "checkmark.shield",
                            title: "Check New Apps",
                            description: "Reviews apps and downloads locally before they open")
                FeatureCard(icon: "magnifyingglass",
                            title: "Scan Your Mac",
                            description: "Runs a quick check or a deeper scan whenever you choose")
                FeatureCard(icon: "bell.badge",
                            title: "Explain Alerts",
                            description: "Shows what happened, what Nick did, and what to do next")
                FeatureCard(icon: "checkmark.shield",
                            title: "Verify Mac Settings",
                            description: "Checks important macOS protections and links to each fix")
            }
            .padding(.horizontal, 40)

            Spacer().frame(height: 40)

            // Interface mode — Simple is the default for new installs.
            HStack(alignment: .top, spacing: 10) {
                Image(systemName: "slider.horizontal.3")
                    .foregroundStyle(Color.nickAccent)
                    .accessibilityHidden(true)
                Text("Nick opens in **Simple** view: one clear status and plain-language alerts. Switch to **Advanced** any time from the toolbar or with ⇧⌘A to see processes, network activity and rule details.")
                    .font(.nickBodySmall)
                    .foregroundStyle(Color.textSecondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 12)
            .background(
                RoundedRectangle(cornerRadius: NickLayout.insetCornerRadius, style: .continuous)
                    .fill(Color.nickInset)
            )
            .padding(.horizontal, 60)
            .accessibilityElement(children: .combine)

            Spacer().frame(height: 16)

            // Permissions note — subtle, not alarming
            Text("Nick will ask for notification permission and may request administrator access to install a system monitor.")
                .font(.nickBodySmall)
                .foregroundStyle(Color.textTertiary)
                .multilineTextAlignment(.center)
                .padding(.horizontal, 60)

            Spacer().frame(height: 24)

            // CTA button
            Button(action: {
                Task {
                    await NotificationManager.shared.requestPermission()
                }
                hasCompletedOnboarding = true
                UserDefaults.standard.set(true, forKey: "hasCompletedOnboarding")
            }) {
                Text("Get Started")
                    .font(.system(size: 15, weight: .semibold))
                    .frame(maxWidth: 280)
                    .padding(.vertical, 12)
            }
            .buttonStyle(.borderedProminent)
            .tint(Color.nickAccent)

            Spacer()
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Color.backgroundPrimary)
    }
}

// MARK: - FeatureCard

private struct FeatureCard: View {
    let icon:        String
    let title:       String
    let description: String

    var body: some View {
        HStack(alignment: .top, spacing: NickSpacing.lg) {
            Image(systemName: icon)
                .font(.system(size: 20))
                .foregroundStyle(Color.statusGreen)
                .frame(width: 32, height: 32)

            VStack(alignment: .leading, spacing: NickSpacing.xs) {
                Text(title)
                    .font(.nickBodyMedium)
                Text(description)
                    .font(.nickBodySmall)
                    .foregroundStyle(Color.textSecondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}
