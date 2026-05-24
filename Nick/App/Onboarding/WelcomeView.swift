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

                Text("macOS Security Suite")
                    .font(.system(size: 16, weight: .medium))
                    .foregroundStyle(Color.textSecondary)
            }

            Spacer().frame(height: 40)

            // Feature grid — 2 columns
            LazyVGrid(
                columns: [GridItem(.flexible()), GridItem(.flexible())],
                spacing: 20
            ) {
                FeatureCard(icon: "cpu",
                            title: "Process Monitor",
                            description: "Detects unsigned and suspicious executables in real-time")
                FeatureCard(icon: "network",
                            title: "Network Watchdog",
                            description: "Flags unexpected outbound connections and reverse shells")
                FeatureCard(icon: "arrow.triangle.2.circlepath",
                            title: "Persistence Watch",
                            description: "Monitors LaunchAgents and daemons for unauthorized changes")
                FeatureCard(icon: "checkmark.shield",
                            title: "System Audit",
                            description: "Verifies SIP, FileVault, Gatekeeper, and firewall status")
                FeatureCard(icon: "doc.text.magnifyingglass",
                            title: "YARA Scanner",
                            description: "Scans files with industry-standard malware detection rules")
                FeatureCard(icon: "brain",
                            title: "AI Scoring",
                            description: "Correlates signals with on-device Foundation Models")
            }
            .padding(.horizontal, 40)

            Spacer().frame(height: 40)

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
            .tint(Color.statusBlue)

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
