// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import SwiftUI

// MARK: - SystemAuditView

/// Displays the results of the most recent `SystemAuditor` run as a scrollable
/// list of check rows with pass / fail / warning / unknown indicators.
///
/// Each row shows the check icon, title, current value, description, and
/// any recommendation — all using Nick design tokens for font and color.
/// Non-passing checks include an `AuditFixLink` that opens the relevant
/// System Settings pane or Apple Support page.
struct SystemAuditView: View {

    @Environment(SecurityEngine.self) private var engine

    var body: some View {
        ScrollView {
            VStack(spacing: 0) {
                if engine.auditResults.isEmpty {
                    emptyState
                } else {
                    ForEach(engine.auditResults) { result in
                        AuditResultRow(result: result)
                        Divider()
                            .padding(.leading, NickLayout.separatorInset)
                    }
                }
            }
        }
    }

    // MARK: - Empty State

    private var emptyState: some View {
        VStack(spacing: NickSpacing.lg) {
            Image(systemName: "checkmark.shield")
                .font(.system(size: 32))
                .foregroundStyle(Color.textTertiary)
            Text("No audit data")
                .font(.nickSubtitle)
                .foregroundStyle(Color.textPrimary)
            Text("Run a scan to check your system configuration.")
                .font(.nickBodySmall)
                .foregroundStyle(Color.textSecondary)
                .multilineTextAlignment(.center)
        }
        .padding(NickSpacing.xxl)
    }
}

// MARK: - AuditResultRow

private struct AuditResultRow: View {

    let result: SystemCheckResult

    var body: some View {
        HStack(alignment: .top, spacing: NickSpacing.md) {
            // Status icon
            Image(systemName: result.status.systemImage)
                .font(.system(size: NickLayout.iconSize, weight: .medium))
                .foregroundStyle(statusColor)
                .frame(width: NickLayout.iconSizeLarge)
                .padding(.top, 2)

            VStack(alignment: .leading, spacing: NickSpacing.xs) {
                HStack(alignment: .firstTextBaseline) {
                    Text(result.check.displayName)
                        .font(.nickBodyMedium)
                        .foregroundStyle(Color.textPrimary)
                    Spacer()
                    // Current value in monospace, colored by status
                    Text(result.currentValue)
                        .font(.nickMono)
                        .foregroundStyle(statusColor)
                        .lineLimit(1)
                }
                // Description
                Text(result.description)
                    .font(.nickBodySmall)
                    .foregroundStyle(Color.textSecondary)
                    .lineLimit(2)
                    .fixedSize(horizontal: false, vertical: true)
                // Recommendation (only on fail/warning)
                if let rec = result.recommendation {
                    Text(rec)
                        .font(.nickBodySmall)
                        .foregroundStyle(Color.statusOrange)
                        .fixedSize(horizontal: false, vertical: true)
                }
                // Fix deep link for non-passing checks
                if result.status != .pass, let fix = fixLink(for: result) {
                    AuditFixLink(label: fix.label, destination: fix.destination)
                        .padding(.top, NickSpacing.xs)
                }
            }
        }
        .padding(.horizontal, NickSpacing.lg)
        .padding(.vertical, NickSpacing.md)
    }

    // MARK: - Private

    private var statusColor: Color {
        switch result.status {
        case .pass:    .statusGreen
        case .warning: .statusYellow
        case .fail:    .statusRed
        case .unknown: .textTertiary
        }
    }

    /// Returns the label and URL/command destination for a non-passing check.
    private func fixLink(for result: SystemCheckResult) -> (label: String, destination: AuditFixDestination)? {
        switch result.check {
        case .fileVault:
            return ("Open FileVault settings", .url("x-apple.systempreferences:com.apple.preference.security?FDE"))
        case .firewall:
            return ("Open Firewall settings", .url("x-apple.systempreferences:com.apple.preference.security?Firewall"))
        case .firewallStealth:
            return ("Configure Stealth Mode in Firewall settings", .url("x-apple.systempreferences:com.apple.preference.security?Firewall"))
        case .gatekeeper:
            return ("Copy terminal command to re-enable Gatekeeper", .copyableCommand("sudo spctl --global-enable"))
        case .sip:
            return ("Learn how to re-enable SIP (requires Recovery Mode)", .url("https://support.apple.com/en-us/102149"))
        case .xprotect:
            return ("Check for updates in Software Update", .url("x-apple.systempreferences:com.apple.preference.softwareupdate"))
        case .automaticUpdates:
            return ("Open Software Update settings", .url("x-apple.systempreferences:com.apple.preference.softwareupdate"))
        case .remoteLogin:
            return ("Open Sharing settings to disable Remote Login", .url("x-apple.systempreferences:com.apple.preferences.sharing?Services_RemoteLogin"))
        }
    }
}

// MARK: - AuditFixDestination

/// The action to perform when the user taps an `AuditFixLink`.
private enum AuditFixDestination {
    /// Open a URL (System Settings deep link or web URL).
    case url(String)
    /// Copy a terminal command to the clipboard.
    case copyableCommand(String)
}

// MARK: - AuditFixLink

/// Inline deep-link button shown below the recommendation text in non-passing audit rows.
private struct AuditFixLink: View {

    let label: String
    let destination: AuditFixDestination

    var body: some View {
        Button(action: performAction) {
            HStack(spacing: NickSpacing.xs) {
                Image(systemName: iconName)
                    .font(.nickCaption)
                Text(label)
                    .font(.nickCaption)
            }
            .foregroundStyle(Color.statusBlue)
        }
        .buttonStyle(.plain)
    }

    private var iconName: String {
        switch destination {
        case .url:              return "arrow.up.forward.square"
        case .copyableCommand:  return "doc.on.clipboard"
        }
    }

    private func performAction() {
        switch destination {
        case .url(let urlString):
            guard let url = URL(string: urlString) else { return }
            NSWorkspace.shared.open(url)
        case .copyableCommand(let command):
            NSPasteboard.general.clearContents()
            NSPasteboard.general.setString(command, forType: .string)
        }
    }
}

// MARK: - Preview

#Preview {
    SystemAuditView()
        .environment(SecurityEngine())
        .frame(width: NickLayout.windowWidth)
        .background(Color.backgroundPrimary)
}

