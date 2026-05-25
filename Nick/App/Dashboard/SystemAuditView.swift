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

    // Separate XProtect result from the rest so it gets its own section.
    private var xprotectResult: SystemCheckResult? {
        engine.auditResults.first { $0.check == .xprotect }
    }
    private var securityResults: [SystemCheckResult] {
        engine.auditResults.filter { $0.check != .xprotect }
    }
    private var passCount: Int { engine.auditResults.filter { $0.status == .pass }.count }
    private var issueCount: Int { engine.auditResults.filter { $0.status != .pass && $0.status != .unknown }.count }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 0) {
                if engine.auditResults.isEmpty {
                    emptyState
                } else {
                    // Hero row
                    HStack(spacing: 14) {
                        IconTile(
                            systemImage: issueCount > 0 ? "exclamationmark.shield.fill" : "checkmark.shield.fill",
                            tint: issueCount > 0 ? .orange : .green,
                            size: 56
                        )
                        VStack(alignment: .leading, spacing: 4) {
                            Text("System Audit")
                                .font(.system(size: 18, weight: .semibold))
                                .foregroundStyle(Color.textPrimary)
                            Text(heroSubtitle)
                                .font(.system(size: 13))
                                .foregroundStyle(Color.textSecondary)
                        }
                        Spacer()
                    }
                    .padding(.horizontal, 20)
                    .padding(.top, 20)
                    .padding(.bottom, 16)

                    // Security Settings section
                    VStack(alignment: .leading, spacing: 8) {
                        Text("SECURITY SETTINGS")
                            .font(.system(size: 11, weight: .semibold))
                            .foregroundStyle(Color.textTertiary)
                            .tracking(0.5)
                            .padding(.horizontal, 20)

                        VStack(spacing: 0) {
                            ForEach(Array(securityResults.enumerated()), id: \.offset) { idx, result in
                                if idx > 0 { Divider().padding(.leading, 56) }
                                if result.check == .firewall {
                                    FirewallAuditRow(result: result, allowlist: engine.firewallAllowlist)
                                } else {
                                    AuditResultRow(result: result)
                                }
                            }
                        }
                        .background(
                            RoundedRectangle(cornerRadius: 10, style: .continuous)
                                .fill(Color.backgroundSecondary)
                        )
                        .overlay(
                            RoundedRectangle(cornerRadius: 10, style: .continuous)
                                .strokeBorder(Color.borderSubtle, lineWidth: 0.5)
                        )
                        .padding(.horizontal, 20)
                        .padding(.bottom, 20)
                    }

                    // XProtect Definitions section
                    if let xp = xprotectResult {
                        VStack(alignment: .leading, spacing: 8) {
                            Text("XPROTECT DEFINITIONS")
                                .font(.system(size: 11, weight: .semibold))
                                .foregroundStyle(Color.textTertiary)
                                .tracking(0.5)
                                .padding(.horizontal, 20)

                            VStack(spacing: 0) {
                                ForEach(Array(xprotectRows(from: xp).enumerated()), id: \.offset) { idx, row in
                                    if idx > 0 { Divider().padding(.leading, 20) }
                                    HStack {
                                        Text(row.label)
                                            .font(.system(size: 13))
                                            .foregroundStyle(Color.textPrimary)
                                        Spacer()
                                        Text(row.value)
                                            .font(.system(size: 13))
                                            .foregroundStyle(
                                                xp.status == .warning && row.label == "Last updated"
                                                    ? Color.statusOrange
                                                    : Color.textSecondary
                                            )
                                    }
                                    .padding(.horizontal, 16)
                                    .padding(.vertical, 10)
                                }
                            }
                            .background(
                                RoundedRectangle(cornerRadius: 10, style: .continuous)
                                    .fill(Color.backgroundSecondary)
                            )
                            .overlay(
                                RoundedRectangle(cornerRadius: 10, style: .continuous)
                                    .strokeBorder(Color.borderSubtle, lineWidth: 0.5)
                            )
                            .padding(.horizontal, 20)
                            .padding(.bottom, 24)
                        }
                    }
                }
            }
        }
        .background(Color.backgroundPrimary)
        .navigationTitle("System Audit")
    }

    // MARK: - Helpers

    private var heroSubtitle: String {
        guard !engine.auditResults.isEmpty else { return "Run a scan to check your system." }
        if issueCount == 0 {
            return "\(passCount) settings verified. All hardened."
        } else {
            return "\(passCount) settings verified · \(issueCount) issue\(issueCount == 1 ? "" : "s") found."
        }
    }

    private func xprotectRows(from result: SystemCheckResult) -> [(label: String, value: String)] {
        // currentValue format: "Version 5345 (updated 9d ago)" or "Unreadable"
        let parts = result.currentValue.components(separatedBy: " ")
        var version = result.currentValue
        var lastUpdated = "—"
        if parts.count >= 4, parts[0] == "Version" {
            version = parts[1]
            let dStr = parts[3].replacingOccurrences(of: "d", with: "")
            if let days = Int(dStr) {
                lastUpdated = days == 0 ? "Today" : days == 1 ? "Yesterday" : "\(days) days ago"
            }
        }
        return [
            ("Definition version", version),
            ("Last updated", lastUpdated),
            ("Provider", "Apple")
        ]
    }

    // MARK: - Empty State

    private var emptyState: some View {
        VStack(spacing: 16) {
            Spacer(minLength: 40)
            IconTile(systemImage: "checkmark.shield", tint: .green, size: 56)
            VStack(spacing: 6) {
                Text("No audit data")
                    .font(.system(size: 17, weight: .semibold))
                    .foregroundStyle(Color.textPrimary)
                Text("Run a scan to verify your system configuration.")
                    .font(.system(size: 13))
                    .foregroundStyle(Color.textSecondary)
                    .multilineTextAlignment(.center)
            }
            Spacer(minLength: 40)
        }
        .frame(maxWidth: .infinity)
        .padding()
    }
}

// MARK: - FirewallAuditRow

/// Extended audit row for the Application Firewall check.
///
/// Displays the standard pass/fail header and description, then appends a
/// sub-section listing any allowlisted apps with issues. Flagged entries do
/// not affect the issue count or health score — they are recommendations only.
private struct FirewallAuditRow: View {

    let result:    SystemCheckResult
    let allowlist: FirewallAllowlistResult?

    var body: some View {
        HStack(alignment: .top, spacing: NickSpacing.md) {
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
                    Text(result.currentValue)
                        .font(.nickMono)
                        .foregroundStyle(statusColor)
                        .lineLimit(1)
                }
                Text(result.description)
                    .font(.nickBodySmall)
                    .foregroundStyle(Color.textSecondary)
                    .fixedSize(horizontal: false, vertical: true)

                if let allowlist {
                    allowlistSection(allowlist)
                        .padding(.top, NickSpacing.sm)
                }

                AuditFixLink(
                    label: "Open Firewall settings",
                    destination: .url("x-apple.systempreferences:com.apple.NetworkFirewall-Settings.extension")
                )
                .padding(.top, NickSpacing.xs)
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

    @ViewBuilder
    private func allowlistSection(_ allowlist: FirewallAllowlistResult) -> some View {
        if allowlist.flagged.isEmpty {
            HStack(spacing: NickSpacing.sm) {
                Image(systemName: "checkmark.circle.fill")
                    .font(.system(size: 11, weight: .medium))
                    .foregroundStyle(Color.statusGreen)
                Text("All \(allowlist.entries.count) allowed apps verified")
                    .font(.nickBodySmall)
                    .foregroundStyle(Color.textSecondary)
            }
        } else {
            VStack(alignment: .leading, spacing: NickSpacing.xs) {
                HStack(spacing: NickSpacing.sm) {
                    Image(systemName: "exclamationmark.triangle.fill")
                        .font(.system(size: 11, weight: .medium))
                        .foregroundStyle(Color.statusYellow)
                    Text("\(allowlist.flagged.count) firewall rule\(allowlist.flagged.count == 1 ? "" : "s") need attention")
                        .font(.nickBodySmall)
                        .foregroundStyle(Color.textSecondary)
                }
                ForEach(allowlist.flagged) { entry in
                    HStack(alignment: .top, spacing: NickSpacing.xs) {
                        Text("▸")
                            .font(.nickBodySmall)
                            .foregroundStyle(Color.textTertiary)
                        Text("\(entry.displayName) \u{2014} \(entry.issue!.description)")
                            .font(.nickBodySmall)
                            .foregroundStyle(Color.textSecondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
            }
        }
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
            return ("Open Firewall settings", .url("x-apple.systempreferences:com.apple.NetworkFirewall-Settings.extension"))
        case .firewallStealth:
            return ("Configure Stealth Mode in Firewall settings", .url("x-apple.systempreferences:com.apple.NetworkFirewall-Settings.extension"))
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

