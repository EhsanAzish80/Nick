// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import AppKit
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
    @Environment(ExtensionXPCClient.self) private var xpcClient

    @State private var isExporting   = false
    @State private var exportMessage: String?

    // Separate XProtect result from the rest so it gets its own section.
    private var xprotectResult: SystemCheckResult? {
        engine.auditResults.first { $0.check == .xprotect }
    }
    private var securityResults: [SystemCheckResult] {
        engine.auditResults.filter { $0.check != .xprotect }
    }
    private var passCount: Int { engine.auditResults.filter { $0.status == .pass }.count }
    private var issueCount: Int { engine.auditResults.filter { $0.status != .pass && $0.status != .unknown }.count }

    /// Days since last XProtect update — kept for the XProtect definitions display row only.
    private var signatureAgeDays: Int {
        guard let xp = xprotectResult else { return 0 }
        let parts = xp.currentValue.components(separatedBy: " ")
        if parts.count >= 4, parts[0] == "Version" {
            let dStr = parts[3].replacingOccurrences(of: "d", with: "")
            if let days = Int(dStr) { return days }
        }
        return 0
    }

    private var blockedLast24h: Int {
        let cutoff = Date().addingTimeInterval(-86400)
        return xpcClient.events.filter { $0.decision == .deny && $0.timestamp > cutoff }.count
    }

    private var healthScore: SystemHealthScore {
        SystemHealthScore.calculate(
            extensionActive:    engine.activePipelineStatus == .running,
            threatsBlocked24h:  blockedLast24h,
            quarantineCount:    xpcClient.quarantineRecords.count,
            fimViolations:      xpcClient.integrityViolations.count,
            networkBlocksCount: xpcClient.events.filter { $0.decision == .deny && $0.eventType == .authOpen }.count,
            privacyAlerts:      xpcClient.privacyAlerts.count
        )
    }

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

                    // Security Score section
                    scoreSection

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

                        // MARK: - Privacy Monitor section
                        privacySection

                        // MARK: - File Integrity section
                        integritySection
                    }
                }
            }
        }
        .background(Color.backgroundPrimary)
        .navigationTitle("System Audit")
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Button {
                    exportHTML()
                } label: {
                    if isExporting {
                        ProgressView().controlSize(.small)
                    } else {
                        Label("Export Report", systemImage: "square.and.arrow.up")
                    }
                }
                .disabled(isExporting || engine.auditResults.isEmpty)
            }
        }
        .safeAreaInset(edge: .bottom) {
            if let msg = exportMessage {
                HStack {
                    Image(systemName: "checkmark.circle.fill").foregroundStyle(.green)
                    Text(msg).font(.footnote)
                    Spacer()
                    Button("Dismiss") { exportMessage = nil }
                        .buttonStyle(.borderless)
                        .font(.footnote)
                }
                .padding(.horizontal)
                .padding(.vertical, 8)
                .background(.regularMaterial)
            }
        }
    }

    // MARK: - Security Score section

    @ViewBuilder
    private var scoreSection: some View {
        let score = healthScore
        VStack(alignment: .leading, spacing: 8) {
            Text("SECURITY SCORE")
                .font(.system(size: 11, weight: .semibold))
                .foregroundStyle(Color.textTertiary)
                .tracking(0.5)
                .padding(.horizontal, 20)

            VStack(spacing: 0) {
                ForEach(Array(score.breakdown.enumerated()), id: \.offset) { idx, component in
                    if idx > 0 { Divider().padding(.leading, 56) }
                    ScoreComponentRow(component: component)
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
            .padding(.bottom, 16)
        }
    }

    // MARK: - Export

    private func exportHTML() {
        let html = buildHTMLReport()
        let panel = NSSavePanel()
        panel.title = "Save Security Report"
        panel.allowedContentTypes = [.html]
        panel.nameFieldStringValue = "NickSecurityReport_\(filenameDateStamp).html"
        isExporting = true
        panel.begin { response in
            isExporting = false
            guard response == .OK, let url = panel.url else { return }
            do {
                try html.write(to: url, atomically: true, encoding: .utf8)
                exportMessage = "Report saved to \(url.lastPathComponent)"
            } catch {
                exportMessage = "Export failed: \(error.localizedDescription)"
            }
        }
    }

    private func buildHTMLReport() -> String {
        let score = healthScore
        let gradeHex: String
        switch score.grade {
        case .a: gradeHex = "#22c55e"
        case .b: gradeHex = "#3b82f6"
        case .c: gradeHex = "#eab308"
        case .d: gradeHex = "#f97316"
        case .f: gradeHex = "#ef4444"
        }

        let breakdownRows = score.breakdown.map { c in
            """
            <tr>
              <td>\(htmlEscape(c.name))</td>
              <td><progress value="\(c.rawScore)" max="\(c.maxScore)" style="width:120px"></progress></td>
              <td>\(c.rawScore)/\(c.maxScore)</td>
              <td style="color:#666">\(htmlEscape(c.description))</td>
            </tr>
            """
        }.joined()

        let threatRows = xpcClient.events
            .filter { $0.decision == .deny }
            .prefix(50)
            .map { e in
                """
                <tr>
                  <td>\(htmlEscape(dateString(e.timestamp)))</td>
                  <td>\(htmlEscape(((e.filePath ?? e.processPath) as NSString).lastPathComponent))</td>
                  <td>\(htmlEscape(e.threatName ?? "—"))</td>
                  <td>\(htmlEscape(e.eventType.rawValue))</td>
                </tr>
                """
            }.joined()

        let auditRows = engine.auditResults.map { r in
            let nonFailColor = r.status == .warning ? "#f97316" : "#22c55e"
            let color = r.status == .fail ? "#ef4444" : nonFailColor
            return """
            <tr>
              <td>\(htmlEscape(r.check.displayName))</td>
              <td style="color:\(color)">\(r.status.rawValue.capitalized)</td>
            </tr>
            """
        }.joined()

        let appVersion = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "1.0"

        return """
        <!DOCTYPE html>
        <html lang="en">
        <head>
        <meta charset="UTF-8">
        <title>Nick Security Report</title>
        <style>
        body { font-family: -apple-system, sans-serif; max-width: 900px; margin: 40px auto; color: #1a1a1a; }
        h1 { color: #1a1a1a; } h2 { border-bottom: 1px solid #ddd; padding-bottom: 4px; }
        table { width: 100%; border-collapse: collapse; margin-bottom: 24px; }
        th { text-align: left; padding: 6px 8px; background: #f5f5f5; }
        td { padding: 6px 8px; border-bottom: 1px solid #eee; }
        .grade { font-size: 64px; font-weight: 700; color: \(gradeHex); }
        .score { color: #666; }
        </style>
        </head>
        <body>
        <h1>Nick Security Report</h1>
        <p class="score">Generated: \(formattedNow)</p>

        <h2>Overall Score</h2>
        <div class="grade">\(score.grade.rawValue)</div>
        <p><strong>\(score.score)/100</strong> — \(htmlEscape(score.summary))</p>

        <h2>Score Breakdown</h2>
        <table><tr><th>Component</th><th>Progress</th><th>Score</th><th>Detail</th></tr>
        \(breakdownRows)
        </table>

        <h2>Blocked Threats</h2>
        <table><tr><th>Time</th><th>File</th><th>Threat Name</th><th>Event Type</th></tr>
        \(threatRows.isEmpty ? "<tr><td colspan='4'>No blocked threats.</td></tr>" : threatRows)
        </table>

        <h2>System Audit</h2>
        <table><tr><th>Check</th><th>Status</th></tr>
        \(auditRows.isEmpty ? "<tr><td colspan='2'>No audit results. Run a full scan to populate.</td></tr>" : auditRows)
        </table>

        <p style="color:#aaa;font-size:12px">Nick \(appVersion) — \(formattedNow)</p>
        </body>
        </html>
        """
    }

    private var formattedNow: String {
        let f = DateFormatter()
        f.dateStyle = .long
        f.timeStyle = .short
        return f.string(from: Date())
    }

    private var filenameDateStamp: String {
        let f = DateFormatter()
        f.dateFormat = "yyyy-MM-dd"
        return f.string(from: Date())
    }

    private func htmlEscape(_ str: String) -> String {
        str.replacingOccurrences(of: "&", with: "&amp;")
            .replacingOccurrences(of: "<", with: "&lt;")
            .replacingOccurrences(of: ">", with: "&gt;")
    }

    private func dateString(_ date: Date) -> String {
        let f = DateFormatter()
        f.dateStyle = .short
        f.timeStyle = .short
        return f.string(from: date)
    }

    // MARK: - Privacy Monitor section

    private static let compactDateFormatter: DateFormatter = {
        let f = DateFormatter()
        f.dateStyle = .none
        f.timeStyle = .short
        return f
    }()

    @ViewBuilder
    private var privacySection: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("PRIVACY MONITOR")
                .font(.system(size: 11, weight: .semibold))
                .foregroundStyle(Color.textTertiary)
                .tracking(0.5)
                .padding(.horizontal, 20)

            if xpcClient.privacyAlerts.isEmpty {
                Text("No privacy events — no unauthorized permission changes detected.")
                    .font(.system(size: 13))
                    .foregroundStyle(Color.textTertiary)
                    .padding(.horizontal, 20)
                    .padding(.bottom, 16)
            } else {
                VStack(spacing: 0) {
                    ForEach(Array(xpcClient.privacyAlerts.prefix(5).enumerated()), id: \.element.id) { idx, alert in
                        if idx > 0 { Divider().padding(.leading, 44) }
                        HStack(spacing: 10) {
                            Image(systemName: alert.changeType == .revoked ? "xmark.shield" : "checkmark.shield.fill")
                                .font(.system(size: 14))
                                .foregroundStyle(alert.changeType == .revoked ? Color.statusOrange : Color.statusGreen)
                                .frame(width: 28)
                            VStack(alignment: .leading, spacing: 2) {
                                Text("\(alert.appBundleID) → \(alert.service)")
                                    .font(.system(size: 13))
                                    .foregroundStyle(Color.textPrimary)
                                    .lineLimit(1)
                                Text(alert.changeType.rawValue.capitalized)
                                    .font(.system(size: 11))
                                    .foregroundStyle(Color.textSecondary)
                            }
                            Spacer()
                            Text(Self.compactDateFormatter.string(from: alert.timestamp))
                                .font(.system(size: 11, design: .monospaced))
                                .foregroundStyle(Color.textTertiary)
                        }
                        .padding(.horizontal, 16)
                        .padding(.vertical, 8)
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
                .padding(.bottom, 16)
            }
        }
    }

    // MARK: - File Integrity section

    @ViewBuilder
    private var integritySection: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("FILE INTEGRITY")
                .font(.system(size: 11, weight: .semibold))
                .foregroundStyle(Color.textTertiary)
                .tracking(0.5)
                .padding(.horizontal, 20)

            if xpcClient.integrityViolations.isEmpty {
                Text("No integrity violations — all monitored paths are unchanged.")
                    .font(.system(size: 13))
                    .foregroundStyle(Color.textTertiary)
                    .padding(.horizontal, 20)
                    .padding(.bottom, 24)
            } else {
                VStack(spacing: 0) {
                    ForEach(Array(xpcClient.integrityViolations.prefix(5).enumerated()), id: \.element.id) { idx, v in
                        if idx > 0 { Divider().padding(.leading, 44) }
                        let createdOrModifiedIcon = v.violationType == .created ? "plus.circle" : "pencil"
                        let violationIcon = v.violationType == .deleted ? "trash" : createdOrModifiedIcon
                        HStack(spacing: 10) {
                            Image(systemName: violationIcon)
                                .font(.system(size: 14))
                                .foregroundStyle(Color.statusOrange)
                                .frame(width: 28)
                            VStack(alignment: .leading, spacing: 2) {
                                Text(v.path)
                                    .font(.system(size: 13, design: .monospaced))
                                    .foregroundStyle(Color.textPrimary)
                                    .lineLimit(1)
                                    .truncationMode(.middle)
                                Text(v.violationType.rawValue.capitalized)
                                    .font(.system(size: 11))
                                    .foregroundStyle(Color.textSecondary)
                            }
                            Spacer()
                            Text(Self.compactDateFormatter.string(from: v.timestamp))
                                .font(.system(size: 11, design: .monospaced))
                                .foregroundStyle(Color.textTertiary)
                        }
                        .padding(.horizontal, 16)
                        .padding(.vertical, 8)
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
                if days == 0 {
                    lastUpdated = "Today"
                } else if days == 1 {
                    lastUpdated = "Yesterday"
                } else {
                    lastUpdated = "\(days) days ago"
                }
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

// MARK: - ScoreComponentRow

/// Audit-style row for a single `SystemHealthScore.Component`.
/// Matches `AuditResultRow` visually and provides actionable fix links
/// for components that are not at full score.
private struct ScoreComponentRow: View {

    let component: SystemHealthScore.Component

    private var isFull: Bool { component.rawScore == component.maxScore }
    private var isZero: Bool { component.rawScore == 0 }

    private var statusIcon: String {
        if isFull { return "checkmark.circle.fill" }
        if isZero { return "xmark.circle.fill" }
        return "exclamationmark.triangle.fill"
    }

    private var statusColor: Color {
        if isFull { return .statusGreen }
        if isZero { return .statusRed }
        return .statusOrange
    }

    private var scoreLabel: String {
        isFull ? "Good" : "\(component.rawScore)/\(component.maxScore) pts"
    }

    private var fixLink: (label: String, destination: AuditFixDestination)? {
        guard !isFull else { return nil }
        switch component.name {
        case "Real-Time Protection":
            return ("Open Privacy & Security settings",
                    .url("x-apple.systempreferences:com.apple.preference.security"))
        case "Signature Freshness":
            return ("Check for updates in Software Update",
                    .url("x-apple.systempreferences:com.apple.preference.softwareupdate"))
        default:
            return nil
        }
    }

    var body: some View {
        HStack(alignment: .top, spacing: NickSpacing.md) {
            Image(systemName: statusIcon)
                .font(.system(size: NickLayout.iconSize, weight: .medium))
                .foregroundStyle(statusColor)
                .frame(width: NickLayout.iconSizeLarge)
                .padding(.top, 2)

            VStack(alignment: .leading, spacing: NickSpacing.xs) {
                HStack(alignment: .firstTextBaseline) {
                    Text(component.name)
                        .font(.nickBodyMedium)
                        .foregroundStyle(Color.textPrimary)
                    Spacer()
                    Text(scoreLabel)
                        .font(.nickMono)
                        .foregroundStyle(statusColor)
                        .lineLimit(1)
                }
                Text(component.description)
                    .font(.nickBodySmall)
                    .foregroundStyle(Color.textSecondary)
                    .fixedSize(horizontal: false, vertical: true)
                if let fix = fixLink {
                    AuditFixLink(label: fix.label, destination: fix.destination)
                        .padding(.top, NickSpacing.xs)
                }
            }
        }
        .padding(.horizontal, NickSpacing.lg)
        .padding(.vertical, NickSpacing.md)
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

