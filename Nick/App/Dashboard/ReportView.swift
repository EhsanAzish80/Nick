// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import SwiftUI
import AppKit

// MARK: - ReportView

/// Phase 6 — Exportable security status report.
///
/// Displays a summary of the current security posture and lets the user save an
/// HTML report to disk. The HTML can be opened in any browser and printed as PDF
/// from there.
struct ReportView: View {

    @Environment(SecurityEngine.self) private var engine
    @Environment(ExtensionXPCClient.self) private var xpcClient
    @Environment(NetworkProtectionManager.self) private var networkProtection

    @State private var isExporting = false
    @State private var exportMessage: String?

    // MARK: - Computed State

    private var healthScore: SystemHealthScore {
        return SystemHealthScore.calculate(
            extensionActive: engine.activePipelineStatus == .running,
            threatsBlocked24h: blockedLast24h,
            quarantineCount: xpcClient.quarantineRecords.count,
            fimViolations: xpcClient.integrityViolations.count,
            networkBlocksCount: networkBlockCount,
            privacyAlerts: xpcClient.privacyAlerts.count
        )
    }

    private var blockedLast24h: Int {
        let cutoff = Date().addingTimeInterval(-86400)
        let endpointBlocks = xpcClient.events.filter {
            $0.decision == .deny && $0.timestamp > cutoff
        }.count
        let networkBlocks = networkProtection.blockEvents.filter {
            $0.decision == .blocked && $0.timestamp > cutoff
        }.count
        return endpointBlocks + networkBlocks
    }

    private var networkBlockCount: Int {
        networkProtection.blockEvents.filter { $0.decision == .blocked }.count
    }

    private var failedChecks: [SystemCheckResult] {
        engine.auditResults.filter { $0.status == .fail }
    }

    // MARK: - Body

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 24) {
                headerSection
                scoreSection
                breakdownSection
                threatsSection
                auditSection
                integritySection
            }
            .padding()
        }
        .navigationTitle("Security Report")
        .navigationSubtitle("Generated \(formattedNow)")
        .toolbar {
            ToolbarItem {
                Button {
                    exportHTML()
                } label: {
                    if isExporting {
                        ProgressView().controlSize(.small)
                    } else {
                        Label("Export HTML", systemImage: "square.and.arrow.up")
                    }
                }
                .disabled(isExporting)
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

    // MARK: - Sections

    private var headerSection: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("Nick Security Report")
                .font(.largeTitle).bold()
            Text(formattedNow)
                .foregroundStyle(.secondary)
        }
    }

    private var scoreSection: some View {
        GroupBox("Overall Security Score") {
            HStack(spacing: 24) {
                // Grade badge
                ZStack {
                    Circle()
                        .fill(gradeColor(healthScore.grade).opacity(0.15))
                        .frame(width: 80, height: 80)
                    VStack(spacing: 0) {
                        Text(healthScore.grade.rawValue)
                            .font(.system(size: 36, weight: .bold))
                            .foregroundStyle(gradeColor(healthScore.grade))
                        Text("\(healthScore.score)/100")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }

                VStack(alignment: .leading, spacing: 6) {
                    Text(healthScore.summary)
                        .font(.headline)
                    Text("Based on real-time protection status, signature freshness, recent threats, file integrity, and privacy alerts.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }

                Spacer()
            }
            .padding(.vertical, 4)
        }
    }

    private var breakdownSection: some View {
        GroupBox("Score Breakdown") {
            VStack(spacing: 8) {
                ForEach(healthScore.breakdown, id: \.name) { component in
                    HStack {
                        Text(component.name)
                            .frame(width: 180, alignment: .leading)
                        ProgressView(value: Double(component.rawScore), total: Double(component.maxScore))
                            .tint(component.rawScore == component.maxScore ? .green : .orange)
                        Text("\(component.rawScore)/\(component.maxScore)")
                            .font(.caption)
                            .frame(width: 50, alignment: .trailing)
                            .foregroundStyle(.secondary)
                    }
                    Text(component.description)
                        .font(.caption2)
                        .foregroundStyle(.tertiary)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(.bottom, 4)
                }
            }
            .padding(.vertical, 4)
        }
    }

    private var threatsSection: some View {
        GroupBox("Recent Threats (\(blockedLast24h) blocked in last 24h)") {
            let threats = xpcClient.events.filter { $0.decision == .deny }.prefix(20)
            if threats.isEmpty {
                Text("No blocked threats.").foregroundStyle(.secondary).frame(maxWidth: .infinity)
            } else {
                VStack(alignment: .leading, spacing: 4) {
                    ForEach(Array(threats)) { event in
                        HStack {
                            Image(systemName: "xmark.circle.fill").foregroundStyle(.red)
                            Text((event.filePath ?? event.processPath).lastPathComponent)
                                .lineLimit(1)
                            Spacer()
                            Text(event.threatName ?? event.eventType.rawValue)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    }
                }
            }
        }
    }

    private var auditSection: some View {
        GroupBox("System Audit (\(failedChecks.count) failing)") {
            if engine.auditResults.isEmpty {
                Text("No audit results. Run a full scan to populate.").foregroundStyle(.secondary)
            } else {
                VStack(alignment: .leading, spacing: 4) {
                    ForEach(engine.auditResults, id: \.id) { check in
                        let nonFailIcon = check.status == .warning ? "exclamationmark.triangle.fill" : "checkmark.circle.fill"
                        let iconName = check.status == .fail ? "xmark.circle.fill" : nonFailIcon
                        let nonFailColor: Color = check.status == .warning ? .orange : .green
                        let statusColor: Color = check.status == .fail ? .red : nonFailColor
                        HStack {
                            Image(systemName: iconName)
                                .foregroundStyle(statusColor)
                            Text(check.check.displayName)
                            Spacer()
                            Text(check.status.rawValue.capitalized)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    }
                }
            }
        }
    }

    private var integritySection: some View {
        GroupBox("File Integrity (\(xpcClient.integrityViolations.count) violation(s))") {
            if xpcClient.integrityViolations.isEmpty {
                Text("No file integrity violations detected.").foregroundStyle(.secondary)
            } else {
                VStack(alignment: .leading, spacing: 4) {
                    ForEach(xpcClient.integrityViolations) { v in
                        HStack {
                            Image(systemName: "exclamationmark.shield.fill").foregroundStyle(.orange)
                            Text(v.path.lastPathComponent).lineLimit(1)
                            Spacer()
                            Text(v.violationType.rawValue).font(.caption).foregroundStyle(.secondary)
                        }
                    }
                }
            }
        }
    }

    // MARK: - Export

    private func exportHTML() {
        let html = buildHTMLReport()
        let panel = NSSavePanel()
        panel.title = "Save Security Report"
        panel.allowedContentTypes = [.html]
        panel.nameFieldStringValue = "NickSecurityReport_\(filenameDateStamp).html"

        panel.begin { response in
            guard response == .OK, let url = panel.url else { return }
            do {
                try html.write(to: url, atomically: true, encoding: .utf8)
                exportMessage = "Report saved to \(url.lastPathComponent)"
            } catch {
                exportMessage = "Export failed: \(error.localizedDescription)"
            }
        }
    }

    // MARK: - HTML Generation

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
                  <td>\(htmlEscape((e.filePath ?? e.processPath).lastPathComponent))</td>
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

    // MARK: - Helpers

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

    private var appVersion: String {
        Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "1.0"
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

    private func gradeColor(_ grade: SystemHealthScore.Grade) -> Color {
        switch grade {
        case .a: .green
        case .b: .blue
        case .c: .yellow
        case .d: .orange
        case .f: .red
        }
    }
}

// MARK: - String Helper

private extension String {
    var lastPathComponent: String { (self as NSString).lastPathComponent }
}

// MARK: - Preview

#Preview {
    ReportView()
        .environment(SecurityEngine())
        .environment(ExtensionXPCClient())
        .environment(NetworkProtectionManager())
        .frame(width: 800, height: 600)
}
