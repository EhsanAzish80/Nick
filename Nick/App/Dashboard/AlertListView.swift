// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import SwiftUI

// MARK: - AlertListView

/// Shows all `ThreatAlert` values produced by `ThreatCorrelator`, sorted by
/// score (highest first).
///
/// Each alert is a flat list row (no card background, no shadow). Rows are
/// separated by a `borderSubtle` divider. Copy JSON and Dismiss actions are
/// inline on every row.
///
/// Alerts with `.info` severity represent trusted-app activity and are hidden
/// by default; use the "Show trusted app activity" toggle to reveal them.
struct AlertListView: View {

    @Environment(SecurityEngine.self) private var engine
    @AppStorage("showTrustedAlerts") private var showTrustedAlerts: Bool = false

    private var visibleAlerts: [ThreatAlert] {
        showTrustedAlerts
            ? engine.alerts
            : engine.alerts.filter { $0.severity != .info }
    }

    var body: some View {
        VStack(spacing: 0) {
            if visibleAlerts.isEmpty {
                emptyState
            } else {
                ScrollView {
                    VStack(spacing: 0) {
                        ForEach(visibleAlerts) { alert in
                            AlertRow(alert: alert)
                            if alert.id != visibleAlerts.last?.id {
                                Divider()
                                    .overlay(Color.borderSubtle)
                            }
                        }
                    }
                }
            }
        }
    }

    // MARK: - Empty state

    private var emptyState: some View {
        // Change 3: centered vertically in available space.
        VStack(spacing: NickSpacing.lg) {
            Image(systemName: "bell.slash")
                .font(.system(size: 32))
                .foregroundStyle(Color.textTertiary)
            Text("No alerts")
                .font(.nickSubtitle)
                .foregroundStyle(Color.textPrimary)
            Text(engine.isScanning
                 ? "Scan in progress…"
                 : "No threats detected in the last scan.")
                .font(.nickBodySmall)
                .foregroundStyle(Color.textSecondary)
                .multilineTextAlignment(.center)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Color.backgroundPrimary)
    }
}

// MARK: - AlertRow

/// Flat list row for one `ThreatAlert`. No card background — content only.
///
/// `.info` severity alerts (trusted-app activity) render with `textTertiary`
/// styling to visually distinguish them from actionable alerts.
private struct AlertRow: View {

    let alert: ThreatAlert
    @Environment(SecurityEngine.self) private var engine
    @State private var killingProcess = false
    @State private var killFailed     = false
    @State private var processKilled  = false   // confirmed dead this session
    @State private var deleteFailed   = false

    /// Whether this alert represents trusted-app activity (severity == .info).
    private var isTrustedActivity: Bool { alert.severity == .info }

    var body: some View {
        VStack(alignment: .leading, spacing: NickSpacing.md) {

            // Line 1 — icon + title
            HStack(alignment: .top, spacing: NickSpacing.md) {
                Image(systemName: alert.severity.systemImage)
                    .font(.system(size: NickLayout.iconSizeLarge))
                    .foregroundStyle(isTrustedActivity ? Color.textTertiary : alert.severity.statusColor)
                Text(alert.title)
                    .font(.nickBodyMedium)
                    .foregroundStyle(isTrustedActivity ? Color.textTertiary : Color.textPrimary)
                    .fixedSize(horizontal: false, vertical: true)
            }

            // Line 2 — badge · confidence · timestamp
            HStack(spacing: NickSpacing.xs) {
                SeverityBadge(severity: alert.severity)
                Text("·")
                    .font(.nickCaption)
                    .foregroundStyle(Color.textTertiary)
                Text(String(format: "%.0f%% confidence", alert.score * 100))
                    .font(.nickMono)
                    .foregroundStyle(Color.textSecondary)
                Text("·")
                    .font(.nickCaption)
                    .foregroundStyle(Color.textTertiary)
                Text(alert.timestamp.formatted(date: .omitted, time: .shortened))
                    .font(.nickMonoSmall)
                    .foregroundStyle(Color.textTertiary)
                Spacer()
            }

            // Description — use Foundation Models explanation when available
            Text(alert.explanation ?? alert.description)
                .font(.nickBody)
                .foregroundStyle(isTrustedActivity ? Color.textTertiary : Color.textPrimary)
                .fixedSize(horizontal: false, vertical: true)

            // Contributing signals — flat list, ▸ prefix, 20pt indent
            if !alert.contributingSignals.isEmpty {
                VStack(alignment: .leading, spacing: NickSpacing.sm) {
                    ForEach(alert.contributingSignals.prefix(5)) { signal in
                        HStack(alignment: .top, spacing: NickSpacing.sm) {
                            Text("▸")
                                .font(.nickBodySmall)
                                .foregroundStyle(Color.textTertiary)
                            VStack(alignment: .leading, spacing: 2) {
                                Text(signal.title)
                                    .font(.nickBodySmall)
                                    .foregroundStyle(Color.textSecondary)
                                    .fixedSize(horizontal: false, vertical: true)
                                let displayPath = signal.metadata["script_path"]
                                    ?? signal.metadata["path"]
                                    ?? signal.processInfo?.path
                                if let path = displayPath, !path.isEmpty {
                                    Text(path)
                                        .font(.nickMono)
                                        .foregroundStyle(Color.textTertiary)
                                        .lineLimit(1)
                                        .truncationMode(.middle)
                                }
                                if let pid = signal.processInfo?.pid {
                                    Text("PID \(pid)")
                                        .font(.nickMonoSmall)
                                        .foregroundStyle(Color.textTertiary)
                                }
                            }
                        }
                    }
                    if alert.contributingSignals.count > 5 {
                        Text("+\(alert.contributingSignals.count - 5) more signals")
                            .font(.nickCaption)
                            .foregroundStyle(Color.textTertiary)
                            .padding(.leading, NickSpacing.lg)
                    }
                }
                .padding(.leading, 20)
            }

            // Buttons
            HStack(spacing: NickSpacing.md) {
                // Kill Process — visible while the process is alive (or mid-kill).
                // Hidden once processKilled is set, making room for Delete File.
                if !processKilled,
                   let pid = alert.contributingSignals.first?.processInfo?.pid,
                   killingProcess || ProcessScanner.isRunning(pid: pid) {
                    Button {
                        killingProcess = true
                        killFailed = false
                        Task { @MainActor in
                            // SIGTERM first — polite termination.
                            kill(pid, SIGTERM)
                            try? await Task.sleep(for: .milliseconds(800))
                            if ProcessScanner.isRunning(pid: pid) {
                                // Escalate to SIGKILL if still alive.
                                kill(pid, SIGKILL)
                                try? await Task.sleep(for: .milliseconds(500))
                            }
                            if !ProcessScanner.isRunning(pid: pid) {
                                // Confirmed dead.
                                let fp = alert.contributingSignals.first?.metadata["script_path"]
                                    ?? alert.contributingSignals.first?.processInfo?.path
                                if let p = fp, !p.isEmpty {
                                    // File path known — offer delete before dismissing.
                                    killingProcess = false
                                    processKilled  = true
                                } else {
                                    // No known path — resolve (not suppress) and rescan.
                                    engine.resolveAlert(alert.id)
                                    engine.runFullScan()
                                }
                            } else {
                                killingProcess = false
                                killFailed = true
                            }
                        }
                    } label: {
                        if killingProcess {
                            Label("Terminating…", systemImage: "xmark.circle")
                                .font(.nickButton)
                        } else if killFailed {
                            Label("Kill failed", systemImage: "xmark.octagon")
                                .font(.nickButton)
                        } else {
                            Label("Kill Process", systemImage: "xmark.circle")
                                .font(.nickButton)
                        }
                    }
                    .buttonStyle(.nickDestructive)
                    .disabled(killingProcess)
                }

                // Delete File — replaces Kill button after process is confirmed dead.
                if processKilled {
                    let fp = alert.contributingSignals.first?.metadata["script_path"]
                        ?? alert.contributingSignals.first?.processInfo?.path
                    if let path = fp, !path.isEmpty {
                        Button {
                            do {
                                try FileManager.default.removeItem(atPath: path)
                                engine.resolveAlert(alert.id)
                                engine.runFullScan()
                            } catch {
                                deleteFailed = true
                            }
                        } label: {
                            Label(
                                deleteFailed ? "Delete failed" : "Delete File",
                                systemImage: deleteFailed ? "trash.slash" : "trash"
                            )
                            .font(.nickButton)
                        }
                        .buttonStyle(.nickDestructive)
                    }
                }

                // Show in Finder
                let finderPath = alert.contributingSignals.first?.metadata["script_path"]
                    ?? alert.contributingSignals.first?.processInfo?.path
                if let path = finderPath, !path.isEmpty {
                    Button {
                        NSWorkspace.shared.selectFile(path, inFileViewerRootedAtPath: "")
                    } label: {
                        Label("Show in Finder", systemImage: "folder")
                            .font(.nickButton)
                    }
                    .buttonStyle(.nickSecondary)
                }

                Spacer()
                Button("Copy JSON") { copyJSON() }
                    .buttonStyle(.plain)
                    .font(.nickButton)
                    .foregroundStyle(Color.textSecondary)
                Button("Dismiss") { engine.dismissAlert(alert.id) }
                    .buttonStyle(.nickPrimary)
            }
        }
        .padding(.horizontal, NickSpacing.lg)
        .padding(.vertical, NickSpacing.lg)
    }

    // MARK: - Private

    private func copyJSON() {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        guard let data = try? encoder.encode(alert),
              let string = String(data: data, encoding: .utf8) else { return }
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(string, forType: .string)
    }
}

// MARK: - SeverityBadge (shared)

/// Pill-shaped severity badge using Nick design tokens.
struct SeverityBadge: View {
    let severity: SignalSeverity

    var body: some View {
        Text(severity.displayName.uppercased())
            .font(.nickCaption)
            .foregroundStyle(severity.statusColor)
            .padding(.horizontal, NickSpacing.md)
            .padding(.vertical, NickSpacing.xs)
            .background(severity.statusBackground, in: Capsule())
    }
}

// MARK: - Preview

#Preview {
    AlertListView()
        .environment(SecurityEngine())
        .frame(width: NickLayout.windowWidth, height: 400)
        .background(Color.backgroundPrimary)
}
