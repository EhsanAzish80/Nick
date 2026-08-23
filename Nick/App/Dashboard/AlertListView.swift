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
    @Environment(ExtensionXPCClient.self) private var xpcClient
    @AppStorage("showTrustedAlerts") private var showTrustedAlerts: Bool = false
    @State private var viewMode = 0
    @State private var timelineFilter: ThreatTimelineView.EventFilter = .all
    @State private var timelineSearch = ""

    private var visibleAlerts: [ThreatAlert] {
        engine.alerts.filter { alert in
            alert.hasActionableEvidence
                && (showTrustedAlerts
                    || UserFacingAlertBuilder.shared.build(from: alert).severity != .safe)
        }
    }

    var body: some View {
        Group {
            if viewMode == 1 {
                ThreatTimelineView(selectedFilter: $timelineFilter, searchText: $timelineSearch)
            } else if visibleAlerts.isEmpty {
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
        .searchable(text: $timelineSearch, placement: .toolbar)
        .navigationTitle(viewMode == 0 ? "Alerts" : "Threat Timeline")
        .toolbar {
            ToolbarItemGroup(placement: .automatic) {
                Picker("View", selection: $viewMode) {
                    Text("Active").tag(0)
                    Text("Timeline").tag(1)
                }
                .pickerStyle(.segmented)

                if viewMode == 1 {
                    Picker("Filter", selection: $timelineFilter) {
                        ForEach(ThreatTimelineView.EventFilter.allCases, id: \.self) {
                            Text($0.rawValue).tag($0)
                        }
                    }
                    .pickerStyle(.segmented)
                }
            }
        }
    }

    // MARK: - Empty state

    private var emptyState: some View {
        VStack(spacing: 10) {
            Image(systemName: "checkmark.shield")
                .font(.title2)
                .foregroundStyle(.secondary)
            Text("No active alerts")
                .font(.title3)
                .foregroundStyle(.secondary)
            Toggle(isOn: $showTrustedAlerts) {
                Text("Show informational activity")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
            .toggleStyle(.checkbox)
            .padding(.top, 4)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
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
    @Environment(ExtensionXPCClient.self) private var xpcClient
    @AppStorage("simpleAlertMode") private var simpleAlertMode: Bool = true
    @State private var killingProcess = false
    @State private var killFailed     = false
    @State private var processKilled  = false   // confirmed dead this session
    @State private var deleteFailed   = false
    @State private var showQuarantineConfirmation = false
    @State private var quarantining = false
    @State private var quarantineError: String?
    @State private var approvalError: String?

    private var userAlert: UserFacingAlert {
        UserFacingAlertBuilder.shared.build(from: alert)
    }

    private var displaySeverity: SignalSeverity {
        guard simpleAlertMode else { return alert.severity }
        switch userAlert.severity {
        case .safe:     return .info
        case .warning:  return .medium
        case .critical: return alert.severity == .critical ? .critical : .high
        }
    }

    /// Whether the consumer assessment says no immediate action is required.
    private var isTrustedActivity: Bool { displaySeverity == .info }

    private var isCaptureAlert: Bool {
        alert.contributingSignals.contains { $0.source == .avCapture }
    }

    private var shouldOfferProcessTermination: Bool {
        userAlert.severity == .critical && !isCaptureAlert
    }

    private var detectedFilePath: String? { alert.detectedFilePath }

    private var evidenceState: AlertEvidenceState { alert.evidenceState() }

    private var fileIsAvailable: Bool {
        if case .fileAvailable = evidenceState { return true }
        return false
    }

    private var attributionSummary: String? {
        guard let process = alert.contributingSignals.compactMap(\.processInfo).first else {
            return nil
        }
        let child = process.name.isEmpty ? "this process" : process.name
        if let parent = process.parentName, !parent.isEmpty, parent != "unknown" {
            return "Origin: \(parent) started \(child)."
        }
        if process.parentPID > 0 {
            return "Origin: \(child) was started by process \(process.parentPID); macOS did not provide its name."
        }
        return "Origin: Nick could not determine which app started \(child)."
    }

    private var detectionRule: String? {
        for signal in alert.contributingSignals {
            if let rule = signal.metadata["rule"] ?? signal.metadata["yaraRules"],
               !rule.isEmpty {
                return rule
            }
        }
        return nil
    }

    private var isMalwareDetection: Bool {
        userAlert.actions.contains(.quarantine)
    }

    private var isHeuristicDetection: Bool {
        alert.contributingSignals.contains { $0.source == .yara }
    }

    private var reviewProcessName: String? {
        alert.contributingSignals.compactMap(\.processInfo?.name)
            .first(where: { !$0.isEmpty })
    }

    private var hasStableSignedIdentity: Bool {
        alert.contributingSignals.contains { signal in
            guard let process = signal.processInfo,
                  case .signed(let teamID) = process.signingStatus else {
                return false
            }
            return !teamID.isEmpty && !process.path.isEmpty
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: NickSpacing.md) {

            // Line 1 — icon + title
            HStack(alignment: .top, spacing: NickSpacing.md) {
                Image(systemName: displaySeverity.systemImage)
                    .font(.system(size: NickLayout.iconSizeLarge))
                    .foregroundStyle(isTrustedActivity ? Color.textTertiary : displaySeverity.statusColor)
                Text(simpleMode_title)
                    .font(.nickBodyMedium)
                    .foregroundStyle(isTrustedActivity ? Color.textTertiary : Color.textPrimary)
                    .fixedSize(horizontal: false, vertical: true)
            }

            // Line 2 — badge · confidence · timestamp
            HStack(spacing: NickSpacing.xs) {
                if simpleAlertMode {
                    AssessmentBadge(text: userAlert.assessment, severity: displaySeverity)
                } else {
                    SeverityBadge(severity: alert.severity)
                }
                Text("·")
                    .font(.nickCaption)
                    .foregroundStyle(Color.textTertiary)
                if !simpleAlertMode {
                    Text(String(format: "%.0f%% confidence", alert.score * 100))
                        .font(.nickMono)
                        .foregroundStyle(Color.textSecondary)
                    Text("·")
                        .font(.nickCaption)
                        .foregroundStyle(Color.textTertiary)
                }
                Text(alert.timestamp.formatted(date: .omitted, time: .shortened))
                    .font(.nickMonoSmall)
                    .foregroundStyle(Color.textTertiary)
                if alert.occurrenceCount > 1 {
                    Text("·")
                        .font(.nickCaption)
                        .foregroundStyle(Color.textTertiary)
                    Text("Seen \(alert.occurrenceCount) times")
                        .font(.nickCaption)
                        .foregroundStyle(Color.textSecondary)
                }
                Spacer()
            }

            // Description
            Text(simpleMode_explanation)
                .font(.nickBody)
                .foregroundStyle(isTrustedActivity ? Color.textTertiary : Color.textPrimary)
                .fixedSize(horizontal: false, vertical: true)

            if let attributionSummary {
                Label(attributionSummary, systemImage: "point.topleft.down.to.point.bottomright.curvepath")
                    .font(.nickBodySmall)
                    .foregroundStyle(Color.textSecondary)
                    .fixedSize(horizontal: false, vertical: true)
            }

            if isMalwareDetection {
                detectionSummary
            }

            if simpleAlertMode {
                HStack(alignment: .top, spacing: NickSpacing.sm) {
                    Image(systemName: "arrow.right.circle.fill")
                        .foregroundStyle(displaySeverity.statusColor)
                    VStack(alignment: .leading, spacing: 2) {
                        Text("What to do")
                            .font(.nickBodyMedium)
                            .foregroundStyle(Color.textPrimary)
                        Text(userAlert.recommendedAction)
                            .font(.nickBody)
                            .foregroundStyle(Color.textSecondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
            }

            // Contributing signals — only in technical mode
            if !simpleAlertMode, !alert.contributingSignals.isEmpty {
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
                if (!isMalwareDetection || isHeuristicDetection), reviewProcessName != nil {
                    Button("Expected for 24 Hours") {
                        engine.allowAlertOnce(alert.id)
                    }
                    .buttonStyle(.nickSecondary)
                    .help("Mutes only this exact behavior for 24 hours. Different, critical, persistence, and malware activity still alerts.")

                    if hasStableSignedIdentity {
                        Button("Allow This Behavior for 7 Days") {
                            engine.alwaysAllowBehavior(from: alert.id)
                        }
                        .buttonStyle(.nickSecondary)
                        .help("Allows this signed app only for the same behavior for 7 days. New, critical, persistence, and malware activity still alerts.")
                    }
                }

                if isMalwareDetection, fileIsAvailable, let path = detectedFilePath {
                    Button("Allow Once") {
                        xpcClient.requestAllowFileOnce(path: path) { success in
                            if success {
                                engine.allowAlertOnce(alert.id)
                            } else {
                                approvalError = "Real-Time Protection did not accept the approval. The file remains blocked."
                            }
                        }
                    }
                    .buttonStyle(.nickSecondary)
                    .help("Allows only the next access and clears the current cached denial.")

                    if isHeuristicDetection {
                        Button("Block File") {
                            xpcClient.requestBlockReviewedFile(path: path) { success in
                                if success {
                                    engine.hideAlert(alert.id)
                                } else {
                                    approvalError = "Real-Time Protection could not block this reviewed file."
                                }
                            }
                        }
                        .buttonStyle(.nickDestructive)
                        .help("Blocks future access to this reviewed file until its cache entry expires.")
                    }
                }

                if isMalwareDetection, fileIsAvailable, detectedFilePath != nil {
                    Button {
                        showQuarantineConfirmation = true
                    } label: {
                        Label(
                            quarantining ? "Quarantining…" : "Quarantine File",
                            systemImage: "archivebox.fill"
                        )
                        .font(.nickButton)
                    }
                    .buttonStyle(.nickDestructive)
                    .disabled(quarantining)
                }

                // Kill Process — visible while the process is alive (or mid-kill).
                // Hidden once processKilled is set, making room for Delete File.
                if shouldOfferProcessTermination,
                   !processKilled,
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
                let finderPath = detectedFilePath
                    ?? alert.contributingSignals.first?.processInfo?.path
                if let path = finderPath,
                   !path.isEmpty,
                   FileManager.default.fileExists(atPath: path),
                   !simpleAlertMode || !isCaptureAlert {
                    Button {
                        NSWorkspace.shared.selectFile(path, inFileViewerRootedAtPath: "")
                    } label: {
                        Label("Show in Finder", systemImage: "folder")
                            .font(.nickButton)
                    }
                    .buttonStyle(.nickSecondary)
                }

                Spacer()
                if !simpleAlertMode {
                    Button("Copy JSON") { copyJSON() }
                        .buttonStyle(.plain)
                        .font(.nickButton)
                        .foregroundStyle(Color.textSecondary)
                }
                Button(simpleAlertMode ? "Hide This Occurrence" : "Dismiss") {
                    if simpleAlertMode {
                        engine.hideAlert(alert.id)
                    } else {
                        engine.dismissAlert(alert.id)
                    }
                }
                    .buttonStyle(.nickPrimary)
            }
        }
        .padding(.horizontal, NickSpacing.lg)
        .padding(.vertical, NickSpacing.lg)
        .confirmationDialog(
            "Move this file to Quarantine?",
            isPresented: $showQuarantineConfirmation,
            titleVisibility: .visible
        ) {
            Button("Quarantine File", role: .destructive) {
                quarantineDetectedFile()
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            if let path = detectedFilePath {
                Text("Nick will re-scan \(URL(fileURLWithPath: path).lastPathComponent), then isolate it so it cannot run. You can restore it later from Quarantine.")
            }
        }
        .alert(
            "Couldn’t Quarantine File",
            isPresented: Binding(
                get: { quarantineError != nil },
                set: { if !$0 { quarantineError = nil } }
            )
        ) {
            Button("OK") { quarantineError = nil }
        } message: {
            Text(quarantineError ?? "")
        }
        .alert(
            "Couldn’t Allow File",
            isPresented: Binding(
                get: { approvalError != nil },
                set: { if !$0 { approvalError = nil } }
            )
        ) {
            Button("OK") { approvalError = nil }
        } message: {
            Text(approvalError ?? "")
        }
    }

    // MARK: - Private

    private var simpleMode_title: String {
        if simpleAlertMode {
            return userAlert.headline
        }
        return alert.title
    }

    private var simpleMode_explanation: String {
        if simpleAlertMode {
            return userAlert.explanation
        }
        return alert.explanation ?? alert.description
    }

    @ViewBuilder
    private var detectionSummary: some View {
        if let path = detectedFilePath, fileIsAvailable {
            VStack(alignment: .leading, spacing: NickSpacing.xs) {
                Label("Detected file", systemImage: "doc.fill")
                    .font(.nickBodyMedium)
                    .foregroundStyle(Color.textPrimary)
                Text(URL(fileURLWithPath: path).lastPathComponent)
                    .font(.nickBody)
                    .foregroundStyle(Color.textPrimary)
                Text(path)
                    .font(.nickMono)
                    .foregroundStyle(Color.textSecondary)
                    .lineLimit(2)
                    .truncationMode(.middle)
                    .help(path)
                if let detectionRule {
                    Text("Detection: \(detectionRule)")
                        .font(.nickCaption)
                        .foregroundStyle(Color.textSecondary)
                }
                Text("Nick found this while monitoring \(URL(fileURLWithPath: path).deletingLastPathComponent().path). It has not been removed.")
                    .font(.nickCaption)
                    .foregroundStyle(Color.textSecondary)
            }
            .padding(.leading, NickSpacing.lg)
        } else if detectedFilePath != nil {
            Label(
                evidenceState.endedMessage ?? "The detected file is no longer available.",
                systemImage: "checkmark.circle"
            )
            .font(.nickBodySmall)
            .foregroundStyle(Color.textSecondary)
        } else {
            Label(
                "The detector did not provide a usable file location, so Nick cannot safely quarantine this item. Open Details before taking action.",
                systemImage: "exclamationmark.circle"
            )
            .font(.nickBodySmall)
            .foregroundStyle(Color.textSecondary)
        }
    }

    private func quarantineDetectedFile() {
        guard let path = detectedFilePath else { return }
        quarantining = true
        quarantineError = nil
        xpcClient.requestQuarantineFile(
            path: path,
            expectedThreatName: detectionRule ?? "Detected threat"
        ) { success, message in
            quarantining = false
            if success {
                engine.resolveAlert(alert.id)
                engine.runFullScan()
            } else {
                quarantineError = message ?? "Nick could not quarantine the file."
            }
        }
    }

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

private struct AssessmentBadge: View {
    let text: String
    let severity: SignalSeverity

    var body: some View {
        Text(text.uppercased())
            .font(.nickCaption)
            .foregroundStyle(severity.statusColor)
            .padding(.horizontal, NickSpacing.md)
            .padding(.vertical, NickSpacing.xs)
            .background(severity.statusBackground, in: Capsule())
    }
}

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
