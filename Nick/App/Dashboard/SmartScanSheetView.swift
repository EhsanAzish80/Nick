// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import SwiftUI

// MARK: - SmartScanContentView

/// Self-contained Smart Scan results view. Manages its own checker, runs the
/// scan on appear (unless `initialStatus` is provided), and handles both
/// individual-check fixes and Fix All.
///
/// Used as the body of `SmartScanSheetView` (sheet) and `SmartScanDetailView`
/// (sidebar detail area).
struct SmartScanContentView: View {

    /// Optional pre-computed status from the caller. If `nil`, the view runs
    /// its own scan on appear.
    var initialStatus: SmartScanStatus?

    /// When `true` the "Done" dismiss button is shown in the header and the
    /// view is given a fixed sheet-friendly size.
    var showDismiss: Bool = false

    @Environment(SecurityEngine.self) private var engine
    @Environment(ExtensionXPCClient.self) private var xpcClient
    @Environment(\.dismiss) private var dismiss

    @State private var status: SmartScanStatus?
    @State private var isFixingAll = false
    @State private var fixAllSummary: FixAllSummary?
    @State private var checker = SmartScanChecker()
    @State private var extensionManager = ExtensionManager()

    init(initialStatus: SmartScanStatus? = nil, showDismiss: Bool = false) {
        self.initialStatus = initialStatus
        self.showDismiss = showDismiss
        self._status = State(initialValue: initialStatus)
    }

    var body: some View {
        VStack(spacing: 0) {
            // ── Header ──────────────────────────────────────────────────
            HStack {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Smart Scan")
                        .font(.title2.bold())
                    if let status {
                        Text(status.issueCount == 0
                             ? "This Mac is fully protected"
                             : "\(status.issueCount) issue\(status.issueCount == 1 ? "" : "s") found")
                            .font(.subheadline)
                            .foregroundStyle(status.issueCount == 0 ? Color.statusGreen : Color.statusOrange)
                    }
                }
                Spacer()
                if showDismiss {
                    Button("Done") { dismiss() }
                }
            }
            .padding(20)

            Divider()

            // ── Fix All summary banner ────────────────────────────────
            if let summary = fixAllSummary {
                summaryBanner(summary)
                Divider()
            }

            // ── Check list ───────────────────────────────────────────────
            if let s = status {
                ScrollView {
                    VStack(spacing: 0) {
                        ForEach(s.checks) { check in
                            ProtectionCheckRow(check: check) {
                                await handleResolve(check)
                            }
                            Divider().padding(.horizontal, 20)
                        }
                    }
                }

                Divider()

                // ── Footer ─────────────────────────────────────────────
                HStack {
                    Text("Scanned \(s.scanTimestamp.formatted(.relative(presentation: .named)))")
                        .font(.caption)
                        .foregroundStyle(Color.textSecondary)
                    Spacer()
                    if s.checks.contains(where: { $0.resolution.canAutoResolve }) {
                        Button(isFixingAll ? "Fixing…" : "Fix All") {
                            handleFixAll(currentStatus: s)
                        }
                        .buttonStyle(.borderedProminent)
                        .disabled(isFixingAll)
                    }
                }
                .padding(20)
            } else {
                Spacer()
                ProgressView("Running Smart Scan…")
                Spacer()
            }
        }
        .background(Color.backgroundPrimary)
        .task {
            checker.securityEngine = engine
            checker.xpcClient = xpcClient
            checker.extensionManager = extensionManager
            xpcClient.connect()
            if status == nil {
                await checker.refreshLiveProtectionState()
                status = checker.runScan()
            }
        }
        .onChange(of: xpcClient.isConnected) {
            // Extension activation and invalidation can happen while this view
            // is open. Re-evaluate every row so stale green states disappear.
            refreshStatus()
        }
        .onChange(of: extensionManager.extensionState) {
            // Surface installation, approval, and failure states immediately.
            refreshStatus()
        }
    }

    // MARK: - Helpers

    private func handleResolve(_ check: ProtectionCheck) async {
        await checker.resolve(check: check)
        await checker.refreshLiveProtectionState()
        if let updated = checker.rescanCheck(id: check.id) {
            status = status?.replacing(check: updated)
        }
    }

    private func refreshStatus() {
        Task { @MainActor in
            await checker.refreshLiveProtectionState()
            status = checker.runScan()
        }
    }

    private func handleFixAll(currentStatus: SmartScanStatus) {
        isFixingAll = true
        fixAllSummary = nil
        Task { @MainActor in
            let newStatus = await checker.resolveAll(status: currentStatus)
            status = newStatus
            fixAllSummary = checker.lastFixAllSummary
            isFixingAll = false
        }
    }

    @ViewBuilder
    private func summaryBanner(_ summary: FixAllSummary) -> some View {
        HStack(spacing: 10) {
            Image(systemName: summary.fixedCount > 0 ? "checkmark.circle.fill" : "info.circle.fill")
                .foregroundStyle(summary.fixedCount > 0 ? Color.statusGreen : Color.statusOrange)
                .font(.system(size: 16))
            VStack(alignment: .leading, spacing: 2) {
                Text(summaryTitle(summary))
                    .font(.system(size: 12, weight: .semibold))
                    .foregroundStyle(Color.textPrimary)
                if !summary.skippedChecks.isEmpty {
                    Text("Still needs attention: " + summary.skippedChecks.map(\.title).joined(separator: ", "))
                        .font(.system(size: 11))
                        .foregroundStyle(Color.textSecondary)
                }
            }
            Spacer()
        }
        .padding(.horizontal, 20)
        .padding(.vertical, 10)
        .background(Color.backgroundSecondary)
    }

    private func summaryTitle(_ summary: FixAllSummary) -> String {
        if summary.fixedCount == 0 {
            return "No items could be fixed automatically."
        } else if summary.skippedChecks.isEmpty {
            return "Fixed all \(summary.fixedCount) issue\(summary.fixedCount == 1 ? "" : "s") automatically."
        } else {
            return "Fixed \(summary.fixedCount) of \(summary.totalAutoFixable) issue\(summary.totalAutoFixable == 1 ? "" : "s")."
        }
    }
}

// MARK: - SmartScanSheetView

/// Sheet wrapper around `SmartScanContentView`. Applies a fixed sheet frame
/// and adds a "Done" dismiss button via `showDismiss: true`.
struct SmartScanSheetView: View {

    let initialStatus: SmartScanStatus?

    var body: some View {
        SmartScanContentView(initialStatus: initialStatus, showDismiss: true)
            .frame(width: 560, height: 520)
    }
}

// MARK: - ProtectionCheckRow

private struct ProtectionCheckRow: View {

    let check: ProtectionCheck
    let onResolve: () async -> Void

    @State private var isResolving = false

    var body: some View {
        HStack(alignment: .top, spacing: 14) {
            Image(systemName: check.icon)
                .font(.system(size: 22))
                .foregroundStyle(statusColor)
                .frame(width: 32)

            VStack(alignment: .leading, spacing: 3) {
                Text(check.title)
                    .font(.system(size: 13, weight: .semibold))
                Text(check.headline)
                    .font(.system(size: 12))
                    .foregroundStyle(Color.textPrimary)
                Text(check.explanation)
                    .font(.system(size: 11))
                    .foregroundStyle(Color.textSecondary)
                    .lineLimit(3)
            }

            Spacer()

            if check.status == .protected {
                Image(systemName: "checkmark.circle.fill")
                    .foregroundStyle(Color.statusGreen)
                    .font(.system(size: 18))
            } else {
                resolutionButton
            }
        }
        .padding(.horizontal, 20)
        .padding(.vertical, 12)
    }

    private var statusColor: Color {
        switch check.status {
        case .protected: return .statusGreen
        case .warning:   return .statusOrange
        case .critical:  return .statusRed
        }
    }

    @ViewBuilder
    private var resolutionButton: some View {
        switch check.resolution {
        case .requiresPermission(_, let url):
            Button("Open Settings") {
                if let u = URL(string: url) { NSWorkspace.shared.open(u) }
            }
            .buttonStyle(.bordered)
            .controlSize(.small)

        case .installExtension:
            Button(isResolving ? "Installing…" : "Install") {
                isResolving = true
                Task {
                    await onResolve()
                    isResolving = false
                }
            }
            .buttonStyle(.bordered)
            .controlSize(.small)
            .disabled(isResolving)

        case .revealAppForInstallation:
            Button("Show App") {
                Task { await onResolve() }
            }
            .buttonStyle(.bordered)
            .controlSize(.small)

        case .restartApplication:
            Button("Reopen Nick") {
                Task { await onResolve() }
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.small)

        case .autoEnable:
            Button(isResolving ? "Enabling…" : "Enable") {
                isResolving = true
                Task {
                    await onResolve()
                    isResolving = false
                }
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.small)
            .disabled(isResolving)

        case .pendingApproval:
            Button(check.resolution.buttonLabel) {
            // No action: the button is always disabled while approval is
            // pending (e.g. a system extension awaiting user confirmation in
            // System Settings). The UI surfaces the pending state for
            // visibility only; the resolution is driven externally once the
            // user grants approval, at which point a rescan promotes this
            // check out of the pendingApproval state.
             }
            .buttonStyle(.bordered)
            .controlSize(.small)
            .disabled(true)

        case .none:
            EmptyView()
        }
    }
}
