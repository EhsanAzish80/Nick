// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import SwiftUI

// MARK: - SmartScanSheetView

/// Sheet presented when the user taps "Smart Scan" on the Overview.
/// Shows every `ProtectionCheck` with its icon, headline, explanation and a
/// "Fix" / "Open Settings" / "Install" button where applicable.
struct SmartScanSheetView: View {

    let status: SmartScanStatus?
    let onFixAll: () -> Void

    @Environment(\.dismiss) private var dismiss

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
                Button("Done") { dismiss() }
            }
            .padding(20)

            Divider()

            // ── Check list ───────────────────────────────────────────────
            if let status {
                ScrollView {
                    VStack(spacing: 0) {
                        ForEach(status.checks) { check in
                            ProtectionCheckRow(check: check)
                            Divider().padding(.horizontal, 20)
                        }
                    }
                }

                Divider()

                // ── Footer ─────────────────────────────────────────────
                HStack {
                    Text("Scanned \(status.scanTimestamp.formatted(.relative(presentation: .named)))")
                        .font(.caption)
                        .foregroundStyle(Color.textSecondary)
                    Spacer()
                    if status.issueCount > 0 {
                        Button("Fix All") {
                            onFixAll()
                            dismiss()
                        }
                        .buttonStyle(.borderedProminent)
                    }
                }
                .padding(20)
            } else {
                Spacer()
                ProgressView("Running Smart Scan…")
                Spacer()
            }
        }
        .frame(width: 560, height: 520)
        .background(Color.backgroundPrimary)
    }
}

// MARK: - ProtectionCheckRow

private struct ProtectionCheckRow: View {

    let check: ProtectionCheck

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

            if check.status != .protected {
                resolutionButton
            } else {
                Image(systemName: "checkmark.circle.fill")
                    .foregroundStyle(Color.statusGreen)
                    .font(.system(size: 18))
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
            Button("Install") { /* handled via Fix All */ }
                .buttonStyle(.bordered)
                .controlSize(.small)
        case .autoEnable:
            Button("Enable") { /* handled via Fix All */ }
                .buttonStyle(.borderedProminent)
                .controlSize(.small)
        case .none:
            EmptyView()
        }
    }
}
