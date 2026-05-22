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
}

// MARK: - Preview

#Preview {
    SystemAuditView()
        .environment(SecurityEngine())
        .frame(width: NickLayout.windowWidth)
        .background(Color.backgroundPrimary)
}

