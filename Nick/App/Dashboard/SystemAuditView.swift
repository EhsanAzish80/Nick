// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import SwiftUI

// MARK: - SystemAuditView

/// Displays the results of the most recent `SystemAuditor` run as a list of
/// check rows with pass / fail / warning / unknown indicators.
struct SystemAuditView: View {

    @Environment(SecurityEngine.self) private var engine

    var body: some View {
        ScrollView {
            LazyVStack(spacing: 2) {
                if engine.auditResults.isEmpty {
                    ContentUnavailableView(
                        "No audit data",
                        systemImage: "checkmark.shield",
                        description: Text("Run a scan to check your system configuration.")
                    )
                    .padding()
                } else {
                    ForEach(engine.auditResults) { result in
                        AuditResultRow(result: result)
                        Divider().padding(.leading, 40)
                    }
                }
            }
            .padding(.vertical, 4)
        }
    }
}

// MARK: - AuditResultRow

private struct AuditResultRow: View {

    let result: SystemCheckResult

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: result.status.systemImage)
                .foregroundStyle(statusColor)
                .frame(width: 20)
                .padding(.top, 2)

            VStack(alignment: .leading, spacing: 2) {
                HStack {
                    Text(result.check.displayName)
                        .font(.callout.bold())
                    Spacer()
                    Text(result.currentValue)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Text(result.description)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(2)
                if let rec = result.recommendation {
                    Text(rec)
                        .font(.caption)
                        .foregroundStyle(.orange)
                        .padding(.top, 2)
                }
            }
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 6)
    }

    private var statusColor: Color {
        switch result.status {
        case .pass:    .green
        case .warning: .orange
        case .fail:    .red
        case .unknown: .secondary
        }
    }
}


