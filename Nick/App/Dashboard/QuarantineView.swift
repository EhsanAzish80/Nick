// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import SwiftUI

// MARK: - QuarantineView

/// Displays all files currently held in the quarantine vault.
/// Each row shows the threat name, original path, and quarantine date,
/// with Restore and Delete actions.
struct QuarantineView: View {

    @Environment(ExtensionXPCClient.self) private var xpcClient

    var body: some View {
        Group {
            if xpcClient.quarantineRecords.isEmpty {
                ContentUnavailableView(
                    "No Quarantined Files",
                    systemImage: "checkmark.shield",
                    description: Text("Files identified as threats will appear here.")
                )
            } else {
                List(xpcClient.quarantineRecords) { record in
                    QuarantineRowView(record: record)
                }
            }
        }
        .navigationTitle("Quarantine")
    }
}

// MARK: - QuarantineRowView

private struct QuarantineRowView: View {

    let record: QuarantineRecord

    private static let dateFormatter: DateFormatter = {
        let f = DateFormatter()
        f.dateStyle = .medium
        f.timeStyle = .short
        return f
    }()

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Image(systemName: "exclamationmark.triangle.fill")
                    .foregroundStyle(.red)
                Text(record.threatName)
                    .fontWeight(.semibold)
                Spacer()
                Text(Self.dateFormatter.string(from: record.quarantinedAt))
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            Text(record.originalPath)
                .font(.caption)
                .foregroundStyle(.secondary)
                .lineLimit(1)
                .truncationMode(.middle)

            HStack(spacing: 4) {
                Text("SHA-256:")
                    .font(.caption2)
                    .foregroundStyle(.tertiary)
                Text(record.hash.prefix(16) + "…")
                    .font(.caption2.monospaced())
                    .foregroundStyle(.tertiary)
            }

            HStack {
                Spacer()
                // Restore button — sends request to extension via XPC
                Button("Restore") {
                    // Phase 4: route through XPCClient → extension requestRestore(id:)
                }
                .buttonStyle(.bordered)
                .tint(.orange)

                Button("Delete Permanently", role: .destructive) {
                    // Phase 4: route through XPCClient → extension requestDelete(id:)
                }
                .buttonStyle(.bordered)
            }
            .padding(.top, 4)
        }
        .padding(.vertical, 4)
    }
}

#Preview {
    NavigationStack {
        QuarantineView()
            .environment(ExtensionXPCClient())
    }
}
