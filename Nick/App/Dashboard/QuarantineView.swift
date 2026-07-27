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
    @Environment(ExtensionXPCClient.self) private var xpcClient
    @State private var isWorking = false
    @State private var actionFailed = false
    @State private var showDeleteConfirmation = false

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
                    isWorking = true
                    actionFailed = false
                    xpcClient.requestRestoreQuarantinedFile(id: record.id) { success in
                        isWorking = false
                        actionFailed = !success
                    }
                }
                .buttonStyle(.bordered)
                .tint(.orange)
                .disabled(isWorking || !xpcClient.isConnected)

                Button("Delete Permanently", role: .destructive) {
                    showDeleteConfirmation = true
                }
                .buttonStyle(.bordered)
                .disabled(isWorking || !xpcClient.isConnected)
            }
            .padding(.top, 4)

            if actionFailed {
                Text("The action failed. Check Real-Time Protection in Smart Scan and try again.")
                    .font(.caption)
                    .foregroundStyle(.red)
            }
        }
        .padding(.vertical, 4)
        .confirmationDialog(
            "Permanently delete this quarantined file?",
            isPresented: $showDeleteConfirmation,
            titleVisibility: .visible
        ) {
            Button("Delete Permanently", role: .destructive) {
                isWorking = true
                actionFailed = false
                xpcClient.requestDeleteQuarantinedFile(id: record.id) { success in
                    isWorking = false
                    actionFailed = !success
                }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("This cannot be undone. The original file will not be recoverable.")
        }
    }
}

#Preview {
    NavigationStack {
        QuarantineView()
            .environment(ExtensionXPCClient())
    }
}
