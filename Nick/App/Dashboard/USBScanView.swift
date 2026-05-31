// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import SwiftUI

// MARK: - USBScanView

/// Displays threats found on external/removable volumes by `USBScanner`.
///
/// Each row shows the volume, the threat file path, threat name, and timestamp.
/// The view is updated in real time as `ExtensionXPCClient.usbThreats` grows.
struct USBScanView: View {

    @Environment(ExtensionXPCClient.self) private var xpcClient

    var body: some View {
        Group {
            if xpcClient.usbThreats.isEmpty {
                ContentUnavailableView(
                    "No USB Threats Detected",
                    systemImage: "externaldrive.fill.badge.checkmark",
                    description: Text(
                        "When you plug in a USB drive or external disk, Nick scans it " +
                        "automatically. Any malware found will appear here."
                    )
                )
            } else {
                List(xpcClient.usbThreats) { threat in
                    USBThreatRow(threat: threat)
                }
            }
        }
        .navigationTitle("USB Scan")
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                if !xpcClient.usbThreats.isEmpty {
                    Text("\(xpcClient.usbThreats.count) threat(s)")
                        .font(.callout)
                        .foregroundStyle(.red)
                }
            }
        }
    }
}

// MARK: - USBThreatRow

private struct USBThreatRow: View {

    let threat: USBThreat

    private static let dateFormatter: DateFormatter = {
        let f = DateFormatter()
        f.dateStyle = .medium
        f.timeStyle = .short
        return f
    }()

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            // Threat icon
            ZStack {
                RoundedRectangle(cornerRadius: 6, style: .continuous)
                    .fill(Color.red)
                    .frame(width: 28, height: 28)
                Image(systemName: "externaldrive.badge.exclamationmark")
                    .font(.system(size: 14, weight: .semibold))
                    .foregroundStyle(.white)
            }

            VStack(alignment: .leading, spacing: 3) {
                // Threat name
                HStack(spacing: 6) {
                    Text(threat.threatName ?? "Unknown Threat")
                        .font(.body.weight(.medium))

                    if let family = threat.threatFamily {
                        Text(family)
                            .font(.caption.weight(.semibold))
                            .padding(.horizontal, 7)
                            .padding(.vertical, 2)
                            .background(Color.red.opacity(0.1), in: Capsule())
                            .foregroundStyle(.red)
                    }
                }

                // Volume label
                Label(
                    threat.volumePath.components(separatedBy: "/").last ?? threat.volumePath,
                    systemImage: "externaldrive.fill"
                )
                .font(.caption)
                .foregroundStyle(.secondary)

                // File path
                Text(threat.filePath)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .truncationMode(.middle)

                // SHA-256 + timestamp
                HStack {
                    if let sha = threat.sha256 {
                        Text(sha.prefix(16) + "…")
                            .font(.system(size: 10, design: .monospaced))
                            .foregroundStyle(.tertiary)
                    }
                    Spacer()
                    Text(Self.dateFormatter.string(from: threat.timestamp))
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
        }
        .padding(.vertical, 4)
        .contextMenu {
            Button {
                NSWorkspace.shared.selectFile(threat.filePath, inFileViewerRootedAtPath: "")
            } label: {
                Label("Show in Finder", systemImage: "folder")
            }
            Divider()
            Button {
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(threat.filePath, forType: .string)
            } label: {
                Label("Copy Path", systemImage: "doc.on.clipboard")
            }
        }
    }
}
