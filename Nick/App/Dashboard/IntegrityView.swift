// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import SwiftUI

// MARK: - IntegrityView

/// Displays File Integrity Monitor violations detected by the extension.
/// Each row shows the affected path, violation type, and timestamp.
/// A "Rebuild Baseline" button triggers a fresh baseline via the XPC channel.
struct IntegrityView: View {

    @Environment(ExtensionXPCClient.self) private var xpcClient

    var body: some View {
        Group {
            if xpcClient.integrityViolations.isEmpty {
                ContentUnavailableView(
                    "No Integrity Violations",
                    systemImage: "lock.shield",
                    description: Text("Unexpected changes to monitored system paths will appear here.")
                )
            } else {
                List(xpcClient.integrityViolations) { violation in
                    IntegrityRowView(violation: violation)
                }
            }
        }
        .navigationTitle("File Integrity")
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Button("Rebuild Baseline") {
                    // Phase 4: route through XPCClient → extension requestRebuildBaseline()
                }
                .help("Clears the current FIM baseline and rebuilds it from the current system state.")
            }
        }
    }
}

// MARK: - IntegrityRowView

private struct IntegrityRowView: View {

    let violation: IntegrityViolation

    private static let dateFormatter: DateFormatter = {
        let f = DateFormatter()
        f.dateStyle = .medium
        f.timeStyle = .short
        return f
    }()

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            // Icon reflects violation type
            Image(systemName: iconName)
                .foregroundStyle(iconColor)
                .frame(width: 20)

            VStack(alignment: .leading, spacing: 3) {
                Text(violation.path)
                    .font(.body)
                    .lineLimit(1)
                    .truncationMode(.middle)

                HStack {
                    Text(violationLabel)
                        .font(.caption)
                        .padding(.horizontal, 6)
                        .padding(.vertical, 2)
                        .background(iconColor.opacity(0.15), in: Capsule())
                        .foregroundStyle(iconColor)

                    Text(Self.dateFormatter.string(from: violation.timestamp))
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }

                // Show hash delta when available
                if let expected = violation.expectedHash, let actual = violation.actualHash {
                    Group {
                        Text("was: ") + Text(expected.prefix(12) + "…").monospaced()
                        Text("now: ") + Text(actual.prefix(12) + "…").monospaced()
                    }
                    .font(.caption2)
                    .foregroundStyle(.tertiary)
                }
            }
        }
        .padding(.vertical, 3)
    }

    private var iconName: String {
        switch violation.violationType {
        case .modified: return "pencil.and.outline"
        case .created:  return "plus.circle"
        case .deleted:  return "minus.circle"
        }
    }

    private var iconColor: Color {
        switch violation.violationType {
        case .modified: return .orange
        case .created:  return .blue
        case .deleted:  return .red
        }
    }

    private var violationLabel: String {
        switch violation.violationType {
        case .modified: return "Modified"
        case .created:  return "Created"
        case .deleted:  return "Deleted"
        }
    }
}

#Preview {
    NavigationStack {
        IntegrityView()
            .environment(ExtensionXPCClient())
    }
}
