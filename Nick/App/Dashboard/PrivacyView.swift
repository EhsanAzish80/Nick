// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import SwiftUI

// MARK: - PrivacyView

/// Lists TCC privacy permission changes reported by the extension.
///
/// Each row shows the app, the service (camera, microphone, etc.) and whether
/// the permission was granted or revoked. Rows are colour-coded by change type.
struct PrivacyView: View {

    @Environment(ExtensionXPCClient.self) private var xpcClient

    var body: some View {
        Group {
            if xpcClient.privacyAlerts.isEmpty {
                ContentUnavailableView(
                    "No Privacy Events",
                    systemImage: "hand.raised.fill",
                    description: Text(
                        "Changes to camera, microphone, accessibility, and other sensitive " +
                        "permissions will appear here in real time."
                    )
                )
            } else {
                List(xpcClient.privacyAlerts) { alert in
                    PrivacyAlertRow(alert: alert)
                }
            }
        }
        .navigationTitle("Privacy Monitor")
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Text("\(xpcClient.privacyAlerts.count) event(s)")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
        }
    }
}

// MARK: - PrivacyAlertRow

private struct PrivacyAlertRow: View {

    let alert: PrivacyAlert

    private static let dateFormatter: DateFormatter = {
        let f = DateFormatter()
        f.dateStyle = .medium
        f.timeStyle = .short
        return f
    }()

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            // Service icon
            ZStack {
                RoundedRectangle(cornerRadius: 6, style: .continuous)
                    .fill(serviceColor)
                    .frame(width: 28, height: 28)
                Image(systemName: serviceIcon)
                    .font(.system(size: 14, weight: .semibold))
                    .foregroundStyle(.white)
            }

            VStack(alignment: .leading, spacing: 3) {
                // App name + service
                HStack(spacing: 6) {
                    Text(displayName(for: alert.appBundleID))
                        .font(.body.weight(.medium))
                        .lineLimit(1)
                    Text("→")
                        .foregroundStyle(.secondary)
                    Text(alert.service)
                        .font(.body)

                    // Grant / revoke badge
                    Text(changeLabel)
                        .font(.caption.weight(.semibold))
                        .padding(.horizontal, 7)
                        .padding(.vertical, 2)
                        .background(badgeColor.opacity(0.15), in: Capsule())
                        .foregroundStyle(badgeColor)
                }

                // App path + timestamp
                HStack(spacing: 8) {
                    Text(alert.appPath)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                    Spacer()
                    Text(Self.dateFormatter.string(from: alert.timestamp))
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
        }
        .padding(.vertical, 4)
    }

    // MARK: Helpers

    private var changeLabel: String {
        switch alert.changeType {
        case .granted:  return "Granted"
        case .revoked:  return "Revoked"
        case .modified: return "Modified"
        }
    }

    private var badgeColor: Color {
        switch alert.changeType {
        case .granted:  return .orange
        case .revoked:  return .secondary
        case .modified: return .blue
        }
    }

    private var serviceColor: Color {
        switch alert.service {
        case "Camera":                      return .red
        case "Microphone":                  return .orange
        case "Screen Recording":            return .purple
        case "Full Disk Access":            return .indigo
        case "Accessibility":               return .blue
        case "Location":                    return .green
        default:                            return .gray
        }
    }

    private var serviceIcon: String {
        switch alert.service {
        case "Camera":                      return "camera.fill"
        case "Microphone":                  return "mic.fill"
        case "Screen Recording":            return "rectangle.dashed.badge.record"
        case "Full Disk Access":            return "lock.open.fill"
        case "Accessibility":               return "accessibility"
        case "Contacts":                    return "person.2.fill"
        case "Calendar":                    return "calendar"
        case "Photos":                      return "photo.fill"
        case "Location":                    return "location.fill"
        case "Input Monitoring":            return "keyboard.fill"
        default:                            return "hand.raised.fill"
        }
    }

    private func displayName(for bundleID: String) -> String {
        // Strip the leading reverse-DNS prefix for readability.
        // "com.apple.Safari" → "Safari"
        bundleID.components(separatedBy: ".").last ?? bundleID
    }
}
