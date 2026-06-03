// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import SwiftUI

// MARK: - NetworkInspectorView

/// LAN vulnerability scanner — discovers local network devices and flags
/// insecure services (Telnet, FTP, exposed RDP, unencrypted VNC, etc.).
///
/// Backed by `NetworkInspector` which uses `arp -a` + TCP port probes.
struct NetworkInspectorView: View {

    @State private var inspector = NetworkInspector()

    var body: some View {
        Group {
            if inspector.isScanning {
                scanningPlaceholder
            } else if inspector.devices.isEmpty {
                emptyState
            } else {
                deviceList
            }
        }
        .navigationTitle("Network Inspector")
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Button(action: startScan) {
                    Label("Scan Network",
                          systemImage: inspector.isScanning ? "stop.fill" : "antenna.radiowaves.left.and.right")
                }
                .disabled(inspector.isScanning)
                .help("Scan your local network for devices with open insecure ports.")
            }
            if let date = inspector.lastScanDate {
                ToolbarItem(placement: .status) {
                    Text("Last scan: \(date.formatted(date: .omitted, time: .shortened))")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
            }
        }
    }

    // MARK: - Subviews

    private var scanningPlaceholder: some View {
        VStack(spacing: 16) {
            ProgressView()
                .progressViewStyle(.circular)
                .controlSize(.large)
            Text("Scanning local network…")
                .font(.body)
                .foregroundStyle(.secondary)
            Text("Probing discovered devices for open ports. This may take up to 30 seconds.")
                .font(.caption)
                .foregroundStyle(.tertiary)
                .multilineTextAlignment(.center)
                .frame(maxWidth: 320)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private var emptyState: some View {
        ContentUnavailableView {
            Label("No Devices Found", systemImage: "network")
        } description: {
            Text("Nick will scan your local network for devices with insecure services.")
        } actions: {
            Button("Scan Network", action: startScan)
                .buttonStyle(.borderedProminent)
        }
    }

    private var deviceList: some View {
        List(inspector.devices) { device in
            NetworkDeviceRow(device: device)
        }
    }

    // MARK: - Actions

    private func startScan() {
        Task {
            await inspector.discoverAndScan()
        }
    }
}

// MARK: - NetworkDeviceRow

private struct NetworkDeviceRow: View {

    let device: NetworkInspector.NetworkDevice

    var body: some View {
        DisclosureGroup {
            // Detail: port list + issues
            VStack(alignment: .leading, spacing: 8) {
                if !device.issues.isEmpty {
                    VStack(alignment: .leading, spacing: 4) {
                        ForEach(device.issues, id: \.self) { issue in
                            Label(issue, systemImage: "exclamationmark.triangle.fill")
                                .font(.caption)
                                .foregroundStyle(.orange)
                        }
                    }
                    .padding(.bottom, 4)
                }

                // Open ports grid
                if !device.openPorts.isEmpty {
                    Text("Open Ports")
                        .font(.caption.weight(.semibold))
                        .foregroundStyle(.secondary)
                    FlowLayout(spacing: 6) {
                        ForEach(device.openPorts, id: \.port) { port in
                            PortBadge(port: port)
                        }
                    }
                }

                if device.openPorts.isEmpty && device.issues.isEmpty {
                    Label("No open ports found — device appears secure", systemImage: "checkmark.shield")
                        .font(.caption)
                        .foregroundStyle(.green)
                }
            }
            .padding(.top, 4)
        } label: {
            // Summary row
            HStack(spacing: 12) {
                // Risk indicator
                Circle()
                    .fill(riskColor)
                    .frame(width: 10, height: 10)
                    .shadow(color: riskColor.opacity(0.4), radius: 4)

                VStack(alignment: .leading, spacing: 2) {
                    HStack(spacing: 6) {
                        Text(device.hostname ?? device.ipAddress)
                            .font(.body.weight(.medium))
                        if device.hostname != nil {
                            Text(device.ipAddress)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    }
                    Text(riskLabel)
                        .font(.caption)
                        .foregroundStyle(riskColor)
                }

                Spacer()

                // Open port count badge
                if !device.openPorts.isEmpty {
                    Text("\(device.openPorts.count) port\(device.openPorts.count == 1 ? "" : "s")")
                        .font(.caption.weight(.semibold))
                        .padding(.horizontal, 8)
                        .padding(.vertical, 3)
                        .background(Color.secondary.opacity(0.15), in: Capsule())
                        .foregroundStyle(.secondary)
                }
            }
        }
    }

    private var riskColor: Color {
        switch device.riskLevel {
        case .safe:   return .green
        case .review: return .orange
        case .risky:  return .red
        }
    }

    private var riskLabel: String {
        switch device.riskLevel {
        case .safe:   return "No issues detected"
        case .review: return "Minor issues — worth reviewing"
        case .risky:  return "Insecure services exposed"
        }
    }
}

// MARK: - PortBadge

private struct PortBadge: View {
    let port: NetworkInspector.PortResult

    var body: some View {
        HStack(spacing: 4) {
            Circle()
                .fill(port.isSecure ? Color.green : Color.orange)
                .frame(width: 6, height: 6)
            Text("\(port.port) \(port.service)")
                .font(.system(size: 11, design: .monospaced))
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 3)
        .background(Color.secondary.opacity(0.1), in: RoundedRectangle(cornerRadius: 4))
    }
}

// MARK: - FlowLayout (simple horizontal wrapping layout)

private struct FlowLayout: Layout {
    var spacing: CGFloat = 8

    func sizeThatFits(proposal: ProposedViewSize, subviews: Subviews, cache _: inout Void) -> CGSize {
        let containerWidth = proposal.width ?? .infinity
        var currentX: CGFloat = 0
        var currentY: CGFloat = 0
        var maxRowHeight: CGFloat = 0
        var totalHeight: CGFloat = 0

        for subview in subviews {
            let size = subview.sizeThatFits(.unspecified)
            if currentX + size.width > containerWidth, currentX > 0 {
                currentX = 0
                currentY += maxRowHeight + spacing
                totalHeight = currentY
                maxRowHeight = 0
            }
            currentX += size.width + spacing
            maxRowHeight = max(maxRowHeight, size.height)
        }
        totalHeight += maxRowHeight
        return CGSize(width: containerWidth, height: totalHeight)
    }

    func placeSubviews(in bounds: CGRect, proposal _: ProposedViewSize, subviews: Subviews, cache _: inout Void) {
        var currentX = bounds.minX
        var currentY = bounds.minY
        var maxRowHeight: CGFloat = 0

        for subview in subviews {
            let size = subview.sizeThatFits(.unspecified)
            if currentX + size.width > bounds.maxX, currentX > bounds.minX {
                currentX = bounds.minX
                currentY += maxRowHeight + spacing
                maxRowHeight = 0
            }
            subview.place(at: CGPoint(x: currentX, y: currentY), proposal: .unspecified)
            currentX += size.width + spacing
            maxRowHeight = max(maxRowHeight, size.height)
        }
    }
}
