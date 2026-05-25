// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import SwiftUI

// MARK: - NetworkConnectionsView

/// Lists active network connections grouped by process name.
///
/// Connections from the same process are collapsed into a `DisclosureGroup`.
/// Shell processes with outbound connections are surfaced first and highlighted.
/// Non-standard remote ports are shown in `statusYellow`. Localhost-only
/// connections are de-emphasized with `textTertiary`. `[UNKNOWN]` DNS labels
/// are replaced with the raw IP address.
struct NetworkConnectionsView: View {

    @Environment(SecurityEngine.self) private var engine
    @State private var searchText = ""
    @State private var expandedProcesses: Set<String> = []

    // MARK: - Filtering + Grouping

    private var filtered: [NetworkConnectionInfo] {
        guard !searchText.isEmpty else { return engine.connections }
        return engine.connections.filter {
            $0.processName.localizedCaseInsensitiveContains(searchText) ||
            ($0.remoteAddress ?? "").localizedCaseInsensitiveContains(searchText)
        }
    }

    /// Connections grouped by process name, suspicious processes first.
    private var grouped: [(key: String, value: [NetworkConnectionInfo])] {
        let dict = Dictionary(grouping: filtered) { $0.processName.isEmpty ? "(unknown)" : $0.processName }
        return dict
            .sorted { a, b in
                let aSuspicious = a.value.contains { $0.isShellProcess && $0.isOutbound }
                let bSuspicious = b.value.contains { $0.isShellProcess && $0.isOutbound }
                if aSuspicious != bSuspicious { return aSuspicious }
                return a.key < b.key
            }
    }

    // MARK: - Body

    private var totalConnections: Int { engine.connections.count }

    var body: some View {
        Group {
            if grouped.isEmpty {
                emptyState
            } else {
                ScrollView {
                    VStack(alignment: .leading, spacing: 0) {
                        // Hero row
                        HStack(spacing: 14) {
                            IconTile(systemImage: "network", tint: Color(NSColor.systemBlue), size: 56)
                            VStack(alignment: .leading, spacing: 4) {
                                Text("Network")
                                    .font(.system(size: 18, weight: .semibold))
                                    .foregroundStyle(Color.textPrimary)
                                Text("\(grouped.count) app\(grouped.count == 1 ? "" : "s") with active connections · \(totalConnections) total")
                                    .font(.system(size: 13))
                                    .foregroundStyle(Color.textSecondary)
                            }
                            Spacer()
                        }
                        .padding(.horizontal, 20)
                        .padding(.top, 20)
                        .padding(.bottom, 16)

                        // Section + card
                        VStack(alignment: .leading, spacing: 8) {
                            Text("ACTIVE APPS · \(grouped.count)")
                                .font(.system(size: 11, weight: .semibold))
                                .foregroundStyle(Color.textTertiary)
                                .tracking(0.5)
                                .padding(.horizontal, 20)

                            VStack(spacing: 0) {
                                ForEach(Array(grouped.enumerated()), id: \.element.key) { index, group in
                                    ProcessGroup(
                                        processName: group.key,
                                        connections: group.value,
                                        isExpanded: expandedProcesses.contains(group.key),
                                        onToggle: { toggle(group.key) }
                                    )
                                    if index < grouped.count - 1 {
                                        Divider().padding(.leading, 60)
                                    }
                                }
                            }
                            .background(
                                RoundedRectangle(cornerRadius: 10, style: .continuous)
                                    .fill(Color(NSColor.controlBackgroundColor))
                            )
                            .overlay(
                                RoundedRectangle(cornerRadius: 10, style: .continuous)
                                    .strokeBorder(Color.borderSubtle, lineWidth: 0.5)
                            )
                            .padding(.horizontal, 20)
                            .padding(.bottom, 24)
                        }
                    }
                }
                .background(Color.backgroundPrimary)
            }
        }
        .searchable(text: $searchText, placement: .toolbar, prompt: "Search process or address…")
        .navigationTitle("Network")
    }

    // MARK: - Private

    private func toggle(_ key: String) {
        if expandedProcesses.contains(key) {
            expandedProcesses.remove(key)
        } else {
            expandedProcesses.insert(key)
        }
    }

    private var emptyState: some View {
        ScrollView {
            VStack(spacing: 20) {
                Spacer(minLength: 40)
                IconTile(systemImage: "network.slash", tint: Color(NSColor.systemGray), size: 64)
                VStack(spacing: 6) {
                    Text("No active connections")
                        .font(.system(size: 18, weight: .semibold))
                        .foregroundStyle(Color.textPrimary)
                    Text(searchText.isEmpty
                         ? "Network connections will appear here when apps are active."
                         : "No connections match \"\(searchText)\".")
                        .font(.system(size: 13))
                        .foregroundStyle(Color.textSecondary)
                        .multilineTextAlignment(.center)
                }
                Spacer(minLength: 40)
            }
            .frame(maxWidth: .infinity)
            .padding(40)
        }
        .background(Color.backgroundPrimary)
    }
}

// MARK: - ProcessGroup

private struct ProcessGroup: View {

    let processName: String
    let connections: [NetworkConnectionInfo]
    let isExpanded: Bool
    let onToggle: () -> Void

    private var isSuspicious: Bool {
        connections.contains { $0.isShellProcess && $0.isOutbound }
    }

    /// Deterministic accent color based on first character of process name.
    private var avatarColor: Color {
        let palette: [Color] = [.blue, .purple, .green, .orange, .red,
                                Color(NSColor.systemTeal), Color(NSColor.systemIndigo),
                                Color(NSColor.systemBrown), Color(NSColor.systemPink)]
        let idx = abs(processName.unicodeScalars.first.map { Int($0.value) } ?? 0) % palette.count
        return isSuspicious ? .red : palette[idx]
    }

    private var avatarLetter: String {
        String(processName.first ?? "?").uppercased()
    }

    var body: some View {
        VStack(spacing: 0) {
            // Header row
            Button(action: onToggle) {
                HStack(spacing: 12) {
                    // Letter avatar tile
                    ZStack {
                        RoundedRectangle(cornerRadius: 8, style: .continuous)
                            .fill(LinearGradient(
                                colors: [avatarColor.opacity(0.75), avatarColor],
                                startPoint: .top, endPoint: .bottom
                            ))
                            .frame(width: 32, height: 32)
                            .shadow(color: avatarColor.opacity(0.27), radius: 5, y: 2)
                        Text(avatarLetter)
                            .font(.system(size: 14, weight: .semibold))
                            .foregroundStyle(.white)
                    }

                    Text(processName)
                        .font(.system(size: 13, weight: .medium))
                        .foregroundStyle(isSuspicious ? Color.statusRed : Color.textPrimary)
                        .lineLimit(1)

                    Spacer()

                    // Status dot
                    Circle()
                        .fill(isSuspicious ? Color.statusRed : Color.statusGreen)
                        .frame(width: 7, height: 7)

                    Text("\(connections.count)")
                        .font(.system(size: 13))
                        .foregroundStyle(Color.textSecondary)
                        .frame(minWidth: 20, alignment: .trailing)

                    Image(systemName: "chevron.right")
                        .font(.system(size: 10, weight: .semibold))
                        .foregroundStyle(Color.textTertiary)
                        .rotationEffect(.degrees(isExpanded ? 90 : 0))
                        .animation(.easeInOut(duration: 0.2), value: isExpanded)
                }
                .padding(.horizontal, 16)
                .padding(.vertical, 10)
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)

            // Expanded connection list
            if isExpanded {
                VStack(spacing: 0) {
                    ForEach(connections) { conn in
                        Divider().padding(.leading, 60)
                        ConnectionDetailRow(connection: conn)
                    }
                }
            }
        }
    }
}

// MARK: - ConnectionDetailRow

private struct ConnectionDetailRow: View {

    let connection: NetworkConnectionInfo

    private var isLocalhost: Bool {
        connection.localAddress.hasPrefix("127.") && (connection.remoteAddress?.hasPrefix("127.") ?? true)
    }

    var body: some View {
        HStack(spacing: 10) {
            // Protocol badge
            Text(connection.transportProtocol.rawValue)
                .font(.system(size: 10, weight: .medium, design: .monospaced))
                .foregroundStyle(Color.textSecondary)
                .padding(.horizontal, 6)
                .padding(.vertical, 3)
                .background(Color.backgroundPrimary, in: RoundedRectangle(cornerRadius: 4))

            // Address line — drop [UNKNOWN] DNS labels, show raw IP
            Text(addressLine)
                .font(.system(size: 11, design: .monospaced))
                .foregroundStyle(isLocalhost ? Color.textTertiary : Color.textSecondary)
                .lineLimit(1)
                .truncationMode(.middle)

            Spacer()

            // Remote port: highlight non-standard ports
            if let port = connection.remotePort {
                Text(":\(port)")
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundStyle(isStandardPort(port) ? Color.textTertiary : Color.statusOrange)
            }
        }
        .padding(.horizontal, 16)
        .padding(.leading, 44)  // indent under avatar
        .padding(.vertical, 9)
        .background(Color.backgroundPrimary.opacity(0.6))
    }

    // MARK: - Private

    private var addressLine: String {
        let local = "\(connection.localAddress):\(connection.localPort)"
        guard let remote = connection.remoteAddress, let rPort = connection.remotePort else {
            if connection.state == .listen { return "\(local) [listening]" }
            return local
        }
        return "\(local) → \(remote):\(rPort)"
    }

    private func isStandardPort(_ port: Int) -> Bool {
        let standard = [80, 443, 22, 53, 25, 587, 993, 465, 8080, 8443]
        return standard.contains(port)
    }
}

// MARK: - Preview

#Preview {
    NetworkConnectionsView()
        .environment(SecurityEngine())
        .frame(width: NickLayout.windowWidth, height: 400)
        .background(Color.backgroundPrimary)
}
