// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import AppKit
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
    @State private var viewMode = 0

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
            if viewMode == 1 {
                NetworkInspectorView()
            } else {
        Group {
            if grouped.isEmpty {
                emptyState
            } else {
                ScrollView {
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
                .background(Color.backgroundPrimary)
            }
        }
        .searchable(text: $searchText, placement: .toolbar, prompt: "Search process or address…")
        } // end else (Connections mode)
        } // end outer Group
        .navigationTitle("Network")
        .navigationSubtitle(viewMode == 0
            ? "\(grouped.count) app\(grouped.count == 1 ? "" : "s") · \(totalConnections) connections"
            : "")
        .toolbar {
            ToolbarItem(placement: .automatic) {
                Picker("View", selection: $viewMode) {
                    Text("Connections").tag(0)
                    Text("Inspector").tag(1)
                }
                .pickerStyle(.segmented)
                .frame(width: 200)
            }
        }
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
    @State private var showsExplanation = false

    private var isSuspicious: Bool {
        connections.contains { $0.isShellProcess && $0.isOutbound }
    }

    private var isUnresolved: Bool {
        processName == "(unknown)" || connections.allSatisfy { $0.pid <= 0 }
    }

    private var hasRegularAppIdentity: Bool {
        connections.contains { connection in
            guard connection.pid > 0,
                  let app = NSRunningApplication(processIdentifier: connection.pid) else {
                return false
            }
            return app.bundleURL != nil
        }
    }

    private var shouldExplainIdentity: Bool {
        isUnresolved || !hasRegularAppIdentity
    }

    var body: some View {
        VStack(spacing: 0) {
            // Header row
            HStack(spacing: 12) {
                Button(action: onToggle) {
                    HStack(spacing: 12) {
                        // App icon
                        AppIconImage(
                            pid: connections.first?.pid ?? -1,
                            processName: processName
                        )
                        .frame(width: 32, height: 32)
                        .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))

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
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .frame(maxWidth: .infinity)

                if shouldExplainIdentity {
                    Button {
                        showsExplanation.toggle()
                    } label: {
                        Image(systemName: "info.circle")
                            .font(.system(size: 13))
                            .foregroundStyle(showsExplanation ? Color.accentColor : Color.textTertiary)
                            .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                    .help("Explain this network activity")
                    .accessibilityLabel("Explain \(processName)")
                }

                Button(action: onToggle) {
                    Image(systemName: "chevron.right")
                        .font(.system(size: 10, weight: .semibold))
                        .foregroundStyle(Color.textTertiary)
                        .rotationEffect(.degrees(isExpanded ? 90 : 0))
                        .animation(.easeInOut(duration: 0.2), value: isExpanded)
                }
                .buttonStyle(.plain)
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 10)

            if showsExplanation {
                HStack(alignment: .top, spacing: 8) {
                    Image(systemName: "info.circle.fill")
                        .foregroundStyle(Color.accentColor)
                    Text(identityExplanation)
                        .font(.system(size: 12))
                        .foregroundStyle(Color.textSecondary)
                        .fixedSize(horizontal: false, vertical: true)
                    Spacer(minLength: 0)
                }
                .padding(.horizontal, 16)
                .padding(.leading, 44)
                .padding(.bottom, 10)
                .accessibilityElement(children: .combine)
            }

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

    private var identityExplanation: String {
        let listener = connections.first { $0.state == .listen }
        let listenerNote: String
        if listener?.localAddress == "0.0.0.0" || listener?.localAddress == "::" {
            listenerNote = " 0.0.0.0 (or ::) means the service is listening on this Mac’s local network interfaces; it is not a remote address or an active connection."
        } else if listener != nil {
            listenerNote = " A listening socket waits for a connection; it does not mean someone is currently connected."
        } else {
            listenerNote = ""
        }

        if isUnresolved {
            return "Nick found the socket but macOS did not provide enough information to match it to an app or process. “Unknown” alone is not evidence of a threat." + listenerNote
        }
        return "\(processName) appears to be a background process or command-line executable, so it may not have a normal app icon. The missing icon alone is not suspicious." + listenerNote
    }
}

// MARK: - AppIconImage

/// Resolves the real app icon for a running process by PID.
/// Falls back to a generic SF Symbol if the process can't be found.
private struct AppIconImage: View {

    let pid: Int32
    let processName: String
    @State private var nsIcon: NSImage?

    var body: some View {
        Group {
            if let nsIcon {
                Image(nsImage: nsIcon)
                    .resizable()
                    .interpolation(.high)
                    .antialiased(true)
            } else {
                Image(systemName: "app.dashed")
                    .font(.system(size: 18))
                    .foregroundStyle(.secondary)
                    .frame(width: 32, height: 32)
            }
        }
        .onAppear(perform: resolveIcon)
    }

    private func resolveIcon() {
        // 1. Fast path: look up by PID (accurate for running processes).
        if pid > 0, let app = NSRunningApplication(processIdentifier: pid) {
            nsIcon = app.icon
            return
        }
        // 2. Fallback: search by localized name.
        if let app = NSWorkspace.shared.runningApplications.first(where: {
            $0.localizedName?.lowercased() == processName.lowercased()
        }) {
            nsIcon = app.icon
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
