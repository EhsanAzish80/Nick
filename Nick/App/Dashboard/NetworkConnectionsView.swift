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

    var body: some View {
        VStack(spacing: 0) {
            if grouped.isEmpty {
                emptyState
            } else {
                ScrollView {
                    VStack(spacing: 0) {
                        ForEach(grouped, id: \.key) { group in
                            ProcessGroup(
                                processName: group.key,
                                connections: group.value,
                                isExpanded: expandedProcesses.contains(group.key),
                                onToggle: { toggle(group.key) }
                            )
                            Rectangle()
                                .fill(Color.borderSubtle)
                                .frame(height: 0.5)
                        }
                    }
                }
            }
        }
        // Change 4: native toolbar search replaces the custom NickSearchField.
        .searchable(text: $searchText, placement: .toolbar, prompt: "Search process or address...")
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
        VStack(spacing: NickSpacing.lg) {
            Image(systemName: "network.slash")
                .font(.system(size: 32))
                .foregroundStyle(Color.textTertiary)
            Text("No connections")
                .font(.nickSubtitle)
                .foregroundStyle(Color.textPrimary)
            Text(searchText.isEmpty
                 ? "Run a scan to view network connections."
                 : "No connections match '\(searchText)'.")
                .font(.nickBodySmall)
                .foregroundStyle(Color.textSecondary)
                .multilineTextAlignment(.center)
        }
        .padding(NickSpacing.xxl)
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

    var body: some View {
        VStack(spacing: 0) {
            // Header row
            Button(action: onToggle) {
                HStack(spacing: NickSpacing.md) {
                    Circle()
                        .fill(isSuspicious ? Color.statusRed : Color.statusGreen)
                        .frame(width: 8, height: 8)

                    Text(processName)
                        .font(.nickBodyMedium)
                        .foregroundStyle(isSuspicious ? Color.statusRed : Color.textPrimary)
                        .lineLimit(1)

                    Spacer()

                    Text("\(connections.count)")
                        .font(.nickMono)
                        .foregroundStyle(Color.textSecondary)

                    Image(systemName: isExpanded ? "chevron.up" : "chevron.down")
                        .font(.system(size: 10, weight: .medium))
                        .foregroundStyle(Color.textTertiary)
                }
                .padding(.horizontal, NickSpacing.lg)
                .frame(minHeight: NickLayout.rowHeight)
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)

            // Expanded connection list
            if isExpanded {
                VStack(spacing: 0) {
                    ForEach(connections) { conn in
                        ConnectionDetailRow(connection: conn)
                        if conn.id != connections.last?.id {
                            Divider().padding(.leading, NickSpacing.xxl)
                        }
                    }
                }
                .background(Color.backgroundTertiary)
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
        HStack(spacing: NickSpacing.md) {
            // Protocol badge
            Text(connection.transportProtocol.rawValue)
                .font(.nickCaption)
                .foregroundStyle(Color.textSecondary)
                .padding(.horizontal, NickSpacing.sm)
                .padding(.vertical, NickSpacing.xs)
                .background(Color.backgroundSecondary, in: RoundedRectangle(cornerRadius: NickLayout.badgeCornerRadius))

            // Address line — drop [UNKNOWN] DNS labels, show raw IP
            Text(addressLine)
                .font(.nickMono)
                .foregroundStyle(isLocalhost ? Color.textTertiary : Color.textSecondary)
                .lineLimit(1)
                .truncationMode(.middle)

            Spacer()

            // Remote port: highlight non-standard ports
            if let port = connection.remotePort {
                Text(":\(port)")
                    .font(.nickMonoSmall)
                    .foregroundStyle(isStandardPort(port) ? Color.textTertiary : Color.statusYellow)
            }
        }
        .padding(.horizontal, NickSpacing.xl)
        .padding(.vertical, NickSpacing.md)
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

// MARK: - NickSearchField

private struct NickSearchField: View {
    @Binding var text: String

    var body: some View {
        HStack(spacing: NickSpacing.md) {
            Image(systemName: "magnifyingglass")
                .foregroundStyle(Color.textTertiary)
                .font(.system(size: NickLayout.iconSize))
            TextField("Search process or address…", text: $text)
                .font(.nickBody)
                .textFieldStyle(.plain)
                .foregroundStyle(Color.textPrimary)
            if !text.isEmpty {
                Button { text = "" } label: {
                    Image(systemName: "xmark.circle.fill")
                        .foregroundStyle(Color.textTertiary)
                }
                .buttonStyle(.plain)
            }
        }
        .padding(NickSpacing.md)
        .background(Color.backgroundTertiary, in: RoundedRectangle(cornerRadius: NickLayout.badgeCornerRadius))
        .overlay(
            RoundedRectangle(cornerRadius: NickLayout.badgeCornerRadius)
                .strokeBorder(Color.borderMedium, lineWidth: 0.5)
        )
    }
}

// MARK: - Preview

#Preview {
    NetworkConnectionsView()
        .environment(SecurityEngine())
        .frame(width: NickLayout.windowWidth, height: 400)
        .background(Color.backgroundPrimary)
}
