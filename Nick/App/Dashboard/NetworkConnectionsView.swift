// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import SwiftUI

// MARK: - NetworkConnectionsView

/// Lists all active network connections from the last `NetworkAnalyzer` snapshot.
///
/// Suspicious connections (shell processes with outbound ESTABLISHED state)
/// are surfaced at the top, highlighted in red.
struct NetworkConnectionsView: View {

    @Environment(SecurityEngine.self) private var engine
    @State private var searchText = ""

    private var filtered: [NetworkConnectionInfo] {
        guard !searchText.isEmpty else { return engine.connections }
        return engine.connections.filter {
            $0.processName.localizedCaseInsensitiveContains(searchText) ||
            ($0.remoteAddress ?? "").localizedCaseInsensitiveContains(searchText)
        }
    }

    private var sorted: [NetworkConnectionInfo] {
        filtered.sorted {
            // Suspicious first
            if $0.isShellProcess != $1.isShellProcess { return $0.isShellProcess }
            return $0.processName < $1.processName
        }
    }

    var body: some View {
        VStack(spacing: 0) {
            SearchField(text: $searchText)
                .padding(.horizontal, 8)
                .padding(.vertical, 4)
            Divider()

            if sorted.isEmpty {
                ContentUnavailableView(
                    "No connections",
                    systemImage: "network.slash",
                    description: Text(searchText.isEmpty ? "Run a scan to view network connections." : "No connections match '\(searchText)'.")
                )
                .padding()
            } else {
                ScrollView {
                    LazyVStack(spacing: 0) {
                        ForEach(sorted) { conn in
                            ConnectionRow(connection: conn)
                            Divider().padding(.leading, 36)
                        }
                    }
                }
            }
        }
    }
}

// MARK: - ConnectionRow

private struct ConnectionRow: View {

    let connection: NetworkConnectionInfo

    var body: some View {
        HStack(spacing: 8) {
            Circle()
                .fill(stateColor)
                .frame(width: 8, height: 8)

            VStack(alignment: .leading, spacing: 2) {
                HStack {
                    Text(connection.processName)
                        .font(.callout.bold())
                        .foregroundStyle(connection.isShellProcess ? .red : .primary)
                    Text("(\(connection.pid))")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    Spacer()
                    Text(connection.transportProtocol.rawValue)
                        .font(.caption2.bold())
                        .padding(.horizontal, 4)
                        .padding(.vertical, 1)
                        .background(.quaternary, in: RoundedRectangle(cornerRadius: 3))
                }
                Text(addressLine)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 5)
    }

    private var stateColor: Color {
        switch connection.state {
        case .established:  .green
        case .listen:       .blue
        case .timeWait, .closeWait, .finWait1, .finWait2: .orange
        default:            .secondary
        }
    }

    private var addressLine: String {
        let local = "\(connection.localAddress):\(connection.localPort)"
        if let remote = connection.remoteAddress, let rPort = connection.remotePort {
            return "\(local) → \(remote):\(rPort) [\(connection.state.rawValue)]"
        }
        return "\(local) [\(connection.state.rawValue)]"
    }
}

// MARK: - SearchField

private struct SearchField: View {
    @Binding var text: String

    var body: some View {
        HStack {
            Image(systemName: "magnifyingglass").foregroundStyle(.secondary)
            TextField("Search process or address…", text: $text)
                .textFieldStyle(.plain)
            if !text.isEmpty {
                Button { text = "" } label: {
                    Image(systemName: "xmark.circle.fill").foregroundStyle(.secondary)
                }
                .buttonStyle(.plain)
            }
        }
        .padding(6)
        .background(.quaternary, in: RoundedRectangle(cornerRadius: 6))
    }
}
