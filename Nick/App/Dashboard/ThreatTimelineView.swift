// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import SwiftUI

// MARK: - ThreatTimelineView

/// Phase 6 — Chronological list of all security events received from the
/// Endpoint Security extension.
///
/// The view is backed by `ExtensionXPCClient.events` which is updated live
/// via XPC. Events are sorted newest-first and grouped by day.
struct ThreatTimelineView: View {

    @Binding var selectedFilter: EventFilter
    @Binding var searchText: String
    @Environment(ExtensionXPCClient.self) private var xpcClient
    @Environment(NetworkProtectionManager.self) private var networkProtection

    // MARK: - Filters

    enum EventFilter: String, CaseIterable {
        case all        = "All"
        case blocked    = "Blocked"
        case threats    = "Threats"
        case writes     = "Writes"

        func matches(_ event: ESEvent) -> Bool {
            switch self {
            case .all:     return true
            case .blocked: return event.decision == .deny
            case .threats: return event.threatName != nil
            case .writes:  return event.eventType == .notifyWrite
            }
        }
    }

    // MARK: - Computed

    private var filtered: [ESEvent] {
        xpcClient.events
            .filter { selectedFilter.matches($0) }
            .filter { event in
                guard !searchText.isEmpty else { return true }
                let q = searchText.lowercased()
                return event.processPath.lowercased().contains(q)
                    || (event.filePath?.lowercased().contains(q) ?? false)
                    || (event.threatName?.lowercased().contains(q) ?? false)
            }
            .sorted { $0.timestamp > $1.timestamp }
    }

    private var filteredNetworkEvents: [NetworkBlockEvent] {
        guard selectedFilter != .writes else { return [] }
        return networkProtection.blockEvents.filter { event in
            if selectedFilter == .blocked && event.decision != .blocked {
                return false
            }
            guard !searchText.isEmpty else { return true }
            let query = searchText.lowercased()
            return event.host.lowercased().contains(query)
                || (event.appIdentifier?.lowercased().contains(query) ?? false)
                || event.reasonTitle.lowercased().contains(query)
        }
    }

    // Group events by calendar day (newest day first).
    private var grouped: [(day: String, events: [ESEvent])] {
        let formatter = DateFormatter()
        formatter.dateStyle = .medium
        formatter.timeStyle = .none

        let dict = Dictionary(grouping: filtered) {
            formatter.string(from: $0.timestamp)
        }
        return dict.sorted { $0.key > $1.key }.map { (day: $0.key, events: $0.value) }
    }

    // MARK: - Body

    var body: some View {
        if filtered.isEmpty && filteredNetworkEvents.isEmpty {
            VStack(spacing: 10) {
                Image(systemName: xpcClient.isConnected ? "clock" : "puzzlepiece.extension")
                    .font(.title2)
                    .foregroundStyle(.secondary)

                Text(emptyTitle)
                    .font(.headline)

                Text(emptyMessage)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal, 40)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        } else {
            List {
                if filteredNetworkEvents.isEmpty == false {
                    Section("Network Protection") {
                        ForEach(filteredNetworkEvents) { event in
                            NetworkBlockEventRow(event: event)
                        }
                    }
                }
                ForEach(grouped, id: \.day) { group in
                    Section(header: Text(group.day).font(.headline)) {
                        ForEach(group.events) { event in
                            EventRow(event: event)
                        }
                    }
                }
            }
            .listStyle(.inset)
            .task { networkProtection.loadEvents() }
        }
    }

    private var emptyTitle: String {
        if !xpcClient.events.isEmpty || !networkProtection.blockEvents.isEmpty {
            if !searchText.isEmpty { return "No matching events" }
            switch selectedFilter {
            case .all:     return "No matching events"
            case .blocked: return "No blocked activity"
            case .threats: return "No threats detected"
            case .writes:  return "No file writes"
            }
        }
        if !xpcClient.isConnected { return "System extension not active" }
        return "No timeline events yet"
    }

    private var emptyMessage: String {
        if !xpcClient.events.isEmpty || !networkProtection.blockEvents.isEmpty {
            if !searchText.isEmpty {
                return "Try a different search or clear the current filter."
            }
            switch selectedFilter {
            case .all:
                return "Try a different filter or clear the search."
            case .blocked:
                return "Nick has not blocked any activity in the recorded timeline."
            case .threats:
                return "No recorded timeline event has been identified as a threat."
            case .writes:
                return "No file-write events match the current timeline."
            }
        }
        if !xpcClient.isConnected {
            return "Timeline requires Nick’s Endpoint Security extension. Open Smart Scan to check its status."
        }
        return "New process and file activity will appear here while Nick is running."
    }
}

private struct NetworkBlockEventRow: View {
    let event: NetworkBlockEvent
    @Environment(NetworkProtectionManager.self) private var networkProtection

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: event.decision == .blocked ? "network.slash" : "eye")
                .foregroundStyle(event.decision == .blocked ? .red : .orange)
                .frame(width: 20)
                .accessibilityHidden(true)

            VStack(alignment: .leading, spacing: 3) {
                HStack {
                    Text(event.host)
                        .fontWeight(.medium)
                        .lineLimit(1)
                    Spacer()
                    Text(event.timestamp.formatted(date: .omitted, time: .standard))
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }

                Text("\(event.decision.userTitle) · \(event.reasonTitle)")
                    .font(.caption)
                    .foregroundStyle(.secondary)

                HStack {
                    if let app = event.appIdentifier, !app.isEmpty {
                        Text(app)
                            .font(.caption2.monospaced())
                            .foregroundStyle(.tertiary)
                            .lineLimit(1)
                    }
                    Spacer()
                    AllowMenu(label: "Allow Website") { duration in
                        Task {
                            if let duration {
                                _ = await networkProtection.allowDomain(event.host, for: duration)
                            } else {
                                _ = await networkProtection.allowDomain(event.host)
                            }
                        }
                    }
                    if let app = event.appIdentifier, !app.isEmpty {
                        AllowMenu(label: "Allow App") { duration in
                            Task {
                                if let duration {
                                    _ = await networkProtection.allowApp(app, for: duration)
                                } else {
                                    _ = await networkProtection.allowApp(app)
                                }
                            }
                        }
                    }
                }
            }
        }
        .padding(.vertical, 2)
        .accessibilityElement(children: .combine)
        .accessibilityLabel(
            "\(event.host), \(event.decision.userTitle), \(event.reasonTitle)"
        )
    }
}

private struct AllowMenu: View {
    let label: String
    let action: (TimeInterval?) -> Void

    var body: some View {
        Menu(label) {
            Button("For 1 Hour") { action(60 * 60) }
            Button("For 24 Hours") { action(24 * 60 * 60) }
            Divider()
            Button("Always") { action(nil) }
        }
        .controlSize(.small)
    }
}

// MARK: - EventRow

private struct EventRow: View {

    let event: ESEvent

    private var timeString: String {
        let f = DateFormatter()
        f.dateStyle = .none
        f.timeStyle = .medium
        return f.string(from: event.timestamp)
    }

    private var severityColor: Color {
        if event.decision == .deny || event.threatName != nil { return .red }
        if event.eventType == .notifyWrite                    { return .orange }
        return .secondary
    }

    private var iconName: String {
        switch event.eventType {
        case .authExec:    return event.decision == .deny ? "xmark.circle.fill"       : "play.circle"
        case .authOpen:    return event.decision == .deny ? "nosign"                  : "folder"
        case .notifyWrite: return "pencil.circle"
        case .notifyFork:  return "arrow.branch"
        case .notifyExit:  return "stop.circle"
        case .notifyOpen:  return "eye"
        case .unknown:     return "questionmark.circle"
        }
    }

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: iconName)
                .foregroundStyle(severityColor)
                .frame(width: 20)

            VStack(alignment: .leading, spacing: 2) {
                HStack {
                    Text(event.processPath.lastPathComponent)
                        .fontWeight(.medium)
                        .lineLimit(1)

                    if let threat = event.threatName {
                        Label(threat, systemImage: "exclamationmark.triangle.fill")
                            .font(.caption)
                            .foregroundStyle(.red)
                            .lineLimit(1)
                    }

                    Spacer()

                    Text(timeString)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }

                if let filePath = event.filePath {
                    Text(filePath)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                }

                HStack(spacing: 8) {
                    Text(event.eventType.rawValue)
                        .font(.caption2)
                        .padding(.horizontal, 5)
                        .padding(.vertical, 2)
                        .background(Color.secondary.opacity(0.15))
                        .clipShape(RoundedRectangle(cornerRadius: 4))

                    if event.decision == .deny {
                        Text("BLOCKED")
                            .font(.caption2)
                            .fontWeight(.semibold)
                            .foregroundStyle(.red)
                    }

                    Text("pid \(event.pid)")
                        .font(.caption2)
                        .foregroundStyle(.tertiary)
                }
            }
        }
        .padding(.vertical, 2)
    }
}

// MARK: - String Helper

private extension String {
    var lastPathComponent: String { (self as NSString).lastPathComponent }
}

// MARK: - Preview

#Preview {
    @Previewable @State var filter = ThreatTimelineView.EventFilter.all
    @Previewable @State var search = ""
    return ThreatTimelineView(selectedFilter: $filter, searchText: $search)
        .environment(ExtensionXPCClient())
        .environment(NetworkProtectionManager())
        .frame(width: 700, height: 500)
}
