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

    @Environment(ExtensionXPCClient.self) private var xpcClient

    @State private var searchText = ""
    @State private var selectedFilter: EventFilter = .all

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
        VStack(spacing: 0) {
            // Filter picker + search
            HStack {
                Picker("Filter", selection: $selectedFilter) {
                    ForEach(EventFilter.allCases, id: \.self) {
                        Text($0.rawValue).tag($0)
                    }
                }
                .pickerStyle(.segmented)

                Spacer()

                TextField("Search", text: $searchText)
                    .textFieldStyle(.roundedBorder)
                    .frame(width: 200)
            }
            .padding(.horizontal)
            .padding(.vertical, 8)

            Divider()

            if filtered.isEmpty {
                ContentUnavailableView(
                    "No Events",
                    systemImage: "clock.badge.checkmark",
                    description: Text(xpcClient.events.isEmpty
                        ? "No events received yet. Events will appear here once the extension is active."
                        : "No events match the current filter.")
                )
            } else {
                List {
                    ForEach(grouped, id: \.day) { group in
                        Section(header: Text(group.day).font(.headline)) {
                            ForEach(group.events) { event in
                                EventRow(event: event)
                            }
                        }
                    }
                }
                .listStyle(.inset)
            }
        }
        .navigationTitle("Threat Timeline")
        .navigationSubtitle("\(xpcClient.events.count) event(s) total")
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
    ThreatTimelineView()
        .environment(ExtensionXPCClient())
        .frame(width: 700, height: 500)
}
