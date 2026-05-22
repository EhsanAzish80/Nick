// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import SwiftUI
import SwiftData

// MARK: - ThreatLogView

/// A sortable, filterable table of all persisted `ThreatLogEntry` records.
///
/// Displays all Nick threat alerts with severity, score, timestamp, and review status.
/// Users can filter by severity level, date range, and resolution state, click any row
/// to expand a full detail panel, mark entries as resolved, and export to JSON or CSV.
///
/// - Note: Requires a SwiftData `ModelContainer` for `ThreatLogEntry` in the environment.
struct ThreatLogView: View {

    // MARK: - Environment & Query

    @Environment(\.modelContext) private var modelContext
    @Query(sort: \ThreatLogEntry.timestamp, order: .reverse) private var allEntries: [ThreatLogEntry]

    // MARK: - View State

    @State private var selectedEntry: ThreatLogEntry?
    @State private var filterSeverity: String = "all"
    @State private var filterResolved: String = "all"
    @State private var showExporter = false
    @State private var searchText = ""

    // MARK: - Body

    var body: some View {
        NavigationSplitView {
            sidebarList
        } detail: {
            if let entry = selectedEntry {
                ThreatLogDetailView(entry: entry)
            } else {
                ContentUnavailableView(
                    "Select an Alert",
                    systemImage: "shield.lefthalf.filled",
                    description: Text("Choose an alert from the list to view its details.")
                )
            }
        }
        .navigationTitle("Threat Log")
        .toolbar { toolbarContent }
        .sheet(isPresented: $showExporter) {
            ThreatLogExporterSheet(entries: filteredEntries)
        }
    }

    // MARK: - Sidebar

    private var sidebarList: some View {
        VStack(spacing: 0) {
            filterBar
            Divider()
            if filteredEntries.isEmpty {
                ContentUnavailableView("No Alerts", systemImage: "checkmark.shield")
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                List(filteredEntries, selection: $selectedEntry) { entry in
                    ThreatLogRowView(entry: entry)
                        .tag(entry)
                }
            }
        }
    }

    private var filterBar: some View {
        VStack(spacing: 8) {
            HStack {
                Image(systemName: "magnifyingglass")
                    .foregroundStyle(Color.textTertiary)
                TextField("Search alerts…", text: $searchText)
                    .font(.nickBody)
                    .textFieldStyle(.plain)
            }
            .padding(.horizontal, NickSpacing.md)
            .padding(.vertical, NickSpacing.sm)
            .background(Color.backgroundTertiary, in: RoundedRectangle(cornerRadius: NickLayout.badgeCornerRadius))

            HStack(spacing: 8) {
                Picker("Severity", selection: $filterSeverity) {
                    Text("All").tag("all")
                    Text("Critical").tag("critical")
                    Text("High").tag("high")
                    Text("Medium").tag("medium")
                    Text("Low").tag("low")
                }
                .pickerStyle(.menu)
                .labelsHidden()

                Picker("Status", selection: $filterResolved) {
                    Text("All").tag("all")
                    Text("Unresolved").tag("unresolved")
                    Text("Resolved").tag("resolved")
                }
                .pickerStyle(.menu)
                .labelsHidden()

                Spacer()

                Text("\(filteredEntries.count) alert(s)")
                    .font(.nickCaption)
                    .foregroundStyle(Color.textSecondary)
            }
        }
        .padding(.horizontal, NickSpacing.lg)
        .padding(.vertical, NickSpacing.md)
    }

    // MARK: - Toolbar

    @ToolbarContentBuilder
    private var toolbarContent: some ToolbarContent {
        ToolbarItem(placement: .primaryAction) {
            Button {
                showExporter = true
            } label: {
                Label("Export", systemImage: "arrow.up.doc")
            }
            .disabled(filteredEntries.isEmpty)
        }
    }

    // MARK: - Filtering

    private var filteredEntries: [ThreatLogEntry] {
        allEntries.filter { entry in
            if filterSeverity != "all" && entry.severity != filterSeverity { return false }
            if filterResolved == "resolved"   && !entry.resolved  { return false }
            if filterResolved == "unresolved" &&  entry.resolved  { return false }
            if !searchText.isEmpty {
                let needle = searchText.lowercased()
                let haystack = "\(entry.alertTitle) \(entry.processName ?? "") \(entry.remoteAddress ?? "")".lowercased()
                if !haystack.contains(needle) { return false }
            }
            return true
        }
    }
}

// MARK: - ThreatLogRowView

/// A single row in the threat log table.
private struct ThreatLogRowView: View {

    let entry: ThreatLogEntry

    private func severityColor(_ severity: String) -> Color {
        switch severity {
        case "critical": return .statusRed
        case "high":     return .statusOrange
        case "medium":   return .statusYellow
        default:         return .textTertiary
        }
    }

    var body: some View {
        HStack(spacing: NickSpacing.md) {
            Circle()
                .fill(severityColor(entry.severity))
                .frame(width: 8, height: 8)

            VStack(alignment: .leading, spacing: NickSpacing.xs) {
                Text(entry.alertTitle)
                    .font(.nickBody)
                    .foregroundStyle(Color.textPrimary)
                    .lineLimit(1)
                HStack(spacing: NickSpacing.sm) {
                    Text(entry.timestamp, style: .relative)
                    Text("·")
                    Text(entry.severity.capitalized)
                    Text("·")
                    Text(String(format: "%.0f%%", entry.score * 100))
                }
                .font(.nickCaption)
                .foregroundStyle(Color.textSecondary)
            }

            Spacer()

            if entry.resolved {
                Image(systemName: "checkmark.circle.fill")
                    .foregroundStyle(Color.statusGreen)
                    .font(.system(size: NickLayout.iconSize))
            }
        }
        .padding(.vertical, NickSpacing.xs)
    }
}

// MARK: - ThreatLogDetailView

/// Full detail panel for a selected `ThreatLogEntry`.
private struct ThreatLogDetailView: View {

    @Environment(\.modelContext) private var modelContext
    @State var entry: ThreatLogEntry
    @State private var showResolveSheet = false
    @State private var resolveNote = ""

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: NickSpacing.xl) {
                headerSection
                if let explanation = entry.explanation, !explanation.isEmpty {
                    explanationSection(explanation)
                }
                signalsSection
                contextSection
                resolveSection
            }
            .padding(NickSpacing.xxl)
        }
        .sheet(isPresented: $showResolveSheet) {
            resolveSheet
        }
    }

    private func severityColor(_ severity: String) -> Color {
        switch severity {
        case "critical": return .statusRed
        case "high":     return .statusOrange
        case "medium":   return .statusYellow
        default:         return .textTertiary
        }
    }

    private var headerSection: some View {
        VStack(alignment: .leading, spacing: NickSpacing.md) {
            HStack {
                Text(entry.alertTitle)
                    .font(.nickTitle)
                    .foregroundStyle(Color.textPrimary)
                Spacer()
                Text(entry.severity.capitalized.uppercased())
                    .font(.nickCaption)
                    .padding(.horizontal, NickSpacing.md)
                    .padding(.vertical, NickSpacing.xs)
                    .background(severityColor(entry.severity).opacity(0.15))
                    .foregroundStyle(severityColor(entry.severity))
                    .clipShape(Capsule())
            }
            Text(entry.timestamp, style: .date) + Text(" ") + Text(entry.timestamp, style: .time)
            Text(entry.alertDescription)
                .font(.nickBody)
                .foregroundStyle(Color.textSecondary)
        }
    }

    private func explanationSection(_ text: String) -> some View {
        GroupBox(label: Label("Nick's Analysis", systemImage: "brain")) {
            Text(text)
                .font(.nickBody)
                .foregroundStyle(Color.textPrimary)
                .padding(.top, NickSpacing.sm)
        }
    }

    private var signalsSection: some View {
        GroupBox(label: Label("Contributing Signals (\(entry.contributingSignalSummaries.count))", systemImage: "exclamationmark.triangle")) {
            VStack(alignment: .leading, spacing: NickSpacing.sm) {
                ForEach(entry.contributingSignalSummaries, id: \.self) { summary in
                    Text("· \(summary)")
                        .font(.nickCaption)
                        .foregroundStyle(Color.textSecondary)
                }
            }
            .padding(.top, NickSpacing.sm)
        }
    }

    private var contextSection: some View {
        GroupBox(label: Label("Context", systemImage: "info.circle")) {
            Grid(alignment: .leading, horizontalSpacing: 16, verticalSpacing: 6) {
                if let name = entry.processName {
                    GridRow {
                        Text("Process").foregroundStyle(.secondary)
                        Text("\(name) (PID \(entry.processPID.map { String($0) } ?? "?"))")
                    }
                }
                if let path = entry.processPath {
                    GridRow {
                        Text("Path").foregroundStyle(.secondary)
                        Text(path).lineLimit(2)
                    }
                }
                if let remote = entry.remoteAddress {
                    GridRow {
                        Text("Remote").foregroundStyle(.secondary)
                        Text("\(remote):\(entry.remotePort.map { String($0) } ?? "?")")
                    }
                }
                if let file = entry.filePath {
                    GridRow {
                        Text("File").foregroundStyle(.secondary)
                        Text(file).lineLimit(2)
                    }
                }
                GridRow {
                    Text("Score").foregroundStyle(.secondary)
                    Text(String(format: "%.1f%%", entry.score * 100))
                }
            }
            .font(.caption)
            .padding(.top, 4)
        }
    }

    private var resolveSection: some View {
        GroupBox(label: Label("Review Status", systemImage: "checkmark.shield")) {
            if entry.resolved {
                VStack(alignment: .leading, spacing: NickSpacing.sm) {
                    Label("Marked as Reviewed", systemImage: "checkmark.circle.fill")
                        .font(.nickBodyMedium)
                        .foregroundStyle(Color.statusGreen)
                    if let note = entry.resolvedNote, !note.isEmpty {
                        Text("Note: \(note)")
                            .font(.nickCaption)
                            .foregroundStyle(Color.textSecondary)
                    }
                }
                .padding(.top, NickSpacing.sm)
            } else {
                Button("Mark as Reviewed") {
                    showResolveSheet = true
                }
                .buttonStyle(.nickPrimary)
                .padding(.top, NickSpacing.sm)
            }
        }
    }

    private var resolveSheet: some View {
        VStack(spacing: NickSpacing.xl) {
            Text("Mark as Reviewed").font(.nickTitle)
            TextField("Optional note…", text: $resolveNote, axis: .vertical)
                .textFieldStyle(.roundedBorder)
                .lineLimit(3, reservesSpace: true)
            HStack {
                Button("Cancel") { showResolveSheet = false }
                Spacer()
                Button("Confirm") {
                    entry.resolved = true
                    entry.resolvedNote = resolveNote.isEmpty ? nil : resolveNote
                    try? modelContext.save()
                    showResolveSheet = false
                }
                .buttonStyle(.borderedProminent)
            }
        }
        .padding(NickSpacing.xxl)
        .frame(minWidth: 300)
        .background(Color.backgroundPrimary)
    }
}

// MARK: - ThreatLogExporterSheet

/// A sheet that presents JSON/CSV export options.
private struct ThreatLogExporterSheet: View {

    let entries: [ThreatLogEntry]
    @Environment(\.dismiss) private var dismiss
    @State private var exportFormat: ExportFormat = .json
    @State private var isSaving = false
    @State private var errorMessage: String?

    enum ExportFormat: String, CaseIterable {
        case json = "JSON"
        case csv  = "CSV"
    }

    var body: some View {
        VStack(spacing: NickSpacing.xl) {
            Text("Export \(entries.count) Alert(s)").font(.nickTitle)

            Picker("Format", selection: $exportFormat) {
                ForEach(ExportFormat.allCases, id: \.self) { Text($0.rawValue).tag($0) }
            }
            .pickerStyle(.segmented)

            if let err = errorMessage {
                Text(err)
                    .font(.nickCaption)
                    .foregroundStyle(Color.statusRed)
            }

            HStack {
                Button("Cancel") { dismiss() }
                Spacer()
                Button("Save…") { saveFile() }
                    .buttonStyle(.borderedProminent)
                    .disabled(isSaving)
            }
        }
        .padding(NickSpacing.xxl)
        .frame(minWidth: 320)
        .background(Color.backgroundPrimary)
    }

    private func saveFile() {
        isSaving = true
        let logger = ThreatLogExporter()
        logger.export(entries: entries, format: exportFormat == .json ? .json : .csv) { @MainActor result in
            isSaving = false
            switch result {
            case .success: dismiss()
            case .failure(let err): errorMessage = err.localizedDescription
            }
        }
    }
}
