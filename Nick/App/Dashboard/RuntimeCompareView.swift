import AppKit
import SwiftUI

struct RuntimeCompareView: View {
    @Environment(ExtensionXPCClient.self) private var xpcClient
    @Environment(NetworkProtectionManager.self) private var networkProtection
    @State private var store = RuntimeComparisonStore()
    @State private var selectedID: UUID?
    @State private var showingNewComparison = false
    @State private var exportComparison: RuntimeComparison?
    @State private var importError: String?

    var body: some View {
        Group {
            if let selectedID, let comparison = store.comparison(selectedID) {
                RuntimeComparisonDetailView(comparisonID: selectedID, store: store) {
                    self.selectedID = nil
                }
                .environment(xpcClient)
                .environment(networkProtection)
                .id(comparison.updatedAt)
            } else {
                landing
            }
        }
        .navigationTitle("Runtime Compare")
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                HStack {
                    Button(action: importComparison) {
                        Label("Import Comparison", systemImage: "square.and.arrow.down")
                    }
                    Button {
                        showingNewComparison = true
                    } label: {
                        Label("New Comparison", systemImage: "plus")
                    }
                    .keyboardShortcut("n", modifiers: .command)
                }
            }
        }
        .sheet(isPresented: $showingNewComparison) {
            NewRuntimeComparisonView { label, scenario in
                let id = store.create(label: label, scenario: scenario)
                selectedID = id
                showingNewComparison = false
            } onCancel: {
                showingNewComparison = false
            }
        }
        .sheet(item: $exportComparison) { comparison in
            RuntimeExportPreview(comparison: comparison)
        }
        .alert("Comparison could not be imported", isPresented: Binding(
            get: { importError != nil }, set: { if !$0 { importError = nil } }
        )) {
            Button("OK", role: .cancel) { importError = nil }
        } message: {
            Text(importError ?? "Unknown import error")
        }
    }

    private var landing: some View {
        ScrollView {
            LazyVStack(alignment: .leading, spacing: NickSpacing.xxl) {
                VStack(alignment: .leading, spacing: NickSpacing.sm) {
                    Text("See what changed")
                        .font(.title.bold())
                    Text("Capture runtime state before and after installing, removing, or reconfiguring security, VPN, MDM, and network software.")
                        .foregroundStyle(.secondary)
                        .frame(maxWidth: 720, alignment: .leading)
                    Button("Start a comparison") { showingNewComparison = true }
                        .buttonStyle(.borderedProminent)
                }

                if store.comparisons.isEmpty {
                    ContentUnavailableView(
                        "No comparisons yet",
                        systemImage: "square.split.2x1",
                        description: Text("Capture a baseline, make one external change, then capture the follow-up to get an evidence-backed explanation.")
                    )
                    .frame(maxWidth: .infinity, minHeight: 320)
                } else {
                    VStack(alignment: .leading, spacing: NickSpacing.md) {
                        Text("Recent comparisons").font(.title2.bold())
                        ForEach(store.comparisons) { comparison in
                            comparisonCard(comparison)
                        }
                    }
                }
            }
            .padding(NickSpacing.xxl)
        }
    }

    private func comparisonCard(_ comparison: RuntimeComparison) -> some View {
        Button { selectedID = comparison.id } label: {
            HStack(spacing: NickSpacing.lg) {
                Image(systemName: comparison.state == .completed ? "checkmark.circle.fill" : "circle.dotted")
                    .font(.title2)
                    .foregroundStyle(comparison.state == .completed ? .green : .orange)
                VStack(alignment: .leading, spacing: NickSpacing.xs) {
                    Text(comparison.label).font(.headline)
                    Text(comparison.scenario.title).font(.subheadline).foregroundStyle(.secondary)
                    if comparison.state == .completed {
                        let important = comparison.findings.filter { $0.attention == .important }.count
                        Text("\(important) important · \(comparison.findings.count) total changes")
                            .font(.caption).foregroundStyle(.secondary)
                    } else {
                        Text(comparison.state == .awaitingBaseline ? "Baseline needed" : "Baseline captured · Follow-up needed")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                }
                Spacer()
                Text(comparison.updatedAt, style: .relative).foregroundStyle(.secondary)
                Image(systemName: "chevron.right").foregroundStyle(.tertiary)
            }
            .padding(NickSpacing.lg)
            .background(.background.secondary, in: RoundedRectangle(cornerRadius: NickLayout.cardCornerRadius))
        }
        .buttonStyle(.plain)
        .contextMenu {
            Button("Export…") { exportComparison = comparison }.disabled(comparison.state != .completed)
            Divider()
            Button("Delete", role: .destructive) { store.delete(comparison.id) }
        }
    }

    private func importComparison() {
        let panel = NSOpenPanel()
        panel.allowedContentTypes = [.json]
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = false
        panel.message = "Choose a Nick Runtime Comparison JSON file captured on this Mac."
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            selectedID = try store.importComparison(from: url)
        } catch {
            importError = error.localizedDescription
        }
    }
}

private struct NewRuntimeComparisonView: View {
    @State private var scenario: RuntimeScenario = .securityOrMDM
    @State private var label = ""
    let onCreate: (String, RuntimeScenario) -> Void
    let onCancel: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: NickSpacing.xl) {
            Text("New Runtime Comparison").font(.title2.bold())
            TextField("Comparison name", text: $label, prompt: Text("Before and after Intune migration"))
            VStack(alignment: .leading, spacing: NickSpacing.sm) {
                ForEach(RuntimeScenario.allCases) { item in
                    Button { scenario = item } label: {
                        HStack(alignment: .top) {
                            scenarioIndicator(for: item)
                            VStack(alignment: .leading) {
                                Text(item.title).font(.headline)
                                Text(item.detail).font(.caption).foregroundStyle(.secondary)
                            }
                            Spacer()
                        }
                        .contentShape(Rectangle())
                    }.buttonStyle(.plain)
                }
            }
            HStack {
                Spacer()
                Button("Cancel", role: .cancel) { onCancel() }.keyboardShortcut(.cancelAction)
                Button("Create") { onCreate(label.isEmpty ? scenario.title : label, scenario) }
                    .buttonStyle(.borderedProminent).keyboardShortcut(.defaultAction)
            }
        }
        .padding(NickSpacing.xxl)
        .frame(width: 600)
    }

    private func scenarioIndicator(for item: RuntimeScenario) -> some View {
        let isSelected = scenario == item
        return Image(systemName: isSelected ? "largecircle.fill.circle" : "circle")
            .foregroundStyle(isSelected ? Color.accentColor : Color.secondary)
    }
}

private struct RuntimeComparisonDetailView: View {
    @Environment(ExtensionXPCClient.self) private var xpcClient
    @Environment(NetworkProtectionManager.self) private var networkProtection
    let comparisonID: UUID
    let store: RuntimeComparisonStore
    let onBack: () -> Void

    @State private var isCapturing = false
    @State private var progress = RuntimeSnapshotCollector.Progress(stage: "Preparing", fraction: 0)
    @State private var observationSeconds = 30
    @State private var errorMessage: String?
    @State private var showingExport = false
    @State private var captureTask: Task<Void, Never>?

    private var comparison: RuntimeComparison? { store.comparison(comparisonID) }

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Button(action: onBack) { Label("Comparisons", systemImage: "chevron.left") }
                Spacer()
                if comparison?.state == .completed { Button("Export…") { showingExport = true } }
            }
            .padding()
            Divider()
            if isCapturing { captureProgress }
            else if let comparison { content(comparison) }
        }
        .sheet(isPresented: $showingExport) {
            if let comparison { RuntimeExportPreview(comparison: comparison) }
        }
        .alert("Capture could not finish", isPresented: Binding(get: { errorMessage != nil }, set: { if !$0 { errorMessage = nil } })) {
            Button("OK", role: .cancel) { errorMessage = nil }
        } message: { Text(errorMessage ?? "Unknown error") }
    }

    @ViewBuilder private func content(_ value: RuntimeComparison) -> some View {
        switch value.state {
        case .awaitingBaseline:
            capturePrompt(value, baseline: true)
        case .awaitingFollowUp:
            capturePrompt(value, baseline: false)
        case .completed:
            results(value)
        }
    }

    private func capturePrompt(_ value: RuntimeComparison, baseline: Bool) -> some View {
        VStack(spacing: NickSpacing.lg) {
            Image(systemName: baseline ? "camera.metering.center.weighted" : "camera.metering.partial")
                .font(.system(size: 48)).foregroundStyle(.indigo)
            Text(baseline ? "Capture the baseline" : "Capture the follow-up").font(.title.bold())
            Text(baseline
                 ? "Nick will record current processes, persistence, listeners, extensions, sensor health, and a bounded window of outbound connections."
                 : "Make the external change first, then capture the same runtime evidence again.")
                .foregroundStyle(.secondary).multilineTextAlignment(.center).frame(maxWidth: 620)
            Picker("Connection observation", selection: $observationSeconds) {
                Text("30 seconds").tag(30)
                Text("1 minute").tag(60)
                Text("5 minutes").tag(300)
            }.frame(width: 300)
            Button(baseline ? "Capture Baseline" : "Capture Follow-up") { capture(baseline: baseline) }
                .buttonStyle(.borderedProminent)
            Text("Observation only. Runtime Compare does not block traffic or change system configuration.")
                .font(.caption).foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .padding(NickSpacing.xxl)
    }

    private var captureProgress: some View {
        VStack(spacing: NickSpacing.lg) {
            ProgressView(value: progress.fraction).frame(maxWidth: 520)
            Text(progress.stage).font(.headline)
            Text("You can cancel safely. An incomplete snapshot will not be saved.")
                .font(.caption).foregroundStyle(.secondary)
            Button("Cancel", role: .cancel) {
                captureTask?.cancel()
                captureTask = nil
                isCapturing = false
            }
        }.frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private func results(_ value: RuntimeComparison) -> some View {
        let important = value.findings.filter { $0.attention == .important }.count
        let partial = value.baseline?.isPartial == true || value.followUp?.isPartial == true
        return ScrollView {
            LazyVStack(alignment: .leading, spacing: NickSpacing.xl) {
                VStack(alignment: .leading, spacing: NickSpacing.xs) {
                    Text(value.label).font(.title.bold())
                    Text("\(important) important · \(value.findings.count) total findings")
                        .foregroundStyle(important > 0 ? .orange : .secondary)
                    if partial {
                        Label("Partial comparison — one or more providers were unavailable.", systemImage: "exclamationmark.triangle")
                            .foregroundStyle(.orange)
                    }
                }
                if value.findings.isEmpty {
                    ContentUnavailableView("No material changes observed", systemImage: "checkmark.circle",
                                           description: Text("This result applies only to the captured snapshots and observation windows."))
                } else {
                    ForEach(RuntimeFindingCategory.allCases, id: \.self) { category in
                        let rows = value.findings.filter { $0.category == category }
                        if !rows.isEmpty {
                            VStack(alignment: .leading, spacing: NickSpacing.sm) {
                                Text(category.rawValue).font(.title2.bold())
                                ForEach(rows) { finding in
                                    RuntimeFindingRow(
                                        finding: finding,
                                        evidence: RuntimeEvidenceResolver.resolve(finding, in: value)
                                    )
                                }
                            }
                        }
                    }
                }
            }.padding(NickSpacing.xxl)
        }
    }

    private func capture(baseline: Bool) {
        guard let comparison else { return }
        isCapturing = true
        let configuration = RuntimeCaptureConfiguration(requestedObservationSeconds: observationSeconds, sampleIntervalSeconds: 5)
        captureTask?.cancel()
        captureTask = Task {
            do {
                let snapshot = try await RuntimeSnapshotCollector().capture(
                    label: baseline ? "Before" : "After", scenario: comparison.scenario,
                    configuration: configuration, endpointResponding: xpcClient.isConnected,
                    networkResponding: networkProtection.isEnabled,
                    networkState: networkStateDescription
                ) { value in
                    guard isCapturing else { return }
                    progress = value
                }
                guard isCapturing else { return }
                if baseline { try store.setBaseline(snapshot, for: comparisonID) }
                else { try store.setFollowUp(snapshot, for: comparisonID) }
                isCapturing = false
                captureTask = nil
            } catch is CancellationError {
                isCapturing = false
                captureTask = nil
            } catch {
                isCapturing = false
                captureTask = nil
                errorMessage = error.localizedDescription
            }
        }
    }

    private var networkStateDescription: String {
        switch networkProtection.state {
        case .loading: "loading"
        case .disabled: "disabled"
        case .enabled: "enabled and responding"
        case .awaitingApproval: "awaiting approval"
        case .failed(let message): "failed: \(message)"
        }
    }
}

private struct RuntimeFindingRow: View {
    let finding: RuntimeFinding
    let evidence: [RuntimeEvidenceItem]
    @State private var showingEvidence = false

    var body: some View {
        HStack(alignment: .top, spacing: NickSpacing.md) {
            Image(systemName: finding.attention == .important ? "exclamationmark.circle.fill" : "circle.fill")
                .foregroundStyle(finding.attention == .important ? .orange : .secondary)
            VStack(alignment: .leading, spacing: NickSpacing.xs) {
                Text(finding.title).font(.headline)
                Text(finding.explanation).foregroundStyle(.secondary)
                if let limitation = finding.limitation { Text(limitation).font(.caption).foregroundStyle(.tertiary) }
                Text("\(finding.evidence.rawValue.capitalized) · \(finding.change.rawValue.capitalized)")
                    .font(.caption2).foregroundStyle(.secondary)
                if !evidence.isEmpty {
                    Button("View Evidence") { showingEvidence = true }
                        .controlSize(.small)
                }
            }
            Spacer()
        }
        .padding(NickSpacing.md)
        .background(.background.secondary, in: RoundedRectangle(cornerRadius: NickLayout.cardCornerRadius))
        .sheet(isPresented: $showingEvidence) {
            RuntimeEvidenceView(finding: finding, evidence: evidence)
        }
    }
}

private struct RuntimeEvidenceView: View {
    @Environment(\.dismiss) private var dismiss
    let finding: RuntimeFinding
    let evidence: [RuntimeEvidenceItem]

    var body: some View {
        VStack(alignment: .leading, spacing: NickSpacing.lg) {
            HStack {
                VStack(alignment: .leading, spacing: NickSpacing.xs) {
                    Text("Evidence").font(.title2.bold())
                    Text(finding.title).foregroundStyle(.secondary)
                }
                Spacer()
                Button("Done") { dismiss() }.keyboardShortcut(.defaultAction)
            }
            Divider()
            ScrollView {
                LazyVStack(alignment: .leading, spacing: NickSpacing.md) {
                    ForEach(evidence) { item in
                        VStack(alignment: .leading, spacing: NickSpacing.sm) {
                            HStack {
                                Text(item.capture.rawValue).font(.caption.bold())
                                    .padding(.horizontal, NickSpacing.sm).padding(.vertical, NickSpacing.xs)
                                    .background(.quaternary, in: Capsule())
                                Text(item.kind).foregroundStyle(.secondary)
                            }
                            Text(item.title).font(.headline).textSelection(.enabled)
                            Grid(alignment: .leading, horizontalSpacing: NickSpacing.lg, verticalSpacing: NickSpacing.xs) {
                                ForEach(Array(item.details.enumerated()), id: \.offset) { _, detail in
                                    GridRow {
                                        Text(detail.label).foregroundStyle(.secondary)
                                        Text(detail.value).font(.system(.body, design: .monospaced))
                                            .textSelection(.enabled)
                                    }
                                }
                            }
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(NickSpacing.lg)
                        .background(.background.secondary, in: RoundedRectangle(cornerRadius: NickLayout.cardCornerRadius))
                    }
                }
            }
            Text("These are records captured by Nick. They show observed state, not the cause or intent of a change.")
                .font(.caption).foregroundStyle(.secondary)
        }
        .padding(NickSpacing.xxl)
        .frame(width: 720, height: 620)
    }
}

struct RuntimeExportPreview: View {
    @Environment(\.dismiss) private var dismiss
    let comparison: RuntimeComparison
    @State private var sanitized = true
    @State private var errorMessage: String?

    private var preview: String {
        let value = sanitized ? RuntimeComparisonSanitizer.sanitize(comparison) : comparison
        return RuntimeSupportBundleBuilder.summary(for: value, sanitized: sanitized)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: NickSpacing.lg) {
            Text("Export Support Bundle").font(.title2.bold())
            Toggle("Sanitize device-specific values", isOn: $sanitized)
            Text("The ZIP will contain exactly these two files:").foregroundStyle(.secondary)
            Label("Runtime Comparison.md", systemImage: "doc.text")
            Label("Runtime Comparison.json", systemImage: "curlybraces")
            ScrollView { Text(preview).font(.system(.caption, design: .monospaced)).textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading) }
                .padding().background(.background.secondary, in: RoundedRectangle(cornerRadius: NickLayout.cardCornerRadius))
            HStack {
                if let errorMessage { Text(errorMessage).foregroundStyle(.red).font(.caption) }
                Spacer()
                Button("Cancel", role: .cancel) { dismiss() }
                Button("Save ZIP…") { save() }.buttonStyle(.borderedProminent)
            }
        }
        .padding(NickSpacing.xxl)
        .frame(width: 720, height: 620)
    }

    private func save() {
        let panel = NSSavePanel()
        panel.allowedContentTypes = [.zip]
        panel.nameFieldStringValue = "Nick Runtime Comparison.zip"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            let files = try RuntimeSupportBundleBuilder.files(for: comparison, sanitized: sanitized)
            try RuntimeSupportBundleBuilder.writeZIP(files, to: url)
            dismiss()
        } catch { errorMessage = error.localizedDescription }
    }
}
