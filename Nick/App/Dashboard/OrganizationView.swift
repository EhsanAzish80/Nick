import AppKit
import SwiftUI
import UniformTypeIdentifiers

struct OrganizationView: View {
    @Environment(ExtensionXPCClient.self) private var xpcClient
    @Environment(NetworkProtectionManager.self) private var networkProtection

    @State private var managedState = EnterpriseManagedConfigurationStore().load()
    @State private var report: EnterpriseHealthReport?
    @State private var errorMessage: String?
    @State private var isRefreshing = false
    @State private var copiedReadinessSummary = false
    @AppStorage("enterpriseLastStatusExportAt") private var lastStatusExportAt = 0.0

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: NickSpacing.xl) {
                header
                deploymentReadiness
                managementStatus
                if let configuration = managedState.configuration {
                    managedSettings(configuration)
                }
                providerHealth
                collectionDisclosure
                limitations
            }
            .padding(NickSpacing.xl)
            .frame(maxWidth: 940, alignment: .leading)
        }
        .navigationTitle("Organization")
        .toolbar {
            ToolbarItemGroup(placement: .primaryAction) {
                Button(action: exportStatus) {
                    Label("Export Status", systemImage: "square.and.arrow.up")
                }
                .disabled(report == nil)

                Button {
                    Task { await refresh() }
                } label: {
                    Label("Refresh", systemImage: "arrow.clockwise")
                }
                .disabled(isRefreshing)
            }
        }
        .task {
            await refresh()
        }
    }

    @ViewBuilder
    private var deploymentReadiness: some View {
        if let report {
            let readiness = EnterpriseDeploymentReadiness(
                report: report,
                managedConfiguration: managedState
            )
            GroupBox("Deployment readiness") {
                HStack(alignment: .top, spacing: NickSpacing.md) {
                    Image(systemName: readinessSymbol(readiness.level))
                        .font(.largeTitle)
                        .foregroundStyle(readinessColor(readiness.level))
                        .accessibilityHidden(true)
                    VStack(alignment: .leading, spacing: NickSpacing.xs) {
                        Text(readiness.title).font(.title3.weight(.semibold))
                        Text(readiness.detail).foregroundStyle(.secondary)
                        Text("Based on live provider evidence captured \(report.generatedAt.formatted(date: .abbreviated, time: .standard)).")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    Spacer()
                    Button {
                        copyReadinessSummary(readiness.supportSummary)
                    } label: {
                        Label(
                            copiedReadinessSummary ? "Copied" : "Copy Summary",
                            systemImage: copiedReadinessSummary ? "checkmark" : "doc.on.doc"
                        )
                    }
                }
                .padding(NickSpacing.sm)
                .accessibilityElement(children: .combine)
            }
        }
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: NickSpacing.xs) {
            Text(managedState.configuration?.organizationName ?? "Managed Mac")
                .font(.largeTitle.weight(.bold))
            Text("Nick is configured by a forced device-management preference.")
                .font(.title3)
                .foregroundStyle(.secondary)
        }
    }

    private var managementStatus: some View {
        GroupBox("Management status") {
            VStack(alignment: .leading, spacing: NickSpacing.md) {
                statusRow(
                    title: "Policy provenance",
                    value: "Forced preference: \(EnterpriseManagedConfigurationStore.preferenceKey)",
                    icon: "checkmark.seal.fill",
                    color: .green
                )
                switch managedState {
                case .managed(let configuration):
                    LabeledContent("Schema version", value: String(configuration.schemaVersion))
                    LabeledContent("User interface", value: configuration.showUserInterface ? "Visible" : "Hidden by policy")
                case .invalid(let error):
                    statusRow(
                        title: "Configuration needs attention",
                        value: error.recoverySuggestion ?? error.message,
                        icon: "exclamationmark.triangle.fill",
                        color: .orange
                    )
                case .unmanaged:
                    Text("No forced managed configuration is currently visible.")
                        .foregroundStyle(.secondary)
                }
            }
            .padding(NickSpacing.sm)
        }
    }

    private func managedSettings(_ configuration: EnterpriseManagedConfiguration) -> some View {
        GroupBox("Managed configuration") {
            Grid(alignment: .leading, horizontalSpacing: NickSpacing.xl, verticalSpacing: NickSpacing.sm) {
                managedValue("Log level", configuration.logLevel.rawValue.capitalized)
                managedValue("Retention", "\(configuration.retentionDays) days")
                managedValue("Capture duration", "\(configuration.captureDurationSeconds) seconds")
                managedValue("Sanitized exports", configuration.sanitizeExports ? "Required" : "Not required")
                managedValue("Export formats", configuration.exportFormats.map(\.rawValue).joined(separator: ", "))
                managedValue("Export directory", configuration.exportDirectory ?? "Not configured")
            }
            .padding(NickSpacing.sm)
        }
    }

    private var providerHealth: some View {
        GroupBox("Live protection evidence") {
            VStack(alignment: .leading, spacing: 0) {
                if isRefreshing, report == nil {
                    ProgressView("Checking signed providers…")
                        .padding(NickSpacing.md)
                } else if let report {
                    ForEach(report.components) { component in
                        componentRow(component)
                        if component.id != report.components.last?.id {
                            Divider()
                        }
                    }
                } else {
                    ContentUnavailableView(
                        "Status unavailable",
                        systemImage: "waveform.path.ecg.rectangle",
                        description: Text(errorMessage ?? "Nick could not create a live provider report.")
                    )
                }
            }
            .padding(NickSpacing.sm)
        }
    }

    private var collectionDisclosure: some View {
        GroupBox("Administrator visibility") {
            VStack(alignment: .leading, spacing: NickSpacing.sm) {
                Label("Status stays on this Mac unless you or an administrator exports it.", systemImage: "lock.shield")
                Text("The status report contains Nick and macOS versions, architecture, managed-policy presence, provider health, evidence times, and stated limitations. It does not contain document contents, message contents, browsing history, or credentials.")
                    .foregroundStyle(.secondary)
                Text("Nick does not upload fleet data or connect directly to Intune, Jamf, Kandji, or another MDM service.")
                    .foregroundStyle(.secondary)
                LabeledContent(
                    "Last local status export",
                    value: lastStatusExportAt > 0
                        ? Date(timeIntervalSince1970: lastStatusExportAt).formatted(date: .abbreviated, time: .standard)
                        : "Never"
                )
            }
            .padding(NickSpacing.sm)
        }
    }

    private var limitations: some View {
        GroupBox("Current limitations") {
            VStack(alignment: .leading, spacing: NickSpacing.sm) {
                let items = report?.limitations ?? []
                if items.isEmpty {
                    Label("No visibility limitation is reported right now.", systemImage: "checkmark.circle.fill")
                        .foregroundStyle(.green)
                } else {
                    ForEach(items, id: \.self) { item in
                        Label(item, systemImage: "exclamationmark.triangle")
                            .foregroundStyle(.orange)
                    }
                }
                Text("This is runtime evidence, not a compliance certification or proof that a component was removed.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            .padding(NickSpacing.sm)
        }
    }

    private func componentRow(_ component: EnterpriseComponentHealth) -> some View {
        HStack(alignment: .top, spacing: NickSpacing.md) {
            Image(systemName: componentSymbol(component.state))
                .foregroundStyle(componentColor(component.state))
                .font(.title2)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: NickSpacing.xs) {
                HStack {
                    Text(component.displayName).font(.headline)
                    Text(component.state.rawValue.replacingOccurrences(of: "cannotVerify", with: "Cannot verify").capitalized)
                        .font(.caption.weight(.semibold))
                        .foregroundStyle(componentColor(component.state))
                }
                if let message = component.message {
                    Text(message).foregroundStyle(.secondary)
                }
                if let evidence = component.lastSuccessfulEventAt {
                    Text("Last successful evidence: \(evidence.formatted(date: .abbreviated, time: .standard))")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                if let code = component.errorCode {
                    Text("Code: \(code)").font(.caption.monospaced()).foregroundStyle(.secondary)
                }
            }
            Spacer()
        }
        .padding(NickSpacing.md)
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(component.displayName), \(component.state.rawValue)")
    }

    private func statusRow(title: String, value: String, icon: String, color: Color) -> some View {
        Label {
            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(.headline)
                Text(value).foregroundStyle(.secondary)
            }
        } icon: {
            Image(systemName: icon).foregroundStyle(color)
        }
    }

    private func managedValue(_ title: String, _ value: String) -> some View {
        GridRow {
            Text(title).foregroundStyle(.secondary)
            Text(value).textSelection(.enabled)
        }
    }

    private func refresh() async {
        guard !isRefreshing else { return }
        isRefreshing = true
        defer { isRefreshing = false }
        managedState = EnterpriseManagedConfigurationStore().load()
        xpcClient.connect()
        await networkProtection.refresh()
        try? await Task.sleep(for: .milliseconds(400))
        do {
            report = try EnterpriseHealthReportBuilder.buildLive(
                xpcClient: xpcClient,
                networkProtection: networkProtection
            )
            errorMessage = nil
        } catch {
            report = nil
            errorMessage = error.localizedDescription
        }
    }

    private func exportStatus() {
        guard let report else { return }
        let panel = NSSavePanel()
        panel.nameFieldStringValue = "Nick Enterprise Status.json"
        panel.allowedContentTypes = [.json]
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            let envelope = EnterpriseStatusCommand.result(
                report: report,
                managedConfiguration: managedState
            )
            let encoder = JSONEncoder()
            encoder.dateEncodingStrategy = .iso8601
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
            try encoder.encode(envelope).write(to: url, options: .atomic)
            lastStatusExportAt = Date.now.timeIntervalSince1970
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    private func copyReadinessSummary(_ summary: String) {
        let pasteboard = NSPasteboard.general
        pasteboard.clearContents()
        pasteboard.setString(summary, forType: .string)
        copiedReadinessSummary = true
        Task { @MainActor in
            try? await Task.sleep(for: .seconds(2))
            copiedReadinessSummary = false
        }
    }

    private func readinessSymbol(_ level: EnterpriseDeploymentReadiness.Level) -> String {
        switch level {
        case .ready: "checkmark.seal.fill"
        case .needsAttention: "exclamationmark.triangle.fill"
        case .cannotVerify: "questionmark.diamond.fill"
        }
    }

    private func readinessColor(_ level: EnterpriseDeploymentReadiness.Level) -> Color {
        switch level {
        case .ready: .green
        case .needsAttention: .orange
        case .cannotVerify: .yellow
        }
    }

    private func componentSymbol(_ state: EnterpriseComponentState) -> String {
        switch state {
        case .available: "checkmark.circle.fill"
        case .degraded: "exclamationmark.triangle.fill"
        case .unavailable: "xmark.octagon.fill"
        case .notConfigured: "minus.circle.fill"
        case .cannotVerify: "questionmark.circle.fill"
        }
    }

    private func componentColor(_ state: EnterpriseComponentState) -> Color {
        switch state {
        case .available: .green
        case .degraded, .notConfigured: .orange
        case .unavailable: .red
        case .cannotVerify: .secondary
        }
    }
}
