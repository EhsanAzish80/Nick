import SwiftUI

/// Live, read-only coverage and health data. Missing measurements are shown as
/// unavailable rather than inferred from a configured feature.
struct DiagnosticsView: View {
    @Environment(SecurityEngine.self) private var engine
    @Environment(ExtensionXPCClient.self) private var xpcClient
    @Environment(NetworkProtectionManager.self) private var networkProtection
    @AppStorage("nickUpdateLastCheckTime") private var updateLastCheckTime: Double = 0
    @AppStorage("nickUpdateLastCheckResult") private var updateLastCheckResult = "Never checked"

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: NickSpacing.lg) {
                Text("Live measurements from Nick's active sensors. These values report coverage; they do not assume protection from configuration alone.")
                    .foregroundStyle(.secondary)

                diagnosticCard("Endpoint Security", systemImage: "shield.lefthalf.filled") {
                    row("XPC connection", xpcClient.isConnected ? "Connected" : "Disconnected")
                    row("Health updated", healthDate("updatedAt")?.formatted(date: .abbreviated, time: .standard) ?? "Unavailable")
                    row("YARA rules", healthBool("yaraRulesReady") ? "Ready" : "Not ready")
                    row("Exact-hash signatures", healthNumber("signatureCount"))
                    row("FIM monitored paths", healthNumber("fimBaselineCount"))
                }

                diagnosticCard("Event delivery", systemImage: "waveform.path.ecg") {
                    row("App file-queue drops", String(engine.fileEventDroppedCount))
                    row("AUTH deadline misses", healthNumber("deadlineMissCount"))
                    row("Last AUTH deadline miss", healthDate("lastDeadlineMissAt")?.formatted(date: .abbreviated, time: .standard) ?? "None reported")
                    let rates = xpcClient.extensionHealth?["eventsPerSecond"] as? [String: Double] ?? [:]
                    row("Busiest event rate", rates.max(by: { $0.value < $1.value }).map { "\($0.key): \(String(format: "%.1f", $0.value))/s" } ?? "Unavailable")
                }

                diagnosticCard("Network and updates", systemImage: "network") {
                    row("Network sensor", networkState)
                    row("Network health updated", NetworkProtectionSharedStore.currentHealthDate(
                        expectedProviderVersion: NetworkProtectionSharedStore.bundledProviderVersion()
                    )?.formatted(date: .abbreviated, time: .standard) ?? "Unavailable")
                    row("Last update check", updateLastCheckTime > 0
                        ? Date(timeIntervalSince1970: updateLastCheckTime).formatted(date: .abbreviated, time: .standard)
                        : "Never")
                    row("Update result", updateLastCheckResult)
                }
            }
            .padding(NickSpacing.xxl)
        }
        .navigationTitle("Diagnostics")
        .toolbar {
            Button("Refresh") {
                Task {
                    await xpcClient.refreshExtensionHealth()
                    await networkProtection.refresh()
                }
            }
        }
        .task {
            await xpcClient.refreshExtensionHealth()
            await networkProtection.refresh()
        }
    }

    private var networkState: String {
        switch networkProtection.state {
        case .loading: return "Checking"
        case .disabled: return "Disabled"
        case .enabled: return "Observing"
        case .awaitingApproval: return "Needs approval"
        case .failed(let reason): return "Unavailable: \(reason)"
        }
    }

    private func healthBool(_ key: String) -> Bool {
        xpcClient.extensionHealth?[key] as? Bool ?? false
    }

    private func healthNumber(_ key: String) -> String {
        if let value = xpcClient.extensionHealth?[key] as? NSNumber { return value.stringValue }
        return "Unavailable"
    }

    private func healthDate(_ key: String) -> Date? {
        guard let value = xpcClient.extensionHealth?[key] as? TimeInterval else { return nil }
        return Date(timeIntervalSince1970: value)
    }

    @ViewBuilder
    private func diagnosticCard<Content: View>(
        _ title: String,
        systemImage: String,
        @ViewBuilder content: () -> Content
    ) -> some View {
        VStack(alignment: .leading, spacing: NickSpacing.md) {
            Label(title, systemImage: systemImage).font(.headline)
            content()
        }
        .padding(NickSpacing.lg)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.background.secondary, in: RoundedRectangle(cornerRadius: NickLayout.cardCornerRadius))
    }

    private func row(_ label: String, _ value: String) -> some View {
        HStack(alignment: .firstTextBaseline) {
            Text(label).foregroundStyle(.secondary)
            Spacer()
            Text(value).multilineTextAlignment(.trailing).textSelection(.enabled)
        }
        .font(.callout)
    }
}
