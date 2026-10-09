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
                    row("App build", appBuild)
                    row("Active Endpoint Security build", activeEndpointExtensionBuild)
                    row("Active Network Filter build", activeNetworkExtensionBuild)
                    if endpointBuildStatus == .mismatch || networkBuildStatus == .mismatch {
                        Label(
                            "Nick is connected to a different extension build. Reinstall a package with a higher build number before relying on these diagnostics.",
                            systemImage: "exclamationmark.triangle.fill"
                        )
                        .font(.callout.weight(.semibold))
                        .foregroundStyle(.red)
                    }
                    row("Health updated", healthDate("updatedAt")?.formatted(date: .abbreviated, time: .standard) ?? "Unavailable")
                    row("YARA rules", healthBool("yaraRulesReady") ? "Ready" : "Not ready")
                    row("Bundled hash catalog", catalogSummary)
                    row("Loaded exact-hash signatures", healthNumber("signatureCount"))
                    row("FIM monitored paths", healthNumber("fimBaselineCount"))
                }

                diagnosticCard("Event delivery", systemImage: "waveform.path.ecg") {
                    row("App file-queue drops", String(engine.fileEventDroppedCount))
                    row("Incidents evicted by retention", String(engine.incidentStore.evictedIncidentCount))
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

    private var appBuild: String {
        Bundle.main.object(forInfoDictionaryKey: kCFBundleVersionKey as String) as? String ?? "Unavailable"
    }

    private var activeEndpointExtensionBuild: String {
        xpcClient.extensionHealth?["version"] as? String ?? "Unavailable"
    }

    private var activeNetworkExtensionBuild: String {
        NetworkProtectionSharedStore.providerVersion() ?? "Unavailable"
    }

    private var endpointBuildStatus: ExtensionBuildVersionStatus {
        ExtensionBuildVersionStatus(appBuild: appBuild, extensionBuild: activeEndpointExtensionBuild)
    }

    private var networkBuildStatus: ExtensionBuildVersionStatus {
        ExtensionBuildVersionStatus(appBuild: appBuild, extensionBuild: activeNetworkExtensionBuild)
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

    private var catalogSummary: String {
        guard let count = xpcClient.extensionHealth?["signatureCatalogEntries"] as? NSNumber,
              let date = xpcClient.extensionHealth?["signatureCatalogDate"] as? String,
              date != "unavailable"
        else { return "Unavailable" }
        return "\(count.intValue) entries · \(date)"
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

enum ExtensionBuildVersionStatus: Equatable {
    case matching
    case mismatch
    case unavailable

    init(appBuild: String, extensionBuild: String) {
        guard appBuild != "Unavailable", extensionBuild != "Unavailable" else {
            self = .unavailable
            return
        }
        self = appBuild == extensionBuild ? .matching : .mismatch
    }
}
