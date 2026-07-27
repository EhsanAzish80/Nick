import AppKit
import Foundation
import NetworkExtension
import Observation

@MainActor
@Observable
final class NetworkProtectionManager {
    enum State: Equatable {
        case loading
        case disabled
        case enabled
        case awaitingApproval
        case failed(String)
    }

    private(set) var state: State = .loading
    private(set) var allowedDomains: [String] = []
    private(set) var allowedAppIdentifiers: [String] = []
    private(set) var blockEvents: [NetworkBlockEvent] = []

    var isEnabled: Bool { state == .enabled }

    func refresh() async {
        let manager = NEFilterManager.shared()
        do {
            try await manager.loadFromPreferences()
            let configuration = NetworkProtectionConfiguration(
                vendorConfiguration: manager.providerConfiguration?.vendorConfiguration
            )
            allowedDomains = configuration.allowedDomains.sorted()
            allowedAppIdentifiers = configuration.allowedAppIdentifiers.sorted()
            state = manager.isEnabled ? .enabled : .disabled
            loadEvents()
        } catch {
            state = .failed(error.localizedDescription)
            loadEvents()
        }
    }

    func setEnabled(_ enabled: Bool) async {
        if enabled {
            state = .loading
            await NetworkFilterInstaller.shared.installAndEnable()
            switch NetworkFilterInstaller.shared.state {
            case .awaitingApproval:
                state = .awaitingApproval
            case .failed(let message):
                state = .failed(message)
            default:
                await refresh()
            }
            return
        }

        let manager = NEFilterManager.shared()
        do {
            try await manager.loadFromPreferences()
            manager.isEnabled = false
            try await manager.saveToPreferences()
            state = .disabled
        } catch {
            state = .failed(error.localizedDescription)
        }
    }

    func emergencyDisable() async {
        await setEnabled(false)
    }

    @discardableResult
    func allowDomain(_ rawDomain: String) async -> Bool {
        guard let domain = NetworkProtectionConfiguration.normalizedDomain(rawDomain) else {
            return false
        }
        var domains = Set(allowedDomains)
        domains.insert(domain)
        return await saveAllowlist(domains: domains, apps: Set(allowedAppIdentifiers))
    }

    func removeAllowedDomain(_ domain: String) async {
        var domains = Set(allowedDomains)
        domains.remove(domain)
        _ = await saveAllowlist(domains: domains, apps: Set(allowedAppIdentifiers))
    }

    @discardableResult
    func allowApp(_ rawIdentifier: String) async -> Bool {
        let identifier = rawIdentifier.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !identifier.isEmpty else { return false }
        var apps = Set(allowedAppIdentifiers)
        apps.insert(identifier)
        return await saveAllowlist(domains: Set(allowedDomains), apps: apps)
    }

    func removeAllowedApp(_ identifier: String) async {
        var apps = Set(allowedAppIdentifiers)
        apps.remove(identifier)
        _ = await saveAllowlist(domains: Set(allowedDomains), apps: apps)
    }

    func clearEvents() {
        guard let url = NetworkProtectionSharedStore.eventsURL() else { return }
        try? FileManager.default.removeItem(at: url)
        blockEvents = []
    }

    func loadEvents() {
        guard let url = NetworkProtectionSharedStore.eventsURL(),
              let data = try? Data(contentsOf: url),
              let decoded = try? JSONDecoder().decode([NetworkBlockEvent].self, from: data)
        else {
            blockEvents = []
            return
        }
        blockEvents = decoded.sorted { $0.timestamp > $1.timestamp }
    }

    func openNetworkExtensionSettings() {
        guard let url = URL(
            string: "x-apple.systempreferences:com.apple.LoginItems-Settings.extension"
        ) else { return }
        NSWorkspace.shared.open(url)
    }

    private func saveAllowlist(domains: Set<String>, apps: Set<String>) async -> Bool {
        let manager = NEFilterManager.shared()
        do {
            try await manager.loadFromPreferences()
            let provider = manager.providerConfiguration
                ?? NEFilterProviderConfiguration()
            let configuration = NetworkProtectionConfiguration(
                protectionEnabled: true,
                allowedDomains: domains,
                allowedAppIdentifiers: apps
            )
            provider.filterSockets = true
            provider.filterPackets = false
            provider.filterDataProviderBundleIdentifier =
                "com.ehsanazish.nick.NickNetFilter"
            provider.vendorConfiguration = configuration.vendorConfiguration
            manager.providerConfiguration = provider
            try await manager.saveToPreferences()
            allowedDomains = configuration.allowedDomains.sorted()
            allowedAppIdentifiers = configuration.allowedAppIdentifiers.sorted()
            return true
        } catch {
            state = .failed(error.localizedDescription)
            return false
        }
    }
}
