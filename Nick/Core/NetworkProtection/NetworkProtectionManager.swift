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
    private(set) var temporaryAllowedDomains: [String: Date] = [:]
    private(set) var temporaryAllowedAppIdentifiers: [String: Date] = [:]
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
            temporaryAllowedDomains = Self.activeDates(
                configuration.temporaryAllowedDomains
            )
            temporaryAllowedAppIdentifiers = Self.activeDates(
                configuration.temporaryAllowedAppIdentifiers
            )
            if !manager.isEnabled {
                state = .disabled
            } else if NetworkProtectionSharedStore.hasCurrentHealth(
                expectedProviderVersion: NetworkProtectionSharedStore.bundledProviderVersion()
            ) {
                state = .enabled
            } else {
                state = .failed(
                    "The Network Filter is enabled in macOS, but its provider is not running."
                )
            }
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
        return await saveAllowlist(
            domains: domains,
            apps: Set(allowedAppIdentifiers),
            temporaryDomains: Self.timestamps(temporaryAllowedDomains),
            temporaryApps: Self.timestamps(temporaryAllowedAppIdentifiers)
        )
    }

    @discardableResult
    func allowDomain(_ rawDomain: String, for duration: TimeInterval) async -> Bool {
        guard duration > 0,
              let domain = NetworkProtectionConfiguration.normalizedDomain(rawDomain)
        else { return false }
        var temporary = Self.timestamps(temporaryAllowedDomains)
        temporary[domain] = Date().addingTimeInterval(duration).timeIntervalSince1970
        return await saveAllowlist(
            domains: Set(allowedDomains),
            apps: Set(allowedAppIdentifiers),
            temporaryDomains: temporary,
            temporaryApps: Self.timestamps(temporaryAllowedAppIdentifiers)
        )
    }

    func removeAllowedDomain(_ domain: String) async {
        var domains = Set(allowedDomains)
        domains.remove(domain)
        _ = await saveAllowlist(
            domains: domains,
            apps: Set(allowedAppIdentifiers),
            temporaryDomains: Self.timestamps(temporaryAllowedDomains),
            temporaryApps: Self.timestamps(temporaryAllowedAppIdentifiers)
        )
    }

    func removeTemporaryAllowedDomain(_ domain: String) async {
        var temporary = Self.timestamps(temporaryAllowedDomains)
        temporary.removeValue(forKey: domain)
        _ = await saveAllowlist(
            domains: Set(allowedDomains),
            apps: Set(allowedAppIdentifiers),
            temporaryDomains: temporary,
            temporaryApps: Self.timestamps(temporaryAllowedAppIdentifiers)
        )
    }

    @discardableResult
    func allowApp(_ rawIdentifier: String) async -> Bool {
        let identifier = rawIdentifier.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !identifier.isEmpty else { return false }
        var apps = Set(allowedAppIdentifiers)
        apps.insert(identifier)
        return await saveAllowlist(
            domains: Set(allowedDomains),
            apps: apps,
            temporaryDomains: Self.timestamps(temporaryAllowedDomains),
            temporaryApps: Self.timestamps(temporaryAllowedAppIdentifiers)
        )
    }

    @discardableResult
    func allowApp(_ rawIdentifier: String, for duration: TimeInterval) async -> Bool {
        let identifier = rawIdentifier.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard duration > 0, !identifier.isEmpty else { return false }
        var temporary = Self.timestamps(temporaryAllowedAppIdentifiers)
        temporary[identifier] = Date().addingTimeInterval(duration).timeIntervalSince1970
        return await saveAllowlist(
            domains: Set(allowedDomains),
            apps: Set(allowedAppIdentifiers),
            temporaryDomains: Self.timestamps(temporaryAllowedDomains),
            temporaryApps: temporary
        )
    }

    func removeAllowedApp(_ identifier: String) async {
        var apps = Set(allowedAppIdentifiers)
        apps.remove(identifier)
        _ = await saveAllowlist(
            domains: Set(allowedDomains),
            apps: apps,
            temporaryDomains: Self.timestamps(temporaryAllowedDomains),
            temporaryApps: Self.timestamps(temporaryAllowedAppIdentifiers)
        )
    }

    func removeTemporaryAllowedApp(_ identifier: String) async {
        var temporary = Self.timestamps(temporaryAllowedAppIdentifiers)
        temporary.removeValue(forKey: identifier)
        _ = await saveAllowlist(
            domains: Set(allowedDomains),
            apps: Set(allowedAppIdentifiers),
            temporaryDomains: Self.timestamps(temporaryAllowedDomains),
            temporaryApps: temporary
        )
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

    private func saveAllowlist(
        domains: Set<String>,
        apps: Set<String>,
        temporaryDomains: [String: TimeInterval],
        temporaryApps: [String: TimeInterval]
    ) async -> Bool {
        let manager = NEFilterManager.shared()
        do {
            try await manager.loadFromPreferences()
            let provider = manager.providerConfiguration
                ?? NEFilterProviderConfiguration()
            let configuration = NetworkProtectionConfiguration(
                protectionEnabled: true,
                blockingEnabled: false,
                allowedDomains: domains,
                allowedAppIdentifiers: apps,
                temporaryAllowedDomains: temporaryDomains,
                temporaryAllowedAppIdentifiers: temporaryApps
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
            temporaryAllowedDomains = Self.activeDates(
                configuration.temporaryAllowedDomains
            )
            temporaryAllowedAppIdentifiers = Self.activeDates(
                configuration.temporaryAllowedAppIdentifiers
            )
            return true
        } catch {
            state = .failed(error.localizedDescription)
            return false
        }
    }

    private static func activeDates(_ values: [String: TimeInterval]) -> [String: Date] {
        let now = Date()
        return values.reduce(into: [:]) { result, entry in
            let date = Date(timeIntervalSince1970: entry.value)
            if date > now { result[entry.key] = date }
        }
    }

    private static func timestamps(_ values: [String: Date]) -> [String: TimeInterval] {
        values.mapValues(\.timeIntervalSince1970)
    }
}
