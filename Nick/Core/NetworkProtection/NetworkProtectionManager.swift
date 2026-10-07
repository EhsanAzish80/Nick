import AppKit
import Darwin
import Foundation
import NetworkExtension
import Observation

@MainActor
@Observable
final class NetworkProtectionManager {
    static let observationNotification = Notification.Name("com.ehsanazish.nick.network-observation")
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
    var findingHandler: ((NetworkFinding) async -> Void)?
    private var observationToken: NSObjectProtocol?
    private var eventDirectorySource: DispatchSourceFileSystemObject?
    private var deliveredEventIDs: Set<UUID> = []

    init() {
        observationToken = DistributedNotificationCenter.default().addObserver(
            forName: Self.observationNotification,
            object: nil,
            queue: .main
        ) { [weak self] _ in
            MainActor.assumeIsolated { self?.loadEvents() }
        }
    }

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
            startEventDirectoryWatcher()
        } catch {
            state = .failed(error.localizedDescription)
            loadEvents()
            startEventDirectoryWatcher()
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
        let sorted = decoded.sorted { $0.timestamp > $1.timestamp }
        let newEvents = sorted.filter { deliveredEventIDs.insert($0.id).inserted }
        blockEvents = sorted
        for event in newEvents {
            guard let findingHandler else { continue }
            let finding = NetworkFinding(event: event)
            Task { await findingHandler(finding) }
        }
    }

    func openNetworkExtensionSettings() {
        guard let url = URL(
            string: "x-apple.systempreferences:com.apple.LoginItems-Settings.extension"
        ) else { return }
        NSWorkspace.shared.open(url)
    }

    private func startEventDirectoryWatcher() {
        guard eventDirectorySource == nil,
              let directory = NetworkProtectionSharedStore.eventsURL()?.deletingLastPathComponent()
        else { return }
        let descriptor = open(directory.path, O_EVTONLY)
        guard descriptor >= 0 else { return }
        let source = DispatchSource.makeFileSystemObjectSource(
            fileDescriptor: descriptor,
            eventMask: [.write, .extend, .rename, .delete],
            queue: .main
        )
        source.setEventHandler { [weak self] in
            MainActor.assumeIsolated { self?.loadEvents() }
        }
        source.setCancelHandler { close(descriptor) }
        source.resume()
        eventDirectorySource = source
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

struct NetworkFinding: Sendable {
    let signal: ThreatSignal
    let score: Double
    let recommendedAction: String

    init(event: NetworkBlockEvent) {
        let reason = NetworkObservationReason(rawValue: event.reason)
        let severity: SignalSeverity
        let score: Double
        switch reason {
        case .knownThreat:
            severity = .high
            score = 0.9
        case .scamGuardian:
            severity = .medium
            score = 0.7
        case .connectionRate, .unusualPort, .none:
            severity = .medium
            score = 0.5
        }
        self.score = score
        signal = ThreatSignal(
            id: event.id,
            source: .network,
            severity: severity,
            timestamp: event.timestamp,
            title: event.reasonTitle,
            description: "\(event.appIdentifier ?? "An application") connected to \(event.host). Nick observed the connection and did not block it.",
            context: ThreatSignalContext(metadata: [
                "reason": "network_extension_\(event.reason)",
                "rule": "network_\(event.reason)",
                "destination": event.host,
                "destinationClass": reason == .knownThreat || reason == .scamGuardian ? "suspicious" : "external",
                "appIdentifier": event.appIdentifier ?? "unknown",
                "port": event.port.map(String.init) ?? "unknown"
            ])
        )
        recommendedAction = reason == .scamGuardian
            ? "Close the page if you did not intend to visit it and verify the address before entering information."
            : "Review the destination and the application that opened the connection."
    }
}
