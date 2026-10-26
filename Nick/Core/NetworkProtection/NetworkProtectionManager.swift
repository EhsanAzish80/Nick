import AppKit
import Darwin
import Foundation
import NetworkExtension
import Observation
import OSLog

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
    var findingHandler: ((NetworkFinding) async -> IncidentIngestOutcome)? {
        didSet {
            guard findingHandler != nil else { return }
            ingestEvents(blockEvents)
        }
    }
    /// Confirms that the root-owned incident-store snapshot covering a live
    /// finding was durably accepted. Network events are not claimed until this
    /// succeeds, matching the Endpoint Security delivery contract.
    var incidentPersistenceHandler: ((UInt64) async -> (UInt64, Bool)?)?
    /// Creates the durable first-run baseline after the shared event store has
    /// been decoded successfully. A failed or missing read must never create an
    /// empty cursor, because doing so would replay historical events later.
    var cursorBootstrapHandler: ((Set<UUID>) async -> Set<UUID>)?
    private var observationToken: NSObjectProtocol?
    private var eventDirectorySource: DispatchSourceFileSystemObject?
    private var deliveredEventIDs: Set<UUID> = []
    private var inFlightEventIDs: Set<UUID> = []
    private var durableCursorReady = false
    private var cursorBootstrapInFlight = false
    private let eventsURLProvider: () -> URL?
    private let logger = Logger(
        subsystem: "com.ehsanazish.nick",
        category: "NetworkIngest"
    )
    private var storeChangeCount = 0
    private(set) var reloadSummaryCount = 0
    var deliveredEventCount: Int { deliveredEventIDs.count }
    var inFlightEventCount: Int { inFlightEventIDs.count }
    var currentEventIDs: Set<UUID> { Set(blockEvents.map(\.id)) }
    var ruleSourceSummary: String {
        guard let event = blockEvents.first(where: { $0.reason == NetworkObservationReason.knownThreat.rawValue }),
              let version = event.sourceVersion,
              let issuedAt = event.sourceIssuedAt else { return "Unavailable" }
        let age = max(0, Calendar.current.dateComponents([.day], from: issuedAt, to: Date()).day ?? 0)
        return "Curated list v\(version) · \(age)d old" + (age > 90 ? " · Stale" : "")
    }

    init(eventsURLProvider: @escaping () -> URL? = {
        NetworkProtectionSharedStore.eventsURL()
    }) {
        self.eventsURLProvider = eventsURLProvider
        observationToken = DistributedNotificationCenter.default().addObserver(
            forName: Self.observationNotification,
            object: nil,
            queue: .main
        ) { [weak self] _ in
            MainActor.assumeIsolated {
                self?.storeDidChange(trigger: "distributed-notification")
            }
        }
        // Event delivery must not depend on a view appearing or on the async
        // system-extension refresh completing. Start observing the production
        // store as soon as AppDelegate creates this manager; refresh retries if
        // the support directory was not available yet.
        startEventDirectoryWatcher()
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
        guard let url = eventsURLProvider() else { return }
        try? FileManager.default.removeItem(at: url)
        blockEvents = []
    }

    func loadEvents() {
        loadEvents(trigger: "explicit-reload")
    }

    func activateDurableCursor(deliveredEventIDs: Set<UUID>) {
        self.deliveredEventIDs = deliveredEventIDs
        durableCursorReady = true
        ingestEvents(blockEvents)
    }

    private func loadEvents(trigger: String) {
        guard let url = eventsURLProvider() else {
            logger.error("store reload skipped trigger=\(trigger, privacy: .public) reason=no-url")
            blockEvents = []
            return
        }
        guard let data = try? Data(contentsOf: url) else {
            logger.error("store reload skipped trigger=\(trigger, privacy: .public) reason=read-failed")
            blockEvents = []
            return
        }
        guard let decoded = Self.decodeEvents(data) else {
            logger.error("store reload skipped trigger=\(trigger, privacy: .public) reason=decode-failed")
            blockEvents = []
            return
        }
        ingestEvents(decoded)
    }

    static func decodeEvents(_ data: Data) -> [NetworkBlockEvent]? {
        try? JSONDecoder().decode([NetworkBlockEvent].self, from: data)
    }

    /// The app-side entry point for the filter's shared-store payload. Event
    /// identifiers are claimed only after a consumer is installed; otherwise
    /// an event arriving during app startup could be marked delivered and then
    /// permanently skipped when the live-finding handler is attached.
    func ingestEvents(_ decoded: [NetworkBlockEvent]) {
        let sorted = decoded.sorted { $0.timestamp > $1.timestamp }
        blockEvents = sorted
        let skippedAlreadyDelivered = sorted.lazy.filter {
            self.deliveredEventIDs.contains($0.id)
        }.count
        let newEvents = sorted.filter {
            !self.deliveredEventIDs.contains($0.id) && !self.inFlightEventIDs.contains($0.id)
        }
        reloadSummaryCount += 1
        logger.info(
            "reload summary decoded=\(sorted.count, privacy: .public) new=\(newEvents.count, privacy: .public) skipped-already-delivered=\(skippedAlreadyDelivered, privacy: .public)"
        )
        guard durableCursorReady else {
            if !cursorBootstrapInFlight, let cursorBootstrapHandler {
                cursorBootstrapInFlight = true
                let baselineIDs = Set(sorted.map(\.id))
                Task {
                    let persistedIDs = await cursorBootstrapHandler(baselineIDs)
                    await self.finishCursorBootstrap(deliveredEventIDs: persistedIDs)
                }
            }
            logger.info("event delivery deferred reason=cursor-not-ready count=\(newEvents.count, privacy: .public)")
            return
        }
        guard let findingHandler else {
            logger.info("event delivery skipped reason=handler-absent count=\(newEvents.count, privacy: .public)")
            return
        }
        for event in newEvents {
            inFlightEventIDs.insert(event.id)
            let finding = NetworkFinding(event: event)
            logger.info(
                "finding built id=\(event.id.uuidString, privacy: .public) reason=\(event.reason, privacy: .public) decision=\(event.decision.rawValue, privacy: .public)"
            )
            Task {
                let outcome = await findingHandler(finding)
                await self.finishDelivery(outcome: outcome, eventID: event.id)
            }
        }
    }

    private func finishCursorBootstrap(deliveredEventIDs: Set<UUID>) {
        cursorBootstrapInFlight = false
        activateDurableCursor(deliveredEventIDs: deliveredEventIDs)
    }

    func openNetworkExtensionSettings() {
        guard let url = URL(
            string: "x-apple.systempreferences:com.apple.LoginItems-Settings.extension"
        ) else { return }
        NSWorkspace.shared.open(url)
    }

    private func startEventDirectoryWatcher() {
        guard eventDirectorySource == nil,
              let directory = eventsURLProvider()?.deletingLastPathComponent()
        else { return }
        let descriptor = open(directory.path, O_EVTONLY)
        guard descriptor >= 0 else {
            logger.error("store watcher unavailable reason=open-failed")
            return
        }
        let source = DispatchSource.makeFileSystemObjectSource(
            fileDescriptor: descriptor,
            eventMask: [.write, .extend, .rename, .delete],
            queue: .main
        )
        source.setEventHandler { [weak self] in
            MainActor.assumeIsolated {
                self?.storeDidChange(trigger: "filesystem")
            }
        }
        source.setCancelHandler { close(descriptor) }
        source.resume()
        eventDirectorySource = source
    }

    private func storeDidChange(trigger: String) {
        storeChangeCount += 1
        logger.info(
            "store change observed trigger=\(trigger, privacy: .public) count=\(self.storeChangeCount, privacy: .public)"
        )
        loadEvents(trigger: trigger)
    }

    private func finishDelivery(outcome: IncidentIngestOutcome, eventID: UUID) async {
        defer { inFlightEventIDs.remove(eventID) }
        switch outcome {
        case .persisted(let generation), .coalesced(let generation):
            let persistence = await incidentPersistenceHandler?(generation)
            guard let (confirmedGeneration, succeeded) = persistence,
                  confirmedGeneration == generation,
                  succeeded else {
                logger.error(
                    "ingest outcome id=\(eventID.uuidString, privacy: .public) result=failed reason=durability-unconfirmed generation=\(generation, privacy: .public)"
                )
                return
            }
            deliveredEventIDs.insert(eventID)
            let result = if case .persisted = outcome { "persisted" } else { "coalesced" }
            logger.info(
                "ingest outcome id=\(eventID.uuidString, privacy: .public) result=\(result, privacy: .public) generation=\(generation, privacy: .public) durable=yes"
            )
        case .suppressedByPolicy(let reason):
            deliveredEventIDs.insert(eventID)
            logger.info(
                "ingest outcome id=\(eventID.uuidString, privacy: .public) result=suppressed reason=\(reason, privacy: .public)"
            )
        case .failed:
            logger.error(
                "ingest outcome id=\(eventID.uuidString, privacy: .public) result=failed"
            )
        }
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
        let destinationKind = NetworkEventContext.destinationKind(for: event.host)
        let destinationClass: String = switch destinationKind {
        case .localDevice, .localNetworkAddress: "local"
        case .website, .internetAddress:
            reason == .knownThreat || reason == .scamGuardian ? "suspicious" : "external"
        }
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
            description: NetworkEventContext(event: event).explanation,
            context: ThreatSignalContext(metadata: [
                "reason": "network_extension_\(event.reason)",
                "rule": "network_\(event.reason)",
                "ruleTier": "review",
                "destination": event.host,
                "destinationClass": destinationClass,
                "appIdentifier": event.appIdentifier ?? "unknown",
                "port": event.port.map(String.init) ?? "unknown",
                "sourceVersion": event.sourceVersion.map(String.init) ?? "unknown",
                "sourceIssuedAt": event.sourceIssuedAt.map { ISO8601DateFormatter().string(from: $0) } ?? "unknown",
                "sourceAge": event.sourceIssuedAt.map {
                    String(max(0, Calendar.current.dateComponents([.day], from: $0, to: Date()).day ?? 0))
                } ?? "unknown"
            ])
        )
        recommendedAction = reason == .scamGuardian
            ? "Review the attempted destination and quit the app if you did not expect it."
            : "Review the attempted destination and the application responsible."
    }
}
