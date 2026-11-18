import Foundation

enum NetworkBlockReason: String, Codable, Sendable {
    case blocklist
    case scamGuardian

    var userTitle: String {
        switch self {
        case .blocklist: return "Known dangerous destination"
        case .scamGuardian: return "Possible phishing website"
        }
    }
}

enum NetworkObservationReason: String, Codable, Sendable {
    case knownThreat
    case scamGuardian
    case unusualPort
    case connectionRate

    var userTitle: String {
        switch self {
        case .knownThreat: return "Known dangerous destination"
        case .scamGuardian: return "Possible phishing website"
        case .unusualPort: return "Connection used an uncommon port"
        case .connectionRate: return "Unusually frequent connections"
        }
    }
}

enum NetworkPolicyVerdict: Equatable, Sendable {
    case allow
    case observe(NetworkObservationReason)
    case block(NetworkBlockReason)
}

struct NetworkProtectionConfiguration: Equatable, Sendable {
    static let configurationVersion = 6

    var protectionEnabled: Bool
    var allowedDomains: Set<String>
    var allowedAppIdentifiers: Set<String>
    var temporaryAllowedDomains: [String: TimeInterval]
    var temporaryAllowedAppIdentifiers: [String: TimeInterval]

    init(
        protectionEnabled: Bool = true,
        allowedDomains: Set<String> = [],
        allowedAppIdentifiers: Set<String> = [],
        temporaryAllowedDomains: [String: TimeInterval] = [:],
        temporaryAllowedAppIdentifiers: [String: TimeInterval] = [:]
    ) {
        self.protectionEnabled = protectionEnabled
        self.allowedDomains = Set(allowedDomains.compactMap(Self.normalizedDomain))
        self.allowedAppIdentifiers = Set(
            allowedAppIdentifiers.map { $0.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() }
                .filter { !$0.isEmpty }
        )
        self.temporaryAllowedDomains = Dictionary(
            uniqueKeysWithValues: temporaryAllowedDomains.compactMap { domain, expiry in
                Self.normalizedDomain(domain).map { ($0, expiry) }
            }
        )
        self.temporaryAllowedAppIdentifiers = Dictionary(
            uniqueKeysWithValues: temporaryAllowedAppIdentifiers.compactMap { identifier, expiry in
                let normalized = identifier.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
                return normalized.isEmpty ? nil : (normalized, expiry)
            }
        )
    }

    init(vendorConfiguration: [String: Any]?) {
        let hasCurrentVersion =
            vendorConfiguration?["configurationVersion"] as? Int == Self.configurationVersion
        self.init(
            // An absent or stale configuration must never inherit enforcement.
            protectionEnabled: hasCurrentVersion
                && (vendorConfiguration?["protectionEnabled"] as? Bool == true),
            allowedDomains: Set(vendorConfiguration?["allowedDomains"] as? [String] ?? []),
            allowedAppIdentifiers: Set(vendorConfiguration?["allowedAppIdentifiers"] as? [String] ?? []),
            temporaryAllowedDomains:
                vendorConfiguration?["temporaryAllowedDomains"] as? [String: TimeInterval] ?? [:],
            temporaryAllowedAppIdentifiers:
                vendorConfiguration?["temporaryAllowedAppIdentifiers"] as? [String: TimeInterval] ?? [:]
        )
    }

    var vendorConfiguration: [String: Any] {
        [
            "configurationVersion": Self.configurationVersion,
            "protectionEnabled": protectionEnabled,
            "allowedDomains": allowedDomains.sorted(),
            "allowedAppIdentifiers": allowedAppIdentifiers.sorted(),
            "temporaryAllowedDomains": temporaryAllowedDomains,
            "temporaryAllowedAppIdentifiers": temporaryAllowedAppIdentifiers,
        ]
    }

    static func normalizedDomain(_ value: String) -> String? {
        var candidate = value.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        while candidate.hasSuffix(".") { candidate.removeLast() }
        if candidate.hasPrefix("*.") { candidate.removeFirst(2) }
        if candidate.contains("://"), let host = URL(string: candidate)?.host {
            candidate = host.lowercased()
        }
        if candidate.hasPrefix("[") && candidate.hasSuffix("]") {
            candidate = String(candidate.dropFirst().dropLast())
        }
        if candidate.contains(":") {
            return candidate.split(separator: ":").isEmpty ? nil : candidate
        }
        if candidate.split(separator: ".").count == 4,
           candidate.split(separator: ".").allSatisfy({
               guard let value = Int($0) else { return false }
               return (0...255).contains(value)
           }) {
            return candidate
        }
        guard !candidate.isEmpty,
              candidate.count <= 253,
              !candidate.contains("/"),
              candidate.split(separator: ".").allSatisfy({ !$0.isEmpty && $0.count <= 63 })
        else { return nil }
        return URL(string: "https://\(candidate)")?.host?.lowercased() ?? candidate
    }
}

struct NetworkProtectionPolicy: Sendable {
    let configuration: NetworkProtectionConfiguration

    func evaluate(
        host rawHost: String?,
        appIdentifier rawAppIdentifier: String?,
        now: Date = Date(),
        isBlocklisted: (String) -> Bool,
        isScam: (String) -> Bool
    ) -> NetworkPolicyVerdict {
        guard configuration.protectionEnabled,
              let rawHost,
              let host = NetworkProtectionConfiguration.normalizedDomain(rawHost)
        else {
            return .allow
        }

        let appIdentifier = rawAppIdentifier?
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased()

        if let appIdentifier,
           configuration.allowedAppIdentifiers.contains(appIdentifier)
            || (configuration.temporaryAllowedAppIdentifiers[appIdentifier] ?? 0)
                > now.timeIntervalSince1970 {
            return .allow
        }
        if configuration.allowedDomains.contains(where: { allowed in
            host == allowed || host.hasSuffix(".\(allowed)")
        }) || configuration.temporaryAllowedDomains.contains(where: { allowed, expiry in
            expiry > now.timeIntervalSince1970
                && (host == allowed || host.hasSuffix(".\(allowed)"))
        }) {
            return .allow
        }
        if isBlocklisted(host) { return .observe(.knownThreat) }
        // Local heuristics are valuable context, but they are not sufficient
        // evidence to interrupt basic connectivity. Only signed blocklist
        // matches are enforced; heuristic matches remain visible for review.
        if isScam(host) { return .observe(.scamGuardian) }
        return .allow
    }
}

enum NetworkEventDecision: String, Codable, Sendable {
    case observed
    case blocked

    var userTitle: String {
        switch self {
        case .observed: return "Observed"
        case .blocked: return "Blocked"
        }
    }
}

struct NetworkBlockEvent: Codable, Identifiable, Hashable, Sendable {
    let id: UUID
    let timestamp: Date
    let host: String
    let appIdentifier: String?
    let decision: NetworkEventDecision
    let reason: String
    let reasonTitle: String
    let port: Int?
    let sourceVersion: Int?
    let sourceIssuedAt: Date?
    let sourceExpiresAt: Date?
    /// Set only by NickNetFilter after matching a verified signed bundle.
    let isTestIndicator: Bool
    let indicatorIdentifier: String?
    /// Kernel process identity captured from NEFilterFlow.sourceAppAuditToken.
    /// Both values are required because a PID can be reused after exit.
    let sourcePID: Int32?
    let sourcePIDVersion: Int32?

    init(
        id: UUID = UUID(),
        timestamp: Date = Date(),
        host: String,
        appIdentifier: String?,
        decision: NetworkEventDecision,
        reason: String,
        reasonTitle: String,
        port: Int? = nil,
        sourceVersion: Int? = nil,
        sourceIssuedAt: Date? = nil,
        sourceExpiresAt: Date? = nil,
        isTestIndicator: Bool = false,
        indicatorIdentifier: String? = nil,
        sourcePID: Int32? = nil,
        sourcePIDVersion: Int32? = nil
    ) {
        self.id = id
        self.timestamp = timestamp
        self.host = host
        self.appIdentifier = appIdentifier
        self.decision = decision
        self.reason = reason
        self.reasonTitle = reasonTitle
        self.port = port
        self.sourceVersion = sourceVersion
        self.sourceIssuedAt = sourceIssuedAt
        self.sourceExpiresAt = sourceExpiresAt
        self.isTestIndicator = isTestIndicator
        self.indicatorIdentifier = indicatorIdentifier
        self.sourcePID = sourcePID
        self.sourcePIDVersion = sourcePIDVersion
    }

    init(
        id: UUID = UUID(),
        timestamp: Date = Date(),
        host: String,
        appIdentifier: String?,
        reason: NetworkBlockReason,
        port: Int? = nil
    ) {
        self.init(
            id: id,
            timestamp: timestamp,
            host: host,
            appIdentifier: appIdentifier,
            decision: .blocked,
            reason: reason.rawValue,
            reasonTitle: reason.userTitle,
            port: port
        )
    }

    private enum CodingKeys: String, CodingKey {
        case id, timestamp, host, appIdentifier, decision, reason, reasonTitle, port
        case sourceVersion, sourceIssuedAt, sourceExpiresAt, isTestIndicator, indicatorIdentifier
        case sourcePID, sourcePIDVersion
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decode(UUID.self, forKey: .id)
        timestamp = try container.decode(Date.self, forKey: .timestamp)
        host = try container.decode(String.self, forKey: .host)
        appIdentifier = try container.decodeIfPresent(String.self, forKey: .appIdentifier)
        decision = try container.decodeIfPresent(NetworkEventDecision.self, forKey: .decision)
            ?? .blocked
        reason = try container.decode(String.self, forKey: .reason)
        reasonTitle = try container.decodeIfPresent(String.self, forKey: .reasonTitle)
            ?? NetworkBlockReason(rawValue: reason)?.userTitle
            ?? reason
        port = try container.decodeIfPresent(Int.self, forKey: .port)
        sourceVersion = try container.decodeIfPresent(Int.self, forKey: .sourceVersion)
        sourceIssuedAt = try container.decodeIfPresent(Date.self, forKey: .sourceIssuedAt)
        sourceExpiresAt = try container.decodeIfPresent(Date.self, forKey: .sourceExpiresAt)
        isTestIndicator = try container.decodeIfPresent(Bool.self, forKey: .isTestIndicator) ?? false
        indicatorIdentifier = try container.decodeIfPresent(String.self, forKey: .indicatorIdentifier)
        sourcePID = try container.decodeIfPresent(Int32.self, forKey: .sourcePID)
        sourcePIDVersion = try container.decodeIfPresent(Int32.self, forKey: .sourcePIDVersion)
    }
}

// MARK: - User-facing network evidence

/// Deterministic, offline context for a recorded network decision.
///
/// This deliberately avoids reputation claims. It explains only evidence Nick
/// already has: the destination class, the responsible signing identifier,
/// the port, the recorded reason, and whether the connection was interrupted.
struct NetworkEventContext: Equatable, Sendable {
    enum DestinationKind: Equatable, Sendable {
        case website
        case localDevice
        case localNetworkAddress
        case internetAddress
    }

    let appName: String
    let destinationKind: DestinationKind
    let destinationLabel: String
    let portPurpose: String?
    let explanation: String
    let guidance: String
    let destinationActionLabel: String
    let appActionLabel: String

    init(event: NetworkBlockEvent) {
        appName = Self.displayName(for: event.appIdentifier)
        destinationKind = Self.destinationKind(for: event.host)
        destinationLabel = Self.destinationLabel(for: destinationKind)
        portPurpose = Self.portPurpose(for: event.port)
        destinationActionLabel = destinationKind == .website
            ? "Allow This Website"
            : "Allow This Destination"
        appActionLabel = "Allow This Domain"

        let purpose = portPurpose.map { " It used \($0)." } ?? ""
        if event.isTestIndicator {
            explanation = "\(appName) connected to \(event.host), a signed Nick test destination. Nick recorded the attempt; it did not block it.\(purpose)"
            guidance = "This is a test indicator from a verified Nick intelligence bundle. No action is required."
            return
        }
        switch event.decision {
        case .observed:
            let classification = event.reason == NetworkObservationReason.knownThreat.rawValue
                ? "a known dangerous destination"
                : "a destination flagged as \(event.reasonTitle.lowercased())"
            explanation = "\(appName) tried to connect to \(event.host), \(classification). Nick recorded the attempt; it did not block it.\(purpose)"
            guidance = "If you expected this attempt, no action is required. Allow this domain only to stop warnings for this destination."
        case .blocked:
            explanation = "Nick blocked \(appName) from connecting to this \(destinationLabel.lowercased()) because \(event.reasonTitle.lowercased()).\(purpose)"
            guidance = "Review the app and destination first. Allow this destination for the narrowest exception, or allow the app only if you trust all of its network activity."
        }
    }

    static func displayName(for identifier: String?) -> String {
        guard let identifier, !identifier.isEmpty else { return "An unidentified process" }
        let knownNames: [String: String] = [
            "com.apple.rapportd": "Apple Continuity",
            "com.apple.syncservices.applemobiledevicehelper": "Apple device sync",
            "com.apple.controlcenter": "Control Center",
            "com.apple.coredevice.remotepairingd": "Apple device pairing",
            "com.apple.usbmuxd": "Apple USB device service",
            "com.apple.remoted": "Apple remote services",
            "com.apple.ampdevicediscoveryagent": "Apple device discovery",
            "com.apple.mdnsresponder": "macOS network discovery",
            "com.spotify.client.helper": "Spotify",
            "com.spotify.client": "Spotify",
            "com.openai.codex.helper": "Codex",
        ]
        if let name = knownNames[identifier.lowercased()] { return name }

        let component = identifier.split(separator: ".").last.map(String.init) ?? identifier
        let spaced = component
            .replacingOccurrences(of: "-", with: " ")
            .replacingOccurrences(of: "_", with: " ")
        return spaced.isEmpty ? identifier : spaced
    }

    static func destinationKind(for rawHost: String) -> DestinationKind {
        let host = rawHost.lowercased().split(separator: "%", maxSplits: 1)
            .first.map(String.init) ?? rawHost.lowercased()
        if host.contains(":") {
            return host.hasPrefix("fe8") || host.hasPrefix("fe9")
                || host.hasPrefix("fea") || host.hasPrefix("feb")
                ? .localDevice
                : (host.hasPrefix("fc") || host.hasPrefix("fd")
                    ? .localNetworkAddress
                    : .internetAddress)
        }

        let octets = host.split(separator: ".").compactMap { Int($0) }
        if octets.count == 4 {
            if octets[0] == 10
                || (octets[0] == 172 && (16...31).contains(octets[1]))
                || (octets[0] == 192 && octets[1] == 168)
                || octets[0] == 127
                || octets[3] == 255 {
                return .localNetworkAddress
            }
            return .internetAddress
        }
        return .website
    }

    static func isExpectedLocalDiscovery(host: String, port: Int) -> Bool {
        guard [.localDevice, .localNetworkAddress].contains(destinationKind(for: host)) else {
            return false
        }
        return [1900, 5353, 5355, 8009, 62078].contains(port)
    }

    private static func destinationLabel(for kind: DestinationKind) -> String {
        switch kind {
        case .website: return "Website"
        case .localDevice: return "Nearby device"
        case .localNetworkAddress: return "Local network address"
        case .internetAddress: return "Internet address"
        }
    }

    private static func portPurpose(for port: Int?) -> String? {
        switch port {
        case 80: return "port 80, the standard web port"
        case 443: return "port 443, the standard encrypted web port"
        case 8080, 8443: return "an alternate port commonly used by web services"
        case 5353: return "port 5353, commonly used for local device discovery (mDNS)"
        case 62078: return "port 62078, commonly used for Apple device pairing and sync"
        case 8009: return "port 8009, commonly used for local media or casting control"
        case .some(let port): return "port \(port), which is outside common web ports"
        case nil: return nil
        }
    }
}

enum NetworkProtectionSharedStore {
    static let systemSupportDirectory = URL(
        fileURLWithPath: "/Library/Application Support/com.ehsanazish.nick",
        isDirectory: true
    )
    static let eventsFileName = "network-block-events.json"
    static let signedRulesFileName = "network-rules-v1.json"
    static let signedRulesVersionFileName = "network-rules-version"
    static let threatIntelligenceDirectoryName = "threat-intelligence"
    static let healthFileName = "network-filter-health.json"
    static let maximumEventCount = 500

    static func eventsURL(fileManager: FileManager = .default) -> URL? {
        systemSupportDirectory.appendingPathComponent(eventsFileName)
    }

    static func signedRulesURL(fileManager: FileManager = .default) -> URL? {
        systemSupportDirectory.appendingPathComponent(signedRulesFileName)
    }

    static func signedRulesVersionURL(fileManager: FileManager = .default) -> URL? {
        systemSupportDirectory.appendingPathComponent(signedRulesVersionFileName)
    }

    static func threatIntelligenceDirectory(fileManager _: FileManager = .default) -> URL {
        systemSupportDirectory.appendingPathComponent(
            threatIntelligenceDirectoryName,
            isDirectory: true
        )
    }

    static func healthURL(fileManager: FileManager = .default) -> URL? {
        systemSupportDirectory.appendingPathComponent(healthFileName)
    }

    static func hasCurrentHealth(
        fileManager: FileManager = .default,
        now: TimeInterval = Date().timeIntervalSince1970,
        expectedProviderVersion: String? = nil
    ) -> Bool {
        guard
            let url = healthURL(fileManager: fileManager),
            let data = fileManager.contents(atPath: url.path),
            let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else {
            return false
        }
        return isCurrentHealth(
            object,
            now: now,
            expectedProviderVersion: expectedProviderVersion
        )
    }

    /// Returns the provider-authored health timestamp only when the complete
    /// record passes the same freshness and fail-open checks used by the app.
    static func currentHealthDate(
        fileManager: FileManager = .default,
        now: TimeInterval = Date().timeIntervalSince1970,
        expectedProviderVersion: String? = nil
    ) -> Date? {
        guard
            let url = healthURL(fileManager: fileManager),
            let data = fileManager.contents(atPath: url.path),
            let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
            isCurrentHealth(
                object,
                now: now,
                expectedProviderVersion: expectedProviderVersion
            ),
            let updatedAt = object["updatedAt"] as? TimeInterval
        else {
            return nil
        }
        return Date(timeIntervalSince1970: updatedAt)
    }

    static func isCurrentHealth(
        _ object: [String: Any],
        now: TimeInterval,
        expectedProviderVersion: String? = nil
    ) -> Bool {
        guard
            object["active"] as? Bool == true,
            object["configurationVersion"] as? Int
                == NetworkProtectionConfiguration.configurationVersion,
            object["failOpen"] as? Bool == true,
            let updatedAt = object["updatedAt"] as? TimeInterval
        else {
            return false
        }
        if let expectedProviderVersion,
           object["version"] as? String != expectedProviderVersion {
            return false
        }
        let age = now - updatedAt
        return age >= 0 && age <= 30
    }

    static func providerVersion(fileManager: FileManager = .default) -> String? {
        guard
            let url = healthURL(fileManager: fileManager),
            let data = fileManager.contents(atPath: url.path),
            let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else {
            return nil
        }
        return object["version"] as? String
    }

    static func bundledProviderVersion(in hostBundle: Bundle = .main) -> String? {
        if hostBundle.bundleIdentifier == "com.ehsanazish.nick.NickNetFilter" {
            return hostBundle.object(forInfoDictionaryKey: kCFBundleVersionKey as String) as? String
        }
        let extensionURL = hostBundle.bundleURL
            .appendingPathComponent("Contents/Library/SystemExtensions")
            .appendingPathComponent("com.ehsanazish.nick.NickNetFilter.systemextension")
        return Bundle(url: extensionURL)?
            .object(forInfoDictionaryKey: kCFBundleVersionKey as String) as? String
    }
}

enum NetworkRuleVersionPolicy {
    static func accepts(candidateVersion: Int, highestAcceptedVersion: Int?) -> Bool {
        guard candidateVersion > 0 else { return false }
        guard let highestAcceptedVersion else { return true }
        return candidateVersion >= highestAcceptedVersion
    }
}

/// One writer in NickNetFilter; readers in the app replay the bounded journal.
/// Flow decisions never wait for this store (the provider uses eventWriteQueue).
final class NetworkBlockEventStore: @unchecked Sendable {
    private let lock = NSLock()
    private let url: URL?
    private let writeObserver: ((Int) -> Void)?
    private let maximumJournalBytes: Int
    private var cached: [NetworkBlockEvent]?
    private var tailChecked = false

    init(url: URL? = NetworkProtectionSharedStore.eventsURL(),
         maximumJournalBytes: Int = 1_024 * 1_024,
         writeObserver: ((Int) -> Void)? = nil) {
        self.url = url
        self.maximumJournalBytes = maximumJournalBytes
        self.writeObserver = writeObserver
    }

    static func readEvents(at url: URL) -> [NetworkBlockEvent] {
        readValidatedEvents(at: url) ?? []
    }

    static func readValidatedEvents(at url: URL) -> [NetworkBlockEvent]? {
        // Read the journal first: if a checkpoint replaces the snapshot while
        // reading, it already contains these records. UUID dedup makes that safe.
        let journalURL = URL(fileURLWithPath: url.path + ".journal")
        let journalData = try? Data(contentsOf: journalURL)
        let snapshotData = try? Data(contentsOf: url)
        guard journalData != nil || snapshotData != nil else { return nil }
        var events: [NetworkBlockEvent] = []
        if let snapshotData {
            guard let decoded = try? JSONDecoder().decode([NetworkBlockEvent].self, from: snapshotData) else { return nil }
            events = decoded
        } else if FileManager.default.fileExists(atPath: url.path) { return nil }
        if journalData == nil, FileManager.default.fileExists(atPath: journalURL.path) { return nil }
        let journal = journalData ?? Data()
        var seen = Set(events.map(\.id))
        for line in journal.split(separator: 0x0A) {
            guard let event = try? JSONDecoder().decode(NetworkBlockEvent.self, from: Data(line)),
                  seen.insert(event.id).inserted else { continue }
            events.append(event)
        }
        // A truncated/corrupt journal alone is not a valid empty bootstrap.
        if snapshotData == nil, !journal.isEmpty, events.isEmpty { return nil }
        return Array(events.sorted { $0.timestamp > $1.timestamp }
            .prefix(NetworkProtectionSharedStore.maximumEventCount))
    }

    func append(_ event: NetworkBlockEvent) {
        guard let url else { return }
        lock.withLock {
            do {
                let journalURL = URL(fileURLWithPath: url.path + ".journal")
                var events = cached ?? Self.readEvents(at: url)
                guard !events.contains(where: { $0.id == event.id }) else { return }
                try FileManager.default.createDirectory(at: url.deletingLastPathComponent(),
                    withIntermediateDirectories: true, attributes: [.posixPermissions: 0o755])
                if !FileManager.default.fileExists(atPath: journalURL.path) {
                    FileManager.default.createFile(atPath: journalURL.path, contents: nil,
                                                  attributes: [.posixPermissions: 0o644])
                }
                let handle = try FileHandle(forWritingTo: journalURL)
                defer { try? handle.close() }
                if !tailChecked {
                    if let data = try? Data(contentsOf: journalURL), let last = data.last, last != 0x0A {
                        let end = data.lastIndex(of: 0x0A).map { $0 + 1 } ?? 0
                        if (try? JSONSerialization.jsonObject(with: Data(data.suffix(from: end)))) != nil {
                            try handle.seekToEnd()
                            try handle.write(contentsOf: Data([0x0A]))
                        } else {
                            try handle.truncate(atOffset: UInt64(end))
                        }
                    }
                    tailChecked = true
                }
                var line = try JSONEncoder().encode(event)
                line.append(0x0A)
                try handle.seekToEnd()
                try handle.write(contentsOf: line)
                try handle.synchronize()
                writeObserver?(line.count)
                events.insert(event, at: 0)
                events = Array(events.prefix(NetworkProtectionSharedStore.maximumEventCount))
                cached = events
                let bytes = try handle.offset()
                if bytes >= maximumJournalBytes {
                    let checkpoint = try JSONEncoder().encode(events)
                    try checkpoint.write(to: url, options: .atomic)
                    try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: url.path)
                    let snapshotHandle = try FileHandle(forWritingTo: url)
                    try snapshotHandle.synchronize()
                    try snapshotHandle.close()
                    writeObserver?(checkpoint.count)
                    try handle.truncate(atOffset: 0)
                    try handle.synchronize()
                }
            } catch {
                tailChecked = false
                // Observability failure never changes the provider's verdict.
            }
        }
    }
}

/// Fixed-capacity telemetry debounce. Unique-host churn cannot grow its memory.
/// Eviction only allows an observation to be recorded again; it never exempts a
/// flow from inspection or changes the network verdict.
final class NetworkObservationThrottle: @unchecked Sendable {
    private let lock = NSLock()
    private var timestamps: [String: Date] = [:]
    private var keys: [String?]
    private var nextSlot = 0

    init(capacity: Int = 1_024) { keys = Array(repeating: nil, count: max(1, capacity)) }

    var retainedCount: Int { lock.withLock { timestamps.count } }

    func shouldRecord(key: String, now: Date, interval: TimeInterval) -> Bool {
        lock.withLock {
            if let previous = timestamps[key], now.timeIntervalSince(previous) < interval { return false }
            if timestamps[key] == nil {
                if let evicted = keys[nextSlot] { timestamps.removeValue(forKey: evicted) }
                keys[nextSlot] = key
                nextSlot = (nextSlot + 1) % keys.count
            }
            timestamps[key] = now
            return true
        }
    }
}
