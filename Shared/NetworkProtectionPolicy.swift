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
    static let configurationVersion = 5

    var protectionEnabled: Bool
    var blockingEnabled: Bool
    var allowedDomains: Set<String>
    var allowedAppIdentifiers: Set<String>
    var temporaryAllowedDomains: [String: TimeInterval]
    var temporaryAllowedAppIdentifiers: [String: TimeInterval]

    init(
        protectionEnabled: Bool = true,
        blockingEnabled: Bool = false,
        allowedDomains: Set<String> = [],
        allowedAppIdentifiers: Set<String> = [],
        temporaryAllowedDomains: [String: TimeInterval] = [:],
        temporaryAllowedAppIdentifiers: [String: TimeInterval] = [:]
    ) {
        self.protectionEnabled = protectionEnabled
        self.blockingEnabled = blockingEnabled
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
            blockingEnabled: hasCurrentVersion
                && (vendorConfiguration?["blockingEnabled"] as? Bool == true),
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
            "blockingEnabled": blockingEnabled,
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
        if isBlocklisted(host) {
            return configuration.blockingEnabled
                ? .block(.blocklist)
                : .observe(.knownThreat)
        }
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

    init(
        id: UUID = UUID(),
        timestamp: Date = Date(),
        host: String,
        appIdentifier: String?,
        decision: NetworkEventDecision,
        reason: String,
        reasonTitle: String,
        port: Int? = nil
    ) {
        self.id = id
        self.timestamp = timestamp
        self.host = host
        self.appIdentifier = appIdentifier
        self.decision = decision
        self.reason = reason
        self.reasonTitle = reasonTitle
        self.port = port
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
    }
}

enum NetworkProtectionSharedStore {
    static let systemSupportDirectory = URL(
        fileURLWithPath: "/Library/Application Support/com.ehsanazish.nick",
        isDirectory: true
    )
    static let eventsFileName = "network-block-events.json"
    static let signedRulesFileName = "network-rules-v1.json"
    static let healthFileName = "network-filter-health.json"
    static let maximumEventCount = 500

    static func eventsURL(fileManager: FileManager = .default) -> URL? {
        systemSupportDirectory.appendingPathComponent(eventsFileName)
    }

    static func signedRulesURL(fileManager: FileManager = .default) -> URL? {
        systemSupportDirectory.appendingPathComponent(signedRulesFileName)
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
