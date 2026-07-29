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

enum NetworkPolicyVerdict: Equatable, Sendable {
    case allow
    case block(NetworkBlockReason)
}

struct NetworkProtectionConfiguration: Equatable, Sendable {
    static let configurationVersion = 3

    var protectionEnabled: Bool
    var allowedDomains: Set<String>
    var allowedAppIdentifiers: Set<String>

    init(
        protectionEnabled: Bool = true,
        allowedDomains: Set<String> = [],
        allowedAppIdentifiers: Set<String> = []
    ) {
        self.protectionEnabled = protectionEnabled
        self.allowedDomains = Set(allowedDomains.compactMap(Self.normalizedDomain))
        self.allowedAppIdentifiers = Set(
            allowedAppIdentifiers.map { $0.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() }
                .filter { !$0.isEmpty }
        )
    }

    init(vendorConfiguration: [String: Any]?) {
        self.init(
            protectionEnabled: vendorConfiguration?["protectionEnabled"] as? Bool ?? true,
            allowedDomains: Set(vendorConfiguration?["allowedDomains"] as? [String] ?? []),
            allowedAppIdentifiers: Set(vendorConfiguration?["allowedAppIdentifiers"] as? [String] ?? [])
        )
    }

    var vendorConfiguration: [String: Any] {
        [
            "configurationVersion": Self.configurationVersion,
            "protectionEnabled": protectionEnabled,
            "allowedDomains": allowedDomains.sorted(),
            "allowedAppIdentifiers": allowedAppIdentifiers.sorted(),
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
           configuration.allowedAppIdentifiers.contains(appIdentifier) {
            return .allow
        }
        if configuration.allowedDomains.contains(where: { allowed in
            host == allowed || host.hasSuffix(".\(allowed)")
        }) {
            return .allow
        }
        if isBlocklisted(host) { return .block(.blocklist) }
        if isScam(host) { return .block(.scamGuardian) }
        return .allow
    }
}

struct NetworkBlockEvent: Codable, Identifiable, Hashable, Sendable {
    let id: UUID
    let timestamp: Date
    let host: String
    let appIdentifier: String?
    let reason: NetworkBlockReason

    init(
        id: UUID = UUID(),
        timestamp: Date = Date(),
        host: String,
        appIdentifier: String?,
        reason: NetworkBlockReason
    ) {
        self.id = id
        self.timestamp = timestamp
        self.host = host
        self.appIdentifier = appIdentifier
        self.reason = reason
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
        now: TimeInterval = Date().timeIntervalSince1970
    ) -> Bool {
        guard
            let url = healthURL(fileManager: fileManager),
            let data = fileManager.contents(atPath: url.path),
            let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else {
            return false
        }
        return isCurrentHealth(object, now: now)
    }

    static func isCurrentHealth(
        _ object: [String: Any],
        now: TimeInterval
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
        let age = now - updatedAt
        return age >= 0 && age <= 30
    }
}
