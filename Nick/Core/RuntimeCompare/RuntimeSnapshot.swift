import Foundation

enum RuntimeScenario: String, Codable, CaseIterable, Identifiable, Sendable {
    case securityOrMDM
    case vpnOrNetwork
    case appChange
    case custom

    var id: String { rawValue }

    var title: String {
        switch self {
        case .securityOrMDM: "Security or MDM change"
        case .vpnOrNetwork: "VPN or network problem"
        case .appChange: "App installation or removal"
        case .custom: "Custom comparison"
        }
    }

    var detail: String {
        switch self {
        case .securityOrMDM: "Compare runtime behavior around management or security changes."
        case .vpnOrNetwork: "Emphasize extensions, listeners, and outbound connections."
        case .appChange: "See processes, background items, listeners, and extensions that changed."
        case .custom: "Capture and label any before-and-after runtime state."
        }
    }
}

enum RuntimeProviderState: String, Codable, Sendable {
    case available
    case partial
    case unavailable
}

struct RuntimeProviderHealth: Codable, Equatable, Identifiable, Sendable {
    let provider: String
    let state: RuntimeProviderState
    let message: String?
    let recordCount: Int
    var id: String { provider }
}

struct RuntimeProcessRecord: Codable, Equatable, Identifiable, Sendable {
    let id: String
    let pid: Int32
    let name: String
    let path: String
    let parentPID: Int32
    let parentName: String?
    let user: String?
    let startTime: Date?
    let signingState: String
    let teamID: String?

    var stableKey: String {
        let normalizedPath = RuntimeIdentity.normalizePath(path)
        if let teamID, !teamID.isEmpty, !normalizedPath.isEmpty {
            return "team:\(teamID.lowercased())|path:\(normalizedPath)"
        }
        if !normalizedPath.isEmpty { return "path:\(normalizedPath)" }
        return "name:\(name.lowercased())"
    }
}

struct RuntimeListenerRecord: Codable, Equatable, Identifiable, Sendable {
    let id: String
    let transport: String
    let localAddress: String
    let localPort: Int
    let ownerName: String
    let ownerPath: String?
    let pid: Int32

    var stableKey: String {
        "\(transport.lowercased())|\(RuntimeIdentity.addressScope(localAddress))|\(localPort)|\(RuntimeIdentity.owner(name: ownerName, path: ownerPath))"
    }
}

struct RuntimeConnectionRecord: Codable, Equatable, Identifiable, Sendable {
    let id: String
    let transport: String
    let remoteAddress: String
    let remotePort: Int
    let ownerName: String
    let ownerPath: String?
    let firstSeen: Date
    let lastSeen: Date
    let observationCount: Int

    var stableKey: String {
        "\(RuntimeIdentity.owner(name: ownerName, path: ownerPath))|\(transport.lowercased())|\(RuntimeIdentity.normalizeAddress(remoteAddress))|\(remotePort)"
    }
}

struct RuntimePersistenceRecord: Codable, Equatable, Identifiable, Sendable {
    let id: String
    let type: String
    let scope: String
    let name: String
    let path: String
    let executablePath: String?
    let isEnabled: Bool
    let signingState: String?
    let teamID: String?
    let lastModified: Date?

    var stableKey: String {
        "\(type)|\(scope)|\(RuntimeIdentity.normalizePath(path))|\(name.lowercased())"
    }
}

enum RuntimeExtensionCategory: String, Codable, Sendable {
    case endpointSecurity
    case network
    case driver
    case other
}

struct RuntimeExtensionRecord: Codable, Equatable, Identifiable, Sendable {
    let id: String
    let category: RuntimeExtensionCategory
    let bundleIdentifier: String
    let teamIdentifier: String?
    let version: String?
    let isActivated: Bool
    let isEnabled: Bool
    let stateDescription: String

    var stableKey: String {
        "\(category.rawValue)|\(teamIdentifier?.lowercased() ?? "unknown")|\(bundleIdentifier.lowercased())"
    }
}

struct RuntimeSensorHealth: Codable, Equatable, Sendable {
    let endpointSecurityResponding: Bool
    let networkFilterResponding: Bool
    let networkFilterState: String
}

struct RuntimeCaptureConfiguration: Codable, Equatable, Sendable {
    let requestedObservationSeconds: Int
    let sampleIntervalSeconds: Int

    static let standard = RuntimeCaptureConfiguration(
        requestedObservationSeconds: 30,
        sampleIntervalSeconds: 5
    )
}

struct RuntimeSnapshot: Codable, Equatable, Identifiable, Sendable {
    static let currentSchemaVersion = 1

    let id: UUID
    let schemaVersion: Int
    let label: String
    let scenario: RuntimeScenario
    let startedAt: Date
    let completedAt: Date
    let nickVersion: String
    let macOSVersion: String
    let architecture: String
    let deviceToken: String
    let bootSessionIdentifier: String
    let configuration: RuntimeCaptureConfiguration
    let actualObservationSeconds: Int
    let processes: [RuntimeProcessRecord]
    let listeners: [RuntimeListenerRecord]
    let connections: [RuntimeConnectionRecord]
    let persistence: [RuntimePersistenceRecord]
    let extensions: [RuntimeExtensionRecord]
    let sensorHealth: RuntimeSensorHealth
    let providerHealth: [RuntimeProviderHealth]

    var isPartial: Bool {
        providerHealth.contains { $0.state != .available }
    }
}

enum RuntimeComparisonState: String, Codable, Sendable {
    case awaitingBaseline
    case awaitingFollowUp
    case completed
}

struct RuntimeComparison: Codable, Equatable, Identifiable, Sendable {
    let id: UUID
    var label: String
    let scenario: RuntimeScenario
    let createdAt: Date
    var updatedAt: Date
    var state: RuntimeComparisonState
    var baseline: RuntimeSnapshot?
    var followUp: RuntimeSnapshot?
    var findings: [RuntimeFinding]
}

enum RuntimeFindingCategory: String, Codable, CaseIterable, Sendable {
    case process = "Processes"
    case listener = "Listening Ports"
    case connection = "Connections"
    case persistence = "Persistence"
    case systemExtension = "System Extensions"
    case sensor = "Sensor Health"
}

enum RuntimeChangeKind: String, Codable, Sendable {
    case added
    case removed
    case changed
    case quality
}

enum RuntimeEvidenceLevel: String, Codable, Sendable {
    case observed
    case inference
    case cannotConfirm
}

enum RuntimeAttention: String, Codable, Comparable, Sendable {
    case informational
    case review
    case important

    static func < (lhs: RuntimeAttention, rhs: RuntimeAttention) -> Bool {
        let order: [RuntimeAttention] = [.informational, .review, .important]
        return order.firstIndex(of: lhs)! < order.firstIndex(of: rhs)!
    }
}

struct RuntimeFinding: Codable, Equatable, Identifiable, Sendable {
    let id: String
    let category: RuntimeFindingCategory
    let change: RuntimeChangeKind
    let evidence: RuntimeEvidenceLevel
    let attention: RuntimeAttention
    let title: String
    let explanation: String
    let limitation: String?
    let sourceReferences: [String]
}

enum RuntimeIdentity {
    static func normalizePath(_ path: String) -> String {
        let trimmed = path.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return "" }
        return URL(fileURLWithPath: trimmed).standardizedFileURL.path.lowercased()
    }

    static func owner(name: String, path: String?) -> String {
        if let path, !normalizePath(path).isEmpty { return "path:\(normalizePath(path))" }
        return "name:\(name.lowercased())"
    }

    static func normalizeAddress(_ address: String) -> String {
        address.trimmingCharacters(in: CharacterSet(charactersIn: "[]")).lowercased()
    }

    static func addressScope(_ address: String) -> String {
        switch normalizeAddress(address) {
        case "*", "0.0.0.0", "::": "wildcard"
        case "127.0.0.1", "::1", "localhost": "loopback"
        default: "specific:\(normalizeAddress(address))"
        }
    }
}

extension SigningStatus {
    var runtimeTeamID: String? {
        if case .signed(let teamID) = self { return teamID }
        return nil
    }
}
