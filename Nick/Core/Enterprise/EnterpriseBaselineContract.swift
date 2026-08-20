import Foundation

/// Metadata-only contract for a future signed-baseline adapter. Nick does not
/// execute baseline content or translate these results into compliance claims.
struct EnterpriseBaselineManifest: Codable, Equatable, Sendable {
    static let currentSchemaVersion = 1

    let schemaVersion: Int
    let baselineIdentifier: String
    let baselineVersion: String
    let publisher: String
    let platform: String
    let minimumOSVersion: String?
    let maximumOSVersion: String?
    let issuedAt: Date
    let expiresAt: Date?
    let contentSHA256: String
    let signingKeyIdentifier: String
    let assertions: [EnterpriseRuntimeAssertion]

    func validate(now: Date = .now) throws {
        guard schemaVersion == Self.currentSchemaVersion else {
            throw EnterpriseBaselineError.unsupportedSchema(schemaVersion)
        }
        guard platform == "macOS" else { throw EnterpriseBaselineError.unsupportedPlatform }
        guard contentSHA256.count == 64,
              contentSHA256.allSatisfy({ $0.isHexDigit }) else {
            throw EnterpriseBaselineError.invalidChecksum
        }
        if let expiresAt, expiresAt <= now { throw EnterpriseBaselineError.expired }
        let identifiers = assertions.map(\.identifier)
        guard Set(identifiers).count == identifiers.count else {
            throw EnterpriseBaselineError.duplicateAssertionIdentifier
        }
    }
}

struct EnterpriseRuntimeAssertion: Codable, Equatable, Identifiable, Sendable {
    enum Kind: String, Codable, CaseIterable, Sendable {
        case processPresent
        case processAbsent
        case persistencePresent
        case persistenceAbsent
        case listenerPresent
        case listenerAbsent
        case extensionActive
        case extensionInactive
        case sensorResponsive
    }

    let identifier: String
    let ruleIdentifier: String
    let kind: Kind
    let subject: String
    let explanation: String

    var id: String { identifier }
}

enum EnterpriseAssertionResult: String, Codable, Sendable {
    case matches
    case contradicts
    case cannotVerify
}

struct EnterpriseAssertionEvaluation: Codable, Equatable, Identifiable, Sendable {
    let assertionIdentifier: String
    let ruleIdentifier: String
    let result: EnterpriseAssertionResult
    let explanation: String
    let evidenceReferences: [String]
    let limitation: String?

    var id: String { assertionIdentifier }
}

enum EnterpriseBaselineError: Error, Equatable {
    case unsupportedSchema(Int)
    case unsupportedPlatform
    case invalidChecksum
    case expired
    case duplicateAssertionIdentifier
}
