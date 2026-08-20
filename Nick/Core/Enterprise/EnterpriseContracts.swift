import Foundation

/// Versioned settings accepted from an organization-managed preferences domain.
/// Parsing stays independent from `UserDefaults` so local preferences cannot
/// masquerade as policy delivered by device management.
struct EnterpriseManagedConfiguration: Codable, Equatable, Sendable {
    static let currentSchemaVersion = 1

    enum ExportFormat: String, Codable, CaseIterable, Sendable {
        case json
        case jsonLines
        case keyValue
        case cef
        case markdown
    }

    enum LogLevel: String, Codable, CaseIterable, Sendable {
        case error
        case warning
        case info
        case debug
    }

    let schemaVersion: Int
    let organizationName: String?
    let logLevel: LogLevel
    let retentionDays: Int
    let exportDirectory: String?
    let exportFormats: [ExportFormat]
    let captureDurationSeconds: Int
    let sanitizeExports: Bool
    let showUserInterface: Bool

    static let defaults = EnterpriseManagedConfiguration(
        schemaVersion: currentSchemaVersion,
        organizationName: nil,
        logLevel: .info,
        retentionDays: 14,
        exportDirectory: nil,
        exportFormats: [.json, .markdown],
        captureDurationSeconds: 30,
        sanitizeExports: true,
        showUserInterface: true
    )

    static func decodeManagedValues(_ values: [String: Any]) throws -> Self {
        var normalized = values
        normalized["schemaVersion"] = values["schemaVersion"] ?? currentSchemaVersion
        let data = try JSONSerialization.data(withJSONObject: normalized)
        let decoded = try JSONDecoder().decode(Self.self, from: data)
        try decoded.validate()
        return decoded
    }

    func validate() throws {
        guard schemaVersion == Self.currentSchemaVersion else {
            throw EnterpriseContractError.unsupportedSchema(schemaVersion)
        }
        guard (1...90).contains(retentionDays) else {
            throw EnterpriseContractError.invalidRetentionDays
        }
        guard (5...300).contains(captureDurationSeconds) else {
            throw EnterpriseContractError.invalidCaptureDuration
        }
        guard !exportFormats.isEmpty else {
            throw EnterpriseContractError.missingExportFormat
        }
        if let exportDirectory, !exportDirectory.hasPrefix("/") {
            throw EnterpriseContractError.exportDirectoryMustBeAbsolute
        }
    }
}

enum EnterpriseComponentState: String, Codable, Equatable, Sendable {
    case available
    case degraded
    case unavailable
    case notConfigured
    case cannotVerify
}

struct EnterpriseComponentHealth: Codable, Equatable, Identifiable, Sendable {
    let identifier: String
    let displayName: String
    let state: EnterpriseComponentState
    let installed: Bool?
    let enabled: Bool?
    let responsive: Bool?
    let version: String?
    let lastSuccessfulEventAt: Date?
    let errorCode: String?
    let message: String?

    var id: String { identifier }
}

struct EnterpriseHealthReport: Codable, Equatable, Sendable {
    static let currentSchemaVersion = 1

    let schemaVersion: Int
    let generatedAt: Date
    let nickVersion: String
    let nickBuild: String
    let macOSVersion: String
    let architecture: String
    let managedConfigurationDetected: Bool
    let organizationName: String?
    let components: [EnterpriseComponentHealth]
    let limitations: [String]

    func validate() throws {
        guard schemaVersion == Self.currentSchemaVersion else {
            throw EnterpriseContractError.unsupportedSchema(schemaVersion)
        }
        let identifiers = components.map(\.identifier)
        guard Set(identifiers).count == identifiers.count else {
            throw EnterpriseContractError.duplicateComponentIdentifier
        }
    }
}

struct EnterpriseDiagnosticArtifact: Codable, Equatable, Identifiable, Sendable {
    let relativePath: String
    let mediaType: String
    let byteCount: Int
    let sha256: String

    var id: String { relativePath }
}

struct EnterpriseDiagnosticManifest: Codable, Equatable, Sendable {
    static let currentSchemaVersion = 1

    let schemaVersion: Int
    let generatedAt: Date
    let nickVersion: String
    let sanitized: Bool
    let healthReportPath: String
    let artifacts: [EnterpriseDiagnosticArtifact]
    let limitations: [String]

    func validate() throws {
        guard schemaVersion == Self.currentSchemaVersion else {
            throw EnterpriseContractError.unsupportedSchema(schemaVersion)
        }
        guard sanitized else { throw EnterpriseContractError.unsanitizedDiagnosticBundle }
        guard !healthReportPath.hasPrefix("/"), !healthReportPath.contains("..") else {
            throw EnterpriseContractError.invalidArtifactPath
        }
        let paths = artifacts.map(\.relativePath)
        guard Set(paths).count == paths.count else {
            throw EnterpriseContractError.duplicateArtifactPath
        }
        for artifact in artifacts {
            guard !artifact.relativePath.hasPrefix("/"),
                  !artifact.relativePath.contains("..") else {
                throw EnterpriseContractError.invalidArtifactPath
            }
            guard artifact.byteCount >= 0,
                  artifact.sha256.count == 64,
                  artifact.sha256.allSatisfy({ $0.isHexDigit }) else {
                throw EnterpriseContractError.invalidArtifactMetadata
            }
        }
    }
}

enum EnterpriseContractError: Error, Equatable, Sendable {
    case unsupportedSchema(Int)
    case invalidRetentionDays
    case invalidCaptureDuration
    case missingExportFormat
    case exportDirectoryMustBeAbsolute
    case duplicateComponentIdentifier
    case inconsistentCLIResult
    case unsanitizedDiagnosticBundle
    case invalidArtifactPath
    case duplicateArtifactPath
    case invalidArtifactMetadata
}

/// Stable process exit codes reserved for the future `nickctl` interface.
/// Existing meanings must never be reassigned after a public pilot ships.
enum NickCLIExitCode: Int32, Codable, CaseIterable, Sendable {
    case success = 0
    case invalidArguments = 2
    case configurationInvalid = 10
    case visibilityLimited = 20
    case componentDegraded = 21
    case componentUnavailable = 22
    case operationFailed = 30
    case outputFailed = 31
    case unsupportedSchema = 40
}

enum NickEnterpriseErrorCode: String, Codable, CaseIterable, Sendable {
    case invalidArguments = "NICK-CLI-001"
    case invalidManagedConfiguration = "NICK-CONFIG-001"
    case unsupportedSchema = "NICK-SCHEMA-001"
    case visibilityLimited = "NICK-VISIBILITY-001"
    case endpointUnresponsive = "NICK-ENDPOINT-001"
    case networkFilterUnresponsive = "NICK-NETWORK-001"
    case networkFilterConflict = "NICK-NETWORK-002"
    case diagnosticCaptureFailed = "NICK-DIAGNOSTIC-001"
    case outputWriteFailed = "NICK-OUTPUT-001"
}

enum NickCLICommand: String, Codable, CaseIterable, Sendable {
    case status
    case diagnostics
    case compare
}

struct NickCLIError: Codable, Equatable, Sendable {
    let code: NickEnterpriseErrorCode
    let message: String
    let recoverySuggestion: String?
}

struct NickCLIEnvelope<Payload: Codable & Equatable & Sendable>: Codable, Equatable, Sendable {
    static var currentSchemaVersion: Int { 1 }

    let schemaVersion: Int
    let command: NickCLICommand
    let generatedAt: Date
    let success: Bool
    let exitCode: NickCLIExitCode
    let payload: Payload?
    let errors: [NickCLIError]

    func validate() throws {
        guard schemaVersion == Self.currentSchemaVersion else {
            throw EnterpriseContractError.unsupportedSchema(schemaVersion)
        }
        guard success == (exitCode == .success), success == errors.isEmpty else {
            throw EnterpriseContractError.inconsistentCLIResult
        }
    }
}
