import CryptoKit
import Foundation

enum ThreatIntelligenceBundleTrustAnchor {
    /// Inactive production anchor. Online bundle updates remain disabled until
    /// the separately held signing key and hosting are approved and enabled.
    static let productionPublicKey = Data(
        base64Encoded: "XIYgv92Pzh9CcUrooo2psW5wly507Oxv6oN0a2dbb/0="
    )!

    static var updatesEnabled: Bool {
        Bundle.main.object(forInfoDictionaryKey: "NickThreatBundleUpdatesEnabled") as? Bool == true
    }

    static let productionDirectory = URL(
        fileURLWithPath: "/Library/Application Support/com.ehsanazish.nick/threat-intelligence",
        isDirectory: true
    )
}

enum ThreatBundleUpdateEndpointPolicy {
    static let maximumDownloadBytes = 10 * 1_024 * 1_024

    static func allows(_ url: URL) -> Bool {
        url.scheme?.lowercased() == "https"
            && url.host?.lowercased() == "3nsofts.com"
            && url.path == "/nick/threat-intelligence/current.json"
            && url.user == nil
            && url.password == nil
            && url.port == nil
    }
}

struct ThreatIntelligenceBundlePayload: Codable, Equatable, Sendable {
    struct HashEntry: Codable, Equatable, Hashable, Sendable {
        let sha256: String
        let name: String
        let family: String
        let severity: String
    }

    struct Rule: Codable, Equatable, Hashable, Sendable {
        enum Confidence: String, Codable, Sendable { case review, high }
        let identifier: String
        let confidence: Confidence
        let blockable: Bool
    }

    let schemaVersion: Int
    let version: Int
    let issuedAt: Date
    let expiresAt: Date
    let source: String
    let hashes: [HashEntry]
    let domains: [String]
    let ipAddresses: [String]
    let rules: [Rule]
}

struct SignedThreatIntelligenceBundle: Codable, Equatable, Sendable {
    let payload: ThreatIntelligenceBundlePayload
    let signature: Data

    func verifies(publicKey: Data) -> Bool {
        guard let message = try? Self.canonicalEncoder.encode(payload),
              let key = try? Curve25519.Signing.PublicKey(rawRepresentation: publicKey)
        else { return false }
        return key.isValidSignature(signature, for: message)
    }

    static let canonicalEncoder: JSONEncoder = {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        encoder.dateEncodingStrategy = .millisecondsSince1970
        return encoder
    }()
}

enum ThreatIntelligenceBundleValidationError: Error, Equatable {
    case updatesDisabled
    case malformed
    case invalidSignature
    case unsupportedSchema
    case invalidVersion
    case rollback
    case notYetValid
    case expired
    case invalidLifetime
    case invalidEntry
    case gateRejected
}

struct ThreatIntelligenceBundleValidator: Sendable {
    static let supportedSchema = 1
    static let maximumLifetime: TimeInterval = 180 * 24 * 60 * 60

    let publicKey: Data

    func validate(
        _ bundle: SignedThreatIntelligenceBundle,
        now: Date,
        highestAcceptedVersion: Int?
    ) throws -> ThreatIntelligenceBundlePayload {
        let payload = bundle.payload
        guard bundle.verifies(publicKey: publicKey) else {
            throw ThreatIntelligenceBundleValidationError.invalidSignature
        }
        guard payload.schemaVersion == Self.supportedSchema else {
            throw ThreatIntelligenceBundleValidationError.unsupportedSchema
        }
        guard payload.version > 0 else {
            throw ThreatIntelligenceBundleValidationError.invalidVersion
        }
        if let highestAcceptedVersion, payload.version <= highestAcceptedVersion {
            throw ThreatIntelligenceBundleValidationError.rollback
        }
        guard payload.issuedAt <= now else {
            throw ThreatIntelligenceBundleValidationError.notYetValid
        }
        guard payload.expiresAt > now else {
            throw ThreatIntelligenceBundleValidationError.expired
        }
        guard payload.expiresAt.timeIntervalSince(payload.issuedAt) <= Self.maximumLifetime else {
            throw ThreatIntelligenceBundleValidationError.invalidLifetime
        }
        guard Self.entriesAreValid(payload) else {
            throw ThreatIntelligenceBundleValidationError.invalidEntry
        }
        return payload
    }

    private static func entriesAreValid(_ payload: ThreatIntelligenceBundlePayload) -> Bool {
        let hex = CharacterSet(charactersIn: "0123456789abcdef")
        let hashes = payload.hashes.map { $0.sha256.lowercased() }
        guard Set(hashes).count == hashes.count,
              hashes.allSatisfy({ $0.count == 64 && $0.unicodeScalars.allSatisfy(hex.contains) })
        else { return false }

        let domains = payload.domains.map { $0.lowercased() }
        guard Set(domains).count == domains.count,
              domains.allSatisfy({ !$0.isEmpty && !$0.contains("/") && !$0.contains(" ") })
        else { return false }

        let ruleIDs = payload.rules.map(\.identifier)
        guard Set(ruleIDs).count == ruleIDs.count,
              ruleIDs.allSatisfy({ !$0.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty }),
              payload.rules.allSatisfy({ !$0.blockable || $0.confidence == .high })
        else { return false }
        return !payload.source.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }
}

/// Crash-safe promotion for signed intelligence. The current bundle remains
/// untouched unless signature, schema, expiry and the deterministic publish
/// gate all succeed. The previous current bundle becomes last-known-good.
final class SignedThreatIntelligenceBundleStore: @unchecked Sendable {
    struct Provenance: Equatable, Sendable {
        let version: Int
        let source: String
        let issuedAt: Date
        let expiresAt: Date
        let usingLastKnownGood: Bool
    }

    private let directory: URL
    private let validator: ThreatIntelligenceBundleValidator
    private let updatesEnabled: Bool
    private let fileManager: FileManager
    private let now: @Sendable () -> Date
    private let lock = NSLock()

    init(
        directory: URL,
        publicKey: Data,
        updatesEnabled: Bool,
        fileManager: FileManager = .default,
        now: @escaping @Sendable () -> Date = Date.init
    ) {
        self.directory = directory
        self.validator = ThreatIntelligenceBundleValidator(publicKey: publicKey)
        self.updatesEnabled = updatesEnabled
        self.fileManager = fileManager
        self.now = now
    }

    func stageAndPromote(
        _ data: Data,
        publishGate: (ThreatIntelligenceBundlePayload) -> Bool
    ) throws -> Provenance {
        try lock.withLock {
            guard updatesEnabled else { throw ThreatIntelligenceBundleValidationError.updatesDisabled }
            guard let bundle = try? Self.decoder.decode(SignedThreatIntelligenceBundle.self, from: data)
            else { throw ThreatIntelligenceBundleValidationError.malformed }
            let highest = highestAcceptedVersion()
            let payload = try validator.validate(bundle, now: now(), highestAcceptedVersion: highest)
            guard publishGate(payload) else { throw ThreatIntelligenceBundleValidationError.gateRejected }

            try prepareDirectory()
            try data.write(to: stagedURL, options: [.atomic, .completeFileProtection])
            if fileManager.fileExists(atPath: currentURL.path) {
                try? fileManager.removeItem(at: lastKnownGoodURL)
                try fileManager.copyItem(at: currentURL, to: lastKnownGoodURL)
            }
            try? fileManager.removeItem(at: currentURL)
            try fileManager.moveItem(at: stagedURL, to: currentURL)
            try Data(String(payload.version).utf8).write(to: versionURL, options: .atomic)
            return Provenance(
                version: payload.version,
                source: payload.source,
                issuedAt: payload.issuedAt,
                expiresAt: payload.expiresAt,
                usingLastKnownGood: false
            )
        }
    }

    func loadBestAvailable() -> (ThreatIntelligenceBundlePayload, Provenance)? {
        lock.withLock {
            if let result = load(url: currentURL, usingLastKnownGood: false) { return result }
            return load(url: lastKnownGoodURL, usingLastKnownGood: true)
        }
    }

    private func load(
        url: URL,
        usingLastKnownGood: Bool
    ) -> (ThreatIntelligenceBundlePayload, Provenance)? {
        guard let data = fileManager.contents(atPath: url.path),
              let bundle = try? Self.decoder.decode(SignedThreatIntelligenceBundle.self, from: data),
              let payload = try? validator.validate(bundle, now: now(), highestAcceptedVersion: nil)
        else { return nil }
        return (payload, Provenance(
            version: payload.version,
            source: payload.source,
            issuedAt: payload.issuedAt,
            expiresAt: payload.expiresAt,
            usingLastKnownGood: usingLastKnownGood
        ))
    }

    private func highestAcceptedVersion() -> Int? {
        guard let data = fileManager.contents(atPath: versionURL.path),
              let value = String(data: data, encoding: .utf8)
        else { return nil }
        return Int(value.trimmingCharacters(in: .whitespacesAndNewlines))
    }

    private func prepareDirectory() throws {
        try fileManager.createDirectory(
            at: directory,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
    }

    private var currentURL: URL { directory.appendingPathComponent("current.json") }
    private var stagedURL: URL { directory.appendingPathComponent("staged.json") }
    private var lastKnownGoodURL: URL { directory.appendingPathComponent("last-known-good.json") }
    private var versionURL: URL { directory.appendingPathComponent("highest-version") }

    private static let decoder: JSONDecoder = {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .millisecondsSince1970
        return decoder
    }()
}
