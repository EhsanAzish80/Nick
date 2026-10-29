import CryptoKit
import Foundation

enum ThreatIntelligenceBundleTrustAnchor {
    /// Inactive production anchor. Online bundle updates remain disabled until
    /// the separately held signing key and hosting are approved and enabled.
    static let productionPublicKey = Data(
        base64Encoded: "vhmPD4eSgTVFeCc6tR7SZdceirBiJ0n29taAnM/s9m4="
    )!

    /// Build-time capability shared by the app and both system extensions.
    ///
    /// This must not depend on `Bundle.main`: each shipped executable has a
    /// different main bundle, and a host-only Info.plist flag made downloads
    /// succeed in the app while the Endpoint Security extension rejected the
    /// same signed bundle as disabled. The user's persisted automatic-update
    /// preference remains a separate, root-owned runtime setting.
    static let updatesEnabled = true

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

enum ThreatBundleRefreshDecision: Equatable, Sendable {
    case notModified
    case install
    case tooLarge
    case invalidResponse
}

enum ThreatBundleRefreshPolicy {
    static let normalInterval: TimeInterval = 6 * 60 * 60
    static let initialFailureBackoff: TimeInterval = 15 * 60

    static func decision(statusCode: Int, byteCount: Int) -> ThreatBundleRefreshDecision {
        if statusCode == 304 { return .notModified }
        guard statusCode == 200 else { return .invalidResponse }
        guard byteCount <= ThreatBundleUpdateEndpointPolicy.maximumDownloadBytes else {
            return .tooLarge
        }
        return .install
    }

    static func nextDelay(consecutiveFailures: Int) -> TimeInterval {
        guard consecutiveFailures > 0 else { return normalInterval }
        return min(
            normalInterval,
            initialFailureBackoff * pow(2, Double(consecutiveFailures - 1))
        )
    }
}

struct ThreatIntelligenceBundlePayload: Codable, Equatable, Sendable {
    struct HashEntry: Codable, Equatable, Hashable, Sendable {
        let sha256: String
        let name: String
        let family: String
        let severity: String
        let identifier: String?

        init(
            sha256: String,
            name: String,
            family: String,
            severity: String,
            identifier: String? = nil
        ) {
            self.sha256 = sha256
            self.name = name
            self.family = family
            self.severity = severity
            self.identifier = identifier
        }
    }

    struct DomainIndicator: Codable, Equatable, Hashable, Sendable {
        let domain: String
        let identifier: String
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
    let domainIndicators: [DomainIndicator]
    let ipAddresses: [String]
    let rules: [Rule]

    init(
        schemaVersion: Int,
        version: Int,
        issuedAt: Date,
        expiresAt: Date,
        source: String,
        hashes: [HashEntry],
        domains: [String],
        domainIndicators: [DomainIndicator] = [],
        ipAddresses: [String],
        rules: [Rule]
    ) {
        self.schemaVersion = schemaVersion
        self.version = version
        self.issuedAt = issuedAt
        self.expiresAt = expiresAt
        self.source = source
        self.hashes = hashes
        self.domains = domains
        self.domainIndicators = domainIndicators
        self.ipAddresses = ipAddresses
        self.rules = rules
    }

    private enum CodingKeys: String, CodingKey {
        case schemaVersion, version, issuedAt, expiresAt, source, hashes, domains
        case domainIndicators, ipAddresses, rules
    }

    init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        schemaVersion = try values.decode(Int.self, forKey: .schemaVersion)
        version = try values.decode(Int.self, forKey: .version)
        issuedAt = try values.decode(Date.self, forKey: .issuedAt)
        expiresAt = try values.decode(Date.self, forKey: .expiresAt)
        source = try values.decode(String.self, forKey: .source)
        hashes = try values.decode([HashEntry].self, forKey: .hashes)
        domains = try values.decode([String].self, forKey: .domains)
        domainIndicators = try values.decodeIfPresent(
            [DomainIndicator].self,
            forKey: .domainIndicators
        ) ?? []
        ipAddresses = try values.decode([String].self, forKey: .ipAddresses)
        rules = try values.decode([Rule].self, forKey: .rules)
    }

    func encode(to encoder: Encoder) throws {
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(schemaVersion, forKey: .schemaVersion)
        try values.encode(version, forKey: .version)
        try values.encode(issuedAt, forKey: .issuedAt)
        try values.encode(expiresAt, forKey: .expiresAt)
        try values.encode(source, forKey: .source)
        try values.encode(hashes, forKey: .hashes)
        try values.encode(domains, forKey: .domains)
        if !domainIndicators.isEmpty {
            try values.encode(domainIndicators, forKey: .domainIndicators)
        }
        try values.encode(ipAddresses, forKey: .ipAddresses)
        try values.encode(rules, forKey: .rules)
    }
}

enum ThreatIntelligenceCanary {
    static let identifierPrefix = "NICK_CANARY_"

    /// Call this only with identifiers carried by a verified signed payload.
    static func isTestIdentifier(_ identifier: String?) -> Bool {
        identifier?.hasPrefix(identifierPrefix) == true
    }
}

struct SignedThreatIntelligenceBundle: Codable, Equatable, Sendable {
    /// Exact bytes covered by `signature`. Verification happens before these
    /// bytes are decoded, so publishers in different languages cannot disagree
    /// about canonical JSON and accidentally create an unverifiable bundle.
    let payloadData: Data
    let signature: Data

    init(payload: ThreatIntelligenceBundlePayload, signature: Data) {
        self.payloadData = (try? Self.canonicalEncoder.encode(payload)) ?? Data()
        self.signature = signature
    }

    init(payloadData: Data, signature: Data) {
        self.payloadData = payloadData
        self.signature = signature
    }

    func verifiedPayload(publicKey: Data) -> ThreatIntelligenceBundlePayload? {
        guard let key = try? Curve25519.Signing.PublicKey(rawRepresentation: publicKey) else {
            return nil
        }
        guard key.isValidSignature(signature, for: payloadData) else { return nil }
        return try? Self.canonicalDecoder.decode(
            ThreatIntelligenceBundlePayload.self,
            from: payloadData
        )
    }

    static let canonicalEncoder: JSONEncoder = {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        encoder.dateEncodingStrategy = .millisecondsSince1970
        return encoder
    }()

    static let canonicalDecoder: JSONDecoder = {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .millisecondsSince1970
        return decoder
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

enum ThreatBundleInstallResultCode: String, Codable, Sendable {
    case installed, updatesDisabled, malformed, invalidSignature, unsupportedSchema
    case invalidVersion, olderThanInstalled, notYetValid, expired, invalidLifetime
    case invalidEntry, publishGateRejected, tooLarge, unavailable

    init(error: Error) {
        switch error as? ThreatIntelligenceBundleValidationError {
        case .updatesDisabled: self = .updatesDisabled
        case .malformed: self = .malformed
        case .invalidSignature: self = .invalidSignature
        case .unsupportedSchema: self = .unsupportedSchema
        case .invalidVersion: self = .invalidVersion
        case .rollback: self = .olderThanInstalled
        case .notYetValid: self = .notYetValid
        case .expired: self = .expired
        case .invalidLifetime: self = .invalidLifetime
        case .invalidEntry: self = .invalidEntry
        case .gateRejected: self = .publishGateRejected
        case nil: self = .unavailable
        }
    }

    var plainDescription: String {
        switch self {
        case .installed: "Installed"
        case .invalidSignature: "Invalid signature"
        case .expired: "Protection updates expired"
        case .olderThanInstalled: "Older than installed"
        case .tooLarge: "Update is too large"
        case .updatesDisabled: "Automatic protection updates are off"
        case .unavailable: "Update service unavailable"
        case .malformed: "Malformed update"
        case .unsupportedSchema: "Unsupported update format"
        case .invalidVersion: "Invalid update version"
        case .notYetValid: "Update is not valid yet"
        case .invalidLifetime: "Invalid update lifetime"
        case .invalidEntry: "Invalid update contents"
        case .publishGateRejected: "Update failed safety checks"
        }
    }
}

struct ThreatIntelligenceBundleValidator: Sendable {
    static let supportedSchema = 1
    static let maximumLifetime: TimeInterval = 180 * 24 * 60 * 60

    let publicKey: Data

    func validate(
        _ bundle: SignedThreatIntelligenceBundle,
        now: Date,
        highestAcceptedVersion: Int?,
        allowExpired: Bool = false
    ) throws -> ThreatIntelligenceBundlePayload {
        guard let payload = bundle.verifiedPayload(publicKey: publicKey) else {
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
        guard allowExpired || payload.expiresAt > now else {
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
            + payload.domainIndicators.map { $0.domain.lowercased() }
        guard Set(domains).count == domains.count,
              domains.allSatisfy({ !$0.isEmpty && !$0.contains("/") && !$0.contains(" ") })
        else { return false }

        let indicatorIDs = payload.hashes.compactMap(\.identifier)
            + payload.domainIndicators.map(\.identifier)
        guard Set(indicatorIDs).count == indicatorIDs.count,
              indicatorIDs.allSatisfy({
                  !$0.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
              })
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
            try writePrivateFile(data, to: stagedURL)
            if fileManager.fileExists(atPath: currentURL.path) {
                try? fileManager.removeItem(at: lastKnownGoodURL)
                try fileManager.copyItem(at: currentURL, to: lastKnownGoodURL)
            }
            try? fileManager.removeItem(at: currentURL)
            try fileManager.moveItem(at: stagedURL, to: currentURL)
            try writePrivateFile(Data(String(payload.version).utf8), to: versionURL)
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
              let payload = try? validator.validate(
                bundle,
                now: now(),
                highestAcceptedVersion: nil,
                allowExpired: usingLastKnownGood
              )
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

    /// macOS does not support Foundation's iOS data-protection write option
    /// for these files. Keep promotion atomic and constrain access with the
    /// containing 0700 directory plus an explicit 0600 file mode.
    private func writePrivateFile(_ data: Data, to url: URL) throws {
        try data.write(to: url, options: .atomic)
        try fileManager.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
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
