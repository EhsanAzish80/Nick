// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation
import CryptoKit
import os

// MARK: - NetworkBlocklist

/// Thread-safe, in-memory blocklist of known malicious domains and IP addresses.
///
/// The list is compiled from a small hard-coded seed of well-known C2 and
/// malware distribution domains. In a production build, the list would be
/// updated from a signed threat intelligence feed saved to Nick's system
/// support directory.
///
/// **Subdomain matching:** `isBlocked(host:)` matches both exact entries and
/// any subdomain — e.g. blocking `evil.com` also blocks `cdn.evil.com`.
final class NetworkBlocklist: @unchecked Sendable {

    struct Provenance: Sendable {
        let version: Int
        let issuedAt: Date
        let expiresAt: Date
    }

    static let shared = NetworkBlocklist()

    // MARK: - Private

    private static let logger = Logger(
        subsystem: "com.ehsanazish.nick.NickNetFilter",
        category:  "NetworkBlocklist"
    )

    private var blockedDomains: Set<String> = []
    private var blockedIPs:     Set<String> = []
    private var loadedProvenance: Provenance?
    private var lastReloadCheck = Date.distantPast
    private var loadedBundleModificationDate: Date?
    private let lock = NSLock()

    // MARK: - Init

    init() {
        reload()
    }

    // MARK: - Public API

    /// Returns `true` if `host` is (or is a subdomain of) a blocked entry.
    func isBlocked(host: String) -> Bool {
        reloadIfBundleChanged()
        let lower = host.lowercased()

        return lock.withLock {
            if blockedIPs.contains(lower) { return true }
            // Domain check: walk up the label hierarchy
            var labels = lower.components(separatedBy: ".")
            while labels.count >= 2 {
                let candidate = labels.joined(separator: ".")
                if blockedDomains.contains(candidate) { return true }
                labels.removeFirst()
            }
            return false
        }
    }

    var provenance: Provenance? { lock.withLock { loadedProvenance } }

    func reload() {
        lock.withLock {
            blockedDomains = []
            blockedIPs = []
            loadedProvenance = nil
        }
        loadSignedRules()
        let modificationDate = Self.currentBundleModificationDate()
        lock.withLock { loadedBundleModificationDate = modificationDate }
    }

    private func reloadIfBundleChanged() {
        let shouldCheck = lock.withLock { () -> Bool in
            guard Date().timeIntervalSince(lastReloadCheck) >= 60 else { return false }
            lastReloadCheck = Date()
            return true
        }
        guard shouldCheck,
              Self.currentBundleModificationDate() != lock.withLock({ loadedBundleModificationDate })
        else { return }
        reload()
    }

    private static func currentBundleModificationDate() -> Date? {
        let url = ThreatIntelligenceBundleTrustAnchor.productionDirectory
            .appendingPathComponent("current.json")
        return try? url.resourceValues(forKeys: [.contentModificationDateKey]).contentModificationDate
    }

    /// Loads only a versioned Ed25519-signed rule envelope. Invalid, expired,
    /// or downgraded data is ignored so a broken update always fails open.
    private func loadSignedRules() {
        let bundleStore = SignedThreatIntelligenceBundleStore(
            directory: ThreatIntelligenceBundleTrustAnchor.productionDirectory,
            publicKey: ThreatIntelligenceBundleTrustAnchor.productionPublicKey,
            updatesEnabled: ThreatIntelligenceBundleTrustAnchor.updatesEnabled
        )
        if let (payload, provenance) = bundleStore.loadBestAvailable() {
            lock.withLock {
                blockedDomains = Set(payload.domains.compactMap(
                    NetworkProtectionConfiguration.normalizedDomain
                ))
                blockedIPs = Set(payload.ipAddresses.map { $0.lowercased() })
                loadedProvenance = Provenance(
                    version: provenance.version,
                    issuedAt: provenance.issuedAt,
                    expiresAt: provenance.expiresAt
                )
            }
            Self.logger.info("NetworkBlocklist: loaded signed intelligence bundle version \(payload.version)")
            return
        }

        // Legacy 5.0.x envelope fallback. It remains signature-checked and is
        // removed once the 5.1 bundle service is enabled in production.
        guard let listURL = NetworkProtectionSharedStore.signedRulesURL() else { return }
        guard let data = try? Data(contentsOf: listURL) else { return }
        guard let envelope = try? JSONDecoder().decode(SignedNetworkRuleEnvelope.self, from: data),
              envelope.payload.schemaVersion == 1,
              envelope.payload.expiresAt > Date(),
              envelope.verify(),
              NetworkRuleVersionPolicy.accepts(
                  candidateVersion: envelope.payload.version,
                  highestAcceptedVersion: highestAcceptedVersion()
              )
        else {
            Self.logger.error("NetworkBlocklist: rejected invalid, expired, or downgraded signed rules")
            return
        }

        lock.withLock {
            blockedDomains = Set(envelope.payload.domains.compactMap(
                NetworkProtectionConfiguration.normalizedDomain
            ))
            blockedIPs = Set(envelope.payload.ipAddresses.map { $0.lowercased() })
            loadedProvenance = Provenance(
                version: envelope.payload.version,
                issuedAt: envelope.payload.issuedAt,
                expiresAt: envelope.payload.expiresAt
            )
        }
        persistHighestAcceptedVersion(envelope.payload.version)
        Self.logger.info("NetworkBlocklist: loaded signed rule version \(envelope.payload.version)")
    }

    private func highestAcceptedVersion() -> Int? {
        guard let url = NetworkProtectionSharedStore.signedRulesVersionURL(),
              let value = try? String(contentsOf: url, encoding: .utf8),
              let version = Int(value.trimmingCharacters(in: .whitespacesAndNewlines))
        else { return nil }
        return version
    }

    private func persistHighestAcceptedVersion(_ version: Int) {
        guard let url = NetworkProtectionSharedStore.signedRulesVersionURL() else { return }
        do {
            try Data(String(version).utf8).write(to: url, options: .atomic)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
        } catch {
            Self.logger.error("NetworkBlocklist: could not persist accepted rule version")
        }
    }
}

struct NetworkRulePayload: Codable, Sendable {
    let schemaVersion: Int
    let version: Int
    let issuedAt: Date
    let expiresAt: Date
    let domains: [String]
    let ipAddresses: [String]
}

struct SignedNetworkRuleEnvelope: Codable, Sendable {
    let payload: NetworkRulePayload
    let signature: Data

    // Replace only through a coordinated rule-signing key rotation. The
    // corresponding private key must never ship in Nick.
    private static let productionPublicKey = Data(repeating: 0x42, count: 32)

    func verify(publicKeyData: Data = Self.productionPublicKey) -> Bool {
        guard let message = try? Self.canonicalEncoder.encode(payload),
              let key = try? Curve25519.Signing.PublicKey(rawRepresentation: publicKeyData)
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
