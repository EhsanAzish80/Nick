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

    static let shared = NetworkBlocklist()

    // MARK: - Private

    private static let logger = Logger(
        subsystem: "com.ehsanazish.nick.NickNetFilter",
        category:  "NetworkBlocklist"
    )

    private var blockedDomains: Set<String> = []
    private var blockedIPs:     Set<String> = []
    private let lock = NSLock()

    // MARK: - Init

    init() {
        reload()
    }

    // MARK: - Public API

    /// Returns `true` if `host` is (or is a subdomain of) a blocked entry.
    func isBlocked(host: String) -> Bool {
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

    func reload() {
        lock.withLock {
            blockedDomains = []
            blockedIPs = []
        }
        loadSignedRules()
    }

    /// Loads only a versioned Ed25519-signed rule envelope. Invalid, expired,
    /// or downgraded data is ignored so a broken update always fails open.
    private func loadSignedRules() {
        guard let listURL = NetworkProtectionSharedStore.signedRulesURL() else { return }
        guard let data = try? Data(contentsOf: listURL) else { return }
        guard let envelope = try? JSONDecoder().decode(SignedNetworkRuleEnvelope.self, from: data),
              envelope.payload.schemaVersion == 1,
              envelope.payload.expiresAt > Date(),
              envelope.verify()
        else {
            Self.logger.error("NetworkBlocklist: rejected invalid or expired signed rules")
            return
        }

        lock.withLock {
            blockedDomains = Set(envelope.payload.domains.compactMap(
                NetworkProtectionConfiguration.normalizedDomain
            ))
            blockedIPs = Set(envelope.payload.ipAddresses.map { $0.lowercased() })
        }
        Self.logger.info("NetworkBlocklist: loaded signed rule version \(envelope.payload.version)")
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
