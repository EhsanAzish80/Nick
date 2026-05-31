// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation
import os

// MARK: - CloudIntelService

/// Phase 6.1 — Cloud threat-intelligence backend.
///
/// Two capabilities:
/// 1. **Hash lookup** — when a hash is not in the local `SignatureDatabase`,
///    query the cloud with its SHA-256. Any confirmed hit is written back to the
///    local DB so subsequent offline checks are instant.
/// 2. **Signature updates** — pull new signatures from the server on a schedule
///    (typically every 4 hours from the extension's `main.swift`).
///
/// This class is intentionally **not** on any actor — it is thread-safe through
/// its own `NSLock` and `URLSession` (which is thread-safe by design).
///
/// > **Security note:** The API key is stored in the keychain by the container
/// > app and passed in at init. It is never logged or embedded in source.
final class CloudIntelService: @unchecked Sendable {

    // MARK: - Types

    struct LookupResult: Codable, Sendable {
        let hash: String
        let isThreat: Bool
        let threatName: String?
        let family: String?
        let severity: String?
        let firstSeen: String?
        /// Fraction of detection engines that flagged this hash (0.0–1.0).
        let detectionRate: Double?
    }

    private struct SignatureUpdate: Codable {
        let hash: String
        let name: String
        let family: String
        let severity: String
    }

    // MARK: - Private

    private let apiBaseURL: String
    private let apiKey: String
    private let session: URLSession
    private let signatureDB: SignatureDatabase
    private let lock = NSLock()

    private static let logger = Logger(
        subsystem: "com.ehsanazish.nick",
        category: "CloudIntelService"
    )

    // MARK: - Init

    /// - Parameters:
    ///   - apiBaseURL: Base URL of the threat-intelligence API (no trailing slash).
    ///   - apiKey: Bearer / X-API-Key credential.
    ///   - signatureDB: Local database to populate with confirmed cloud hits.
    init(apiBaseURL: String, apiKey: String, signatureDB: SignatureDatabase) {
        self.apiBaseURL  = apiBaseURL
        self.apiKey      = apiKey
        self.signatureDB = signatureDB

        let config = URLSessionConfiguration.ephemeral
        // Short timeout — never block an ES NOTIFY event waiting for cloud.
        config.timeoutIntervalForRequest  = 5
        config.timeoutIntervalForResource = 10
        self.session = URLSession(configuration: config)
    }

    // MARK: - Public API

    /// Looks up `hash` against the cloud service.
    ///
    /// On a confirmed hit the result is also persisted to the local
    /// `SignatureDatabase` so subsequent queries don't need the network.
    ///
    /// - Returns: `LookupResult` on success, `nil` on network error or non-200.
    func lookup(hash: String) async -> LookupResult? {
        guard let url = URL(string: "\(apiBaseURL)/lookup/\(hash)") else { return nil }

        var request = URLRequest(url: url)
        request.setValue(apiKey, forHTTPHeaderField: "X-API-Key")
        request.setValue("application/json", forHTTPHeaderField: "Accept")

        do {
            let (data, response) = try await session.data(for: request)
            guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
                return nil
            }

            let result = try JSONDecoder().decode(LookupResult.self, from: data)

            // Write confirmed threat back to local DB.
            if result.isThreat, let name = result.threatName {
                signatureDB.upsert(
                    hash: hash,
                    name: name,
                    family: result.family ?? "Unknown",
                    severity: result.severity ?? "warning"
                )
                Self.logger.info("CloudIntel: cached threat '\(name)' (\(hash.prefix(8))…)")
            }

            return result
        } catch {
            Self.logger.debug("CloudIntel lookup failed: \(error.localizedDescription)")
            return nil
        }
    }

    /// Pulls new/updated signatures from the cloud and merges them into the
    /// local `SignatureDatabase`.
    ///
    /// Uses the `If-Modified-Since` header so the server can return 304 when
    /// there is nothing new, keeping bandwidth minimal.
    ///
    /// - Returns: Number of signatures added or updated.
    @discardableResult
    func updateSignatures() async -> Int {
        guard let url = URL(string: "\(apiBaseURL)/signatures/latest") else { return 0 }

        var request = URLRequest(url: url)
        request.setValue(apiKey, forHTTPHeaderField: "X-API-Key")
        request.setValue("application/json", forHTTPHeaderField: "Accept")

        // Send the timestamp of the last successful update so the server only
        // returns what's new since then.
        let lastUpdate = UserDefaults.standard.string(forKey: "nickLastSignatureUpdate")
            ?? "1970-01-01T00:00:00Z"
        request.setValue(lastUpdate, forHTTPHeaderField: "If-Modified-Since")

        do {
            let (data, response) = try await session.data(for: request)
            guard let http = response as? HTTPURLResponse else { return 0 }

            if http.statusCode == 304 {
                Self.logger.debug("CloudIntel: signatures up to date (304)")
                return 0
            }
            guard http.statusCode == 200 else { return 0 }

            let updates = try JSONDecoder().decode([SignatureUpdate].self, from: data)
            guard !updates.isEmpty else { return 0 }

            // Bulk-insert via individual upserts (SignatureDatabase is thread-safe).
            for sig in updates {
                signatureDB.upsert(
                    hash: sig.hash,
                    name: sig.name,
                    family: sig.family,
                    severity: sig.severity
                )
            }

            // Persist watermark for the next call.
            UserDefaults.standard.set(
                ISO8601DateFormatter().string(from: Date()),
                forKey: "nickLastSignatureUpdate"
            )

            Self.logger.info("CloudIntel: merged \(updates.count) signature update(s)")
            return updates.count
        } catch {
            Self.logger.warning("CloudIntel signature update failed: \(error.localizedDescription)")
            return 0
        }
    }
}
