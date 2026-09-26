// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import CryptoKit
import Foundation
import os
import Security

// MARK: - FileScanner

/// Scans files using SHA-256 signature matching AND YARA rule pattern scanning.
///
/// Both techniques run on every cache miss so that:
/// - Known malware is caught by hash even if YARA rules don't cover it yet.
/// - Novel/repacked malware is caught by YARA even when the hash is unknown.
///
/// **Threading:** `scan(filePath:)` is synchronous and may be called from any
/// background queue. Never call it from the ES callback queue directly —
/// always dispatch to `ESEventHandler.dispatchQueue` first.
///
/// **Large file strategy:** Files over 10 MB are hashed via streaming to avoid
/// a single large `Data` allocation. Streaming adds ~20 ms per 100 MB on Apple
/// Silicon and is well within the 60-second AUTH deadline.
final class FileScanner {

    // MARK: - Types

    struct ScanResult {
        let filePath: String
        let hash: String          // lowercase hex SHA-256, empty string on I/O error
        let isThreat: Bool
        /// True only for evidence strong enough to deny an Endpoint Security
        /// authorization request without asking the user.
        let mayBlock: Bool
        let threatName: String?
        let threatFamily: String?
    }

    // MARK: - Configuration

    /// Files larger than this threshold are hashed via streaming.
    static let streamingThreshold: Int = 10 * 1_024 * 1_024   // 10 MB

    /// Chunk size used during streaming hashing.
    static let chunkSize: Int = 1_024 * 1_024                  // 1 MB

    // MARK: - Dependencies

    let cache: ScanCache
    private let signatureDB: SignatureDatabase

    /// Optional YARA engine for pattern-based scanning. When non-nil, every
    /// cache-miss file is scanned with compiled YARA rules in addition to the
    /// SHA-256 signature database lookup.
    private let yaraEngine: YARAEngine?

    // MARK: - Private

    private static let logger = Logger(
        subsystem: "com.ehsanazish.nick.NickExtension",
        category: "FileScanner"
    )

    // MARK: - Init

    /// - Parameters:
    ///   - signatureDB: SHA-256 hash database.
    ///   - cache: Scan result cache (shared with `ESEventHandler`).
    ///   - yaraEngine: Optional pre-initialised YARA engine. Pass `nil` to
    ///     disable YARA scanning (e.g. if rules failed to compile at startup).
    init(signatureDB: SignatureDatabase, cache: ScanCache, yaraEngine: YARAEngine? = nil) {
        self.signatureDB = signatureDB
        self.cache       = cache
        self.yaraEngine  = yaraEngine
    }

    // MARK: - Public API

    /// Scans `filePath`, returning a cached result if one is fresh.
    ///
    /// On cache miss, hashes the file, queries the signature DB, and stores the
    /// result. Returns a safe (non-threat) result if the file cannot be read.
    ///
    /// - Parameter filePath: Absolute path to the file.
    /// - Returns: `ScanResult` — never throws.
    func scan(filePath: String) -> ScanResult {
        // Identity is captured before reading so a concurrent rewrite produces
        // an identity mismatch (and a rescan) rather than a stale clean verdict.
        let identity = FileIdentity(path: filePath)

        // 1. Cache hit for the same content — return immediately
        if let entry = cache.lookup(path: filePath, identity: identity) {
            return ScanResult(
                filePath: filePath,
                hash: entry.hash,
                isThreat: entry.isThreat,
                mayBlock: entry.mayBlock,
                threatName: entry.threatName,
                threatFamily: entry.threatFamily
            )
        }

        // 2. Read small files once: the same bytes are hashed and YARA-scanned
        //    in memory. Larger files are hashed by streaming and scanned by path.
        let size = identity.map { Int($0.size) } ?? Int.max
        let contents: Data? = size <= Self.streamingThreshold
            ? FileManager.default.contents(atPath: filePath)
            : nil
        guard let hash = contents.map({ SHA256.hash(data: $0).hexString })
                ?? computeSHA256Streaming(path: filePath) else {
            Self.logger.debug("Cannot hash \(filePath, privacy: .private) — skipping scan")
            return ScanResult(filePath: filePath, hash: "", isThreat: false,
                              mayBlock: false, threatName: nil, threatFamily: nil)
        }

        // 3. Signature DB lookup (hash-based — catches known exact samples)
        let hashMatch = signatureDB.lookup(hash: hash)

        // 4. YARA pattern scan — always runs regardless of hash result so that
        //    repacked/modified variants are caught even when the hash is unknown.
        var yaraMatches: [YARAMatch] = []
        if let yaraEngine {
            do {
                if let contents {
                    yaraMatches = try yaraEngine.scanDataBlocking(contents, reportingPath: filePath)
                } else {
                    yaraMatches = try yaraEngine.scanFileBlocking(at: filePath)
                }
            } catch YARAError.scanTimeout(let p) {
                Self.logger.warning("YARA scan timeout — \(p, privacy: .private)")
            } catch YARAError.fileNotReadable {
                // Silently skip — file may have been deleted between hash and scan.
            } catch {
                Self.logger.error("YARA scan error for \(filePath, privacy: .private): \(error.localizedDescription)")
            }
        }

        // 5. Merge results with the shared verdict policy. Family signatures
        // at HIGH/CRITICAL are threats; generic behaviour rules need file
        // context this path does not have, so they are logged for review
        // unless their author declared them critical.
        let actionableYARAMatches = yaraMatches.filter {
            YARAVerdictPolicy.isContextFreeThreat(ruleName: $0.ruleName, metadata: $0.metadata, tags: $0.tags)
        }
        let isThreat = hashMatch != nil || !actionableYARAMatches.isEmpty
        // YARA rules are pattern/heuristic evidence. Even a high-severity rule
        // can match a legitimate newly-linked executable (for example Xcode
        // DerivedData). Only an exact curated hash is safe to auto-block.
        let mayBlock = hashMatch != nil
        let threatName = hashMatch?.name
            ?? actionableYARAMatches.first.map { match in
                // DRL 1.1 rules require the author in messages based on matches.
                "YARA:\(match.ruleName)" + (match.metadata["author"].map { " (by \($0))" } ?? "")
            }
        let threatFamily = hashMatch?.family ?? actionableYARAMatches.first?.tags.first

        if let hashMatch {
            Self.logger.notice("Hash threat: \(filePath, privacy: .private) → \(hashMatch.name) [\(hashMatch.family)]")
        } else if let first = actionableYARAMatches.first {
            Self.logger.notice("YARA threat: \(filePath, privacy: .private) → rule:\(first.ruleName)")
        } else if let first = yaraMatches.first {
            Self.logger.info("YARA heuristic only: \(filePath, privacy: .private) → rule:\(first.ruleName)")
        }

        // 6. Populate cache
        cache.store(
            path: filePath,
            identity: identity,
            hash: hash,
            isThreat: isThreat,
            mayBlock: mayBlock,
            threatName: threatName,
            threatFamily: threatFamily
        )

        return ScanResult(
            filePath: filePath,
            hash: hash,
            isThreat: isThreat,
            mayBlock: mayBlock,
            threatName: threatName,
            threatFamily: threatFamily
        )
    }

    /// Hash-only check that can run before a first launch is allowed.
    ///
    /// A curated hash match is cached as blockable so the same file is also
    /// denied on open, mmap, and copy. Everything else is left to the full
    /// scan that follows the AUTH response.
    func preLaunchHashMatch(path: String, identity: FileIdentity) -> SignatureDatabase.ThreatMatch? {
        guard let hash = computeSHA256Streaming(path: path),
              let match = signatureDB.lookup(hash: hash) else { return nil }
        cache.store(
            path: path,
            identity: identity,
            hash: hash,
            isThreat: true,
            mayBlock: true,
            threatName: match.name,
            threatFamily: match.family
        )
        return match
    }

    /// Whether any curated hashes are loaded. Refreshed at most once a minute
    /// so the AUTH path never runs a COUNT query.
    var hasSignatures: Bool {
        signatureCountLock.withLock {
            if Date().timeIntervalSince(signatureCountCheckedAt) > 60 {
                cachedHasSignatures = signatureDB.count > 0
                signatureCountCheckedAt = Date()
            }
            return cachedHasSignatures
        }
    }

    private let signatureCountLock = NSLock()
    private var cachedHasSignatures = false
    private var signatureCountCheckedAt = Date.distantPast

    /// Narrow drop-zone check used only by the AUTH_CREATE observation
    /// heuristic, where a broad definition would report routine app writes.
    /// Exec-time scanning uses `ExecutionTrustPolicy.isHighRiskLocation`.
    func isUntrustedLocation(_ path: String) -> Bool {
        let trusted = ["/Applications/", "/System/", "/usr/", "/Library/Apple/", "/sbin/", "/bin/"]
        if trusted.contains(where: { path.hasPrefix($0) }) { return false }

        let untrusted = ["/tmp/", "/private/tmp/", "/var/tmp/", "/var/folders/"]
        if untrusted.contains(where: { path.hasPrefix($0) }) { return true }

        // Paths under any user's Downloads or Desktop
        if path.contains("/Downloads/") || path.contains("/Desktop/") { return true }

        return false
    }

    // MARK: - Hashing

    private func computeSHA256Streaming(path: String) -> String? {
        guard let handle = FileHandle(forReadingAtPath: path) else { return nil }
        defer { try? handle.close() }

        var hasher = SHA256()
        while true {
            let chunk: Data
            if #available(macOS 10.15.4, *) {
                guard let c = try? handle.read(upToCount: Self.chunkSize), !c.isEmpty else { break }
                chunk = c
            } else {
                chunk = handle.readData(ofLength: Self.chunkSize)
                if chunk.isEmpty { break }
            }
            hasher.update(data: chunk)
        }
        return hasher.finalize().hexString
    }

}

// MARK: - Digest Hex Helpers

private extension Digest {
    var hexString: String {
        makeIterator().map { String(format: "%02x", $0) }.joined()
    }
}
