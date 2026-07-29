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
        let isCodeSigned: Bool?   // nil = not evaluated
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

    // CS_VALID bitmask from <sys/codesign.h> — process is dynamically valid
    private static let csValid: UInt32 = 0x00000001

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
        // 1. Cache hit — return immediately
        if let entry = cache.lookup(path: filePath) {
            return ScanResult(
                filePath: filePath,
                hash: entry.hash,
                isThreat: entry.isThreat,
                mayBlock: entry.mayBlock,
                threatName: entry.threatName,
                threatFamily: entry.threatFamily,
                isCodeSigned: nil
            )
        }

        // 2. Hash the file
        guard let hash = computeSHA256(path: filePath) else {
            Self.logger.debug("Cannot hash \(filePath) — skipping scan")
            return ScanResult(filePath: filePath, hash: "", isThreat: false,
                              mayBlock: false, threatName: nil, threatFamily: nil, isCodeSigned: nil)
        }

        // 3. Signature DB lookup (hash-based — catches known exact samples)
        let hashMatch = signatureDB.lookup(hash: hash)

        // 4. YARA pattern scan — always runs regardless of hash result so that
        //    repacked/modified variants are caught even when the hash is unknown.
        var yaraMatches: [YARAMatch] = []
        if let yaraEngine {
            do {
                yaraMatches = try yaraEngine.scanFileBlocking(at: filePath)
            } catch YARAError.scanTimeout(let p) {
                Self.logger.warning("YARA scan timeout — \(p, privacy: .private)")
            } catch YARAError.fileNotReadable {
                // Silently skip — file may have been deleted between hash and scan.
            } catch {
                Self.logger.error("YARA scan error for \(filePath, privacy: .private): \(error.localizedDescription)")
            }
        }

        // 5. Merge results. MEDIUM/LOW YARA rules are behavioral heuristics:
        // useful in an explicit scan, but not enough evidence to deny execution
        // or quarantine a file. Only HIGH/CRITICAL rules are treated as threats.
        let actionableYARAMatches = yaraMatches.filter {
            let severity = $0.metadata["severity"]?.uppercased() ?? "HIGH"
            return severity == "HIGH" || severity == "CRITICAL"
        }
        let isThreat = hashMatch != nil || !actionableYARAMatches.isEmpty
        // YARA rules are pattern/heuristic evidence. Even a high-severity rule
        // can match a legitimate newly-linked executable (for example Xcode
        // DerivedData). Only an exact curated hash is safe to auto-block.
        let mayBlock = hashMatch != nil
        let threatName = hashMatch?.name
            ?? actionableYARAMatches.first.map { "YARA:\($0.ruleName)" }
        let threatFamily = hashMatch?.family ?? actionableYARAMatches.first?.tags.first

        if let hashMatch {
            Self.logger.notice("Hash threat: \(filePath, privacy: .private) → \(hashMatch.name) [\(hashMatch.family)]")
        } else if let first = actionableYARAMatches.first {
            Self.logger.notice("YARA threat: \(filePath, privacy: .private) → rule:\(first.ruleName)")
        } else if let first = yaraMatches.first {
            Self.logger.info("YARA heuristic only: \(filePath, privacy: .private) → rule:\(first.ruleName)")
        }

        // 6. Code-signing check
        let isSigned = evaluateCodeSigning(path: filePath)

        // 7. Populate cache
        cache.store(
            path: filePath,
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
            threatFamily: threatFamily,
            isCodeSigned: isSigned
        )
    }

    /// Returns `true` if `path` is in a location that warrants suspicion when unsigned.
    ///
    /// Trusted system paths always return `false` (never suspicious).
    /// Paths from user home dirs, /tmp, and Downloads are considered untrusted.
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

    private func computeSHA256(path: String) -> String? {
        let attrs = try? FileManager.default.attributesOfItem(atPath: path)
        let size  = (attrs?[.size] as? Int) ?? 0

        return size > Self.streamingThreshold
            ? computeSHA256Streaming(path: path)
            : computeSHA256Buffered(path: path)
    }

    private func computeSHA256Buffered(path: String) -> String? {
        guard let data = FileManager.default.contents(atPath: path) else { return nil }
        return SHA256.hash(data: data).hexString
    }

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

    // MARK: - Code Signing

    private func evaluateCodeSigning(path: String) -> Bool? {
        var staticCode: SecStaticCode?
        let url = URL(fileURLWithPath: path)
        guard SecStaticCodeCreateWithPath(url as CFURL, [], &staticCode) == errSecSuccess,
              let staticCode else {
            return nil
        }

        let result = SecStaticCodeCheckValidity(staticCode, SecCSFlags(rawValue: 0), nil)
        return result == errSecSuccess
    }
}

// MARK: - Digest Hex Helpers

private extension Digest {
    var hexString: String {
        makeIterator().map { String(format: "%02x", $0) }.joined()
    }
}
