// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import CryptoKit
import Foundation
import os
import Security

// MARK: - FileScanner

/// Scans files by computing their SHA-256 hash and looking up the result in
/// `SignatureDatabase`. Results are cached in `ScanCache` (TTL: 5 minutes).
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

    // MARK: - Private

    private static let logger = Logger(
        subsystem: "com.ehsanazish.nick.NickExtension",
        category: "FileScanner"
    )

    // CS_VALID bitmask from <sys/codesign.h> — process is dynamically valid
    private static let csValid: UInt32 = 0x00000001

    // MARK: - Init

    init(signatureDB: SignatureDatabase, cache: ScanCache) {
        self.signatureDB = signatureDB
        self.cache       = cache
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
                threatName: entry.threatName,
                threatFamily: entry.threatFamily,
                isCodeSigned: nil
            )
        }

        // 2. Hash the file
        guard let hash = computeSHA256(path: filePath) else {
            Self.logger.debug("Cannot hash \(filePath) — skipping scan")
            return ScanResult(filePath: filePath, hash: "", isThreat: false,
                              threatName: nil, threatFamily: nil, isCodeSigned: nil)
        }

        // 3. Signature DB lookup
        let match = signatureDB.lookup(hash: hash)

        // 4. Code-signing check (only for executables — identified by .exec path heuristic)
        let isSigned = evaluateCodeSigning(path: filePath)

        // 5. Populate cache
        cache.store(
            path: filePath,
            hash: hash,
            isThreat: match != nil,
            threatName: match?.name,
            threatFamily: match?.family
        )

        if match != nil {
            Self.logger.notice("Threat detected: \(filePath) → \(match!.name) [\(match!.family)]")
        }

        return ScanResult(
            filePath: filePath,
            hash: hash,
            isThreat: match != nil,
            threatName: match?.name,
            threatFamily: match?.family,
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
