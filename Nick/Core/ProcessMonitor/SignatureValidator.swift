// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation
import Security
import os

// MARK: - SignatureValidator

/// Validates the code-signing status of on-disk Mach-O binaries.
///
/// Uses `SecStaticCode` APIs to inspect the binary without running it.
/// Results are cached in-memory with a 5-minute TTL. Entries older than
/// `cacheTTL` are re-evaluated on the next call to `evaluate(binaryPath:)`.
/// Call `clearCache()` to force re-evaluation of all entries immediately.
///
/// - Note: `SecStaticCodeCheckValidity` may be slow on first access while
///   the Trust Evaluation daemon warms up — call only from async contexts.
final class SignatureValidator: @unchecked Sendable {

    // MARK: - Shared Instance

    /// Global shared instance used by `PersistenceWatcher` and `ProcessMonitor`.
    static let shared = SignatureValidator()

    // MARK: - Private

    /// How long a cached signing result is considered fresh.
    let cacheTTL: TimeInterval = 5 * 60  // 5 minutes

    private struct CacheEntry {
        let status: SigningStatus
        let cachedAt: Date
    }

    private let lock = NSLock()
    private var cache: [String: CacheEntry] = [:]

    private static let logger = Logger(
        subsystem: "com.ehsanazish.nick",
        category: "SignatureValidator"
    )

    // MARK: - Init

    private init() {}

    // MARK: - Public API

    /// Returns the code-signing status of a binary at the given path.
    ///
    /// Results are cached for `cacheTTL` seconds (default: 5 minutes). After the
    /// TTL expires the binary is re-evaluated on the next call. The cache key is
    /// the absolute path string; there is no inode-based staleness check.
    ///
    /// - Parameter binaryPath: Absolute path to the Mach-O binary.
    /// - Returns: A `SigningStatus` value describing the binary's signing state.
    func evaluate(binaryPath: String) -> SigningStatus {
        lock.lock()
        if let entry = cache[binaryPath], Date().timeIntervalSince(entry.cachedAt) < cacheTTL {
            lock.unlock()
            return entry.status
        }
        lock.unlock()

        let result = performStaticCheck(path: binaryPath)

        lock.lock()
        cache[binaryPath] = CacheEntry(status: result, cachedAt: Date())
        lock.unlock()

        return result
    }

    /// Removes all cached signing results.
    func clearCache() {
        lock.lock()
        cache.removeAll()
        lock.unlock()
    }

    /// Returns the number of currently cached entries.
    var cacheCount: Int {
        lock.lock()
        defer { lock.unlock() }
        return cache.count
    }

    /// Resolves `.pending` signing statuses for a list of processes asynchronously.
    ///
    /// Iterates `processes`, skipping any that already have a non-`.pending` status
    /// or an empty path. For each `.pending` entry it calls `evaluate(binaryPath:)`
    /// (which may block the calling thread) and invokes `onUpdate` on `@MainActor`
    /// with the updated process so callers can refresh their published state.
    ///
    /// Designed to run inside a `Task.detached(priority: .background)`. Cancellation
    /// is checked between each evaluation so the caller can cancel the task promptly.
    ///
    /// - Parameters:
    ///   - processes: Snapshot returned by `ProcessScanner.scanFast()`.
    ///   - onUpdate: Called with each resolved process. Runs on `@MainActor`.
    func backfill(
        processes: [NickProcessInfo],
        onUpdate: @MainActor @escaping (NickProcessInfo) -> Void
    ) async {
        for proc in processes {
            guard !Task.isCancelled else { return }
            guard proc.signingStatus == .pending, !proc.path.isEmpty else { continue }

            let resolved = evaluate(binaryPath: proc.path)
            let updated = NickProcessInfo(
                pid: proc.pid,
                path: proc.path,
                name: proc.name,
                parentPID: proc.parentPID,
                parentName: proc.parentName,
                signingStatus: resolved,
                user: proc.user,
                startTime: proc.startTime
            )
            await onUpdate(updated)
        }
        Self.logger.debug("Signature backfill complete for \(processes.count) processes")
    }

    // MARK: - Private Helpers

    private func performStaticCheck(path: String) -> SigningStatus {
        let url = URL(fileURLWithPath: path) as CFURL

        var staticCode: SecStaticCode?
        let createStatus = SecStaticCodeCreateWithPath(url, [], &staticCode)
        guard createStatus == errSecSuccess, let code = staticCode else {
            Self.logger.debug("SecStaticCodeCreateWithPath failed for \(path): \(createStatus)")
            return .unknown
        }

        // Validate the signature (does not check revocation in Phase 1)
        let validationStatus = SecStaticCodeCheckValidity(code, [], nil)

        switch validationStatus {
        case errSecSuccess:
            // Signed — extract team ID from signing information
            return extractTeamID(from: code)

        case errSecCSUnsigned:
            return .unsigned

        case -67065: // kSecCSSignatureInvalid — tampered
            return .invalid

        default:
            // Ad-hoc signed binaries return a specific code
            if isAdHocSigned(code: code) { return .adHoc }
            Self.logger.debug("Unknown signing status for \(path): \(validationStatus)")
            return .unknown
        }
    }

    private func extractTeamID(from code: SecStaticCode) -> SigningStatus {
        var info: CFDictionary?
        let flags = SecCSFlags(rawValue: kSecCSSigningInformation)
        guard SecCodeCopySigningInformation(code, flags, &info) == errSecSuccess,
              let dict = info as? [String: Any],
              let teamID = dict[kSecCodeInfoTeamIdentifier as String] as? String
        else {
            // Signed but no team ID → ad-hoc or Developer ID without team
            return .adHoc
        }
        return .signed(teamID: teamID)
    }

    private func isAdHocSigned(code: SecStaticCode) -> Bool {
        var info: CFDictionary?
        let flags = SecCSFlags(rawValue: kSecCSSigningInformation)
        guard SecCodeCopySigningInformation(code, flags, &info) == errSecSuccess,
              let dict = info as? [String: Any]
        else { return false }

        // Ad-hoc certificates have no anchor certificate chain
        let anchors = dict[kSecCodeInfoCertificates as String] as? [Any]
        return anchors == nil || anchors?.isEmpty == true
    }
}
