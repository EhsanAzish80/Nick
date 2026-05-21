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
/// All results are cached in-memory for the lifetime of the process; evict
/// via `clearCache()` between long-running scans to avoid stale entries.
///
/// - Note: `SecStaticCodeCheckValidity` may be slow on first access while
///   the Trust Evaluation daemon warms up — call only from async contexts.
final class SignatureValidator: @unchecked Sendable {

    // MARK: - Shared Instance

    /// Global shared instance used by `PersistenceWatcher` and `ProcessMonitor`.
    static let shared = SignatureValidator()

    // MARK: - Private

    private let lock = NSLock()
    private var cache: [String: SigningStatus] = [:]

    private static let logger = Logger(
        subsystem: "com.ehsanazish.nick",
        category: "SignatureValidator"
    )

    // MARK: - Init

    private init() {}

    // MARK: - Public API

    /// Returns the code-signing status of a binary at the given path.
    ///
    /// Results are cached after the first evaluation. The cache key is the
    /// absolute path string; there is no inode-based staleness check in Phase 1.
    ///
    /// - Parameter binaryPath: Absolute path to the Mach-O binary.
    /// - Returns: A `SigningStatus` value describing the binary's signing state.
    func evaluate(binaryPath: String) -> SigningStatus {
        lock.lock()
        if let cached = cache[binaryPath] {
            lock.unlock()
            return cached
        }
        lock.unlock()

        let result = performStaticCheck(path: binaryPath)

        lock.lock()
        cache[binaryPath] = result
        lock.unlock()

        return result
    }

    /// Removes all cached signing results.
    func clearCache() {
        lock.lock()
        cache.removeAll()
        lock.unlock()
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
