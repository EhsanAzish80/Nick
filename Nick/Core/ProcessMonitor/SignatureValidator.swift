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
        let identity: FileIdentity
        let cachedAt: Date
    }

    private let lock = NSLock()
    private var cache: [String: CacheEntry] = [:]
    private struct ValidatedIdentityCacheKey: Hashable {
        let cdhash: Data
        let teamID: String
        let signingIdentifier: String
    }
    private var validatedIdentityCache: [ValidatedIdentityCacheKey: Bool] = [:]

    private static let logger = Logger(
        subsystem: "com.ehsanazish.nick",
        category: "SignatureValidator"
    )

    // MARK: - Init

    private init() {
        // Creates a new instance. No configuration required.
    }

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
        guard let currentIdentity = FileIdentity(path: binaryPath) else { return .unknown }
        lock.lock()
        if let entry = cache[binaryPath],
           entry.identity == currentIdentity,
           Date().timeIntervalSince(entry.cachedAt) < cacheTTL {
            lock.unlock()
            return entry.status
        }
        lock.unlock()

        // Executables on the sealed system volume cannot be replaced by an
        // unprivileged process. Avoid Security.framework certificate-chain
        // validation for every Apple daemon during each process snapshot.
        // Writable and third-party locations still receive the full check.
        let result: SigningStatus = Self.isSealedSystemBinaryPath(binaryPath)
            ? sealedSystemSigningStatus(path: binaryPath)
            : performStaticCheck(path: binaryPath)

        lock.lock()
        cache[binaryPath] = CacheEntry(
            status: result,
            identity: currentIdentity,
            cachedAt: Date()
        )
        lock.unlock()

        return result
    }

    static func isSealedSystemBinaryPath(_ path: String) -> Bool {
        let prefixes = [
            "/System/",
            "/usr/bin/",
            "/usr/lib/",
            "/usr/libexec/",
            "/bin/",
            "/sbin/"
        ]
        return prefixes.contains { path.hasPrefix($0) }
    }

    /// Removes all cached signing results.
    func clearCache() {
        lock.lock()
        cache.removeAll()
        validatedIdentityCache.removeAll()
        lock.unlock()
    }

    /// Validates an exact Developer ID identity against Apple's certificate
    /// chain. Caller-supplied Team IDs are never sufficient for this decision.
    /// Results are keyed by the signed code's cdhash plus the expected identity.
    func validatesDeveloperIdentity(
        binaryPath: String,
        teamID: String,
        signingIdentifier: String
    ) -> Bool {
        let teamCharacters = CharacterSet.uppercaseLetters.union(.decimalDigits)
        let identifierCharacters = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: ".-"))
        guard !teamID.isEmpty,
              !signingIdentifier.isEmpty,
              teamID.rangeOfCharacter(from: teamCharacters.inverted) == nil,
              signingIdentifier.rangeOfCharacter(from: identifierCharacters.inverted) == nil
        else { return false }

        var code: SecStaticCode?
        guard SecStaticCodeCreateWithPath(URL(fileURLWithPath: binaryPath) as CFURL, [], &code) == errSecSuccess,
              let code else { return false }
        var information: CFDictionary?
        guard SecCodeCopySigningInformation(
            code,
            SecCSFlags(rawValue: kSecCSSigningInformation),
            &information
        ) == errSecSuccess,
              let dictionary = information as? [String: Any],
              let cdhash = dictionary[kSecCodeInfoUnique as String] as? Data
        else { return false }

        let key = ValidatedIdentityCacheKey(
            cdhash: cdhash,
            teamID: teamID,
            signingIdentifier: signingIdentifier
        )
        lock.lock()
        if let cached = validatedIdentityCache[key] {
            lock.unlock()
            return cached
        }
        lock.unlock()

        let requirementText = "identifier \"\(signingIdentifier)\" and anchor apple generic "
            + "and certificate leaf[subject.OU] = \"\(teamID)\""
        var requirement: SecRequirement?
        guard SecRequirementCreateWithString(
            requirementText as CFString,
            [],
            &requirement
        ) == errSecSuccess,
              let requirement else { return false }
        let flags = SecCSFlags(rawValue: UInt32(kSecCSDoNotValidateResources))
        let valid = SecStaticCodeCheckValidity(code, flags, requirement) == errSecSuccess
        lock.lock()
        validatedIdentityCache[key] = valid
        lock.unlock()
        return valid
    }

    /// Returns the number of currently cached entries.
    var cacheCount: Int {
        lock.lock()
        defer { lock.unlock() }
        return cache.count
    }

    /// Resolves `.pending` signing statuses for a list of processes asynchronously.
    ///
    /// Iterates `processes`, skipping entries that already have a resolved status.
    /// A missing executable path settles to `.unknown`; otherwise each `.pending`
    /// entry is evaluated and delivered through `onUpdate` on `@MainActor` so
    /// callers can refresh their published state.
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
            guard proc.signingStatus == .pending else { continue }

            // Certificate-chain evaluation is intentionally paced. A cold launch
            // may contain hundreds of third-party helper processes; validating
            // them back-to-back can monopolize a CPU core and make the entire Mac
            // feel stalled. Sealed-system paths use the cheap policy above and do
            // not need the delay.
            if !proc.path.isEmpty, !Self.isSealedSystemBinaryPath(proc.path) {
                try? await Task.sleep(nanoseconds: 75_000_000)
                guard !Task.isCancelled else { return }
            }
            // An inaccessible executable path is a genuine unavailable result,
            // not an indefinitely pending validation.
            let resolved: SigningStatus = proc.path.isEmpty
                ? .unknown
                : evaluate(binaryPath: proc.path)
            let updated = NickProcessInfo(
                pid: proc.pid,
                path: proc.path,
                name: proc.name,
                parentPID: proc.parentPID,
                parentName: proc.parentName,
                signingStatus: resolved,
                metadata: ProcessMetadata(
                    user: proc.user,
                    startTime: proc.startTime,
                    arguments: proc.arguments
                )
            )
            await onUpdate(updated)
        }
        Self.logger.debug("Signature backfill complete for \(processes.count) processes")
    }

    // MARK: - Private Helpers

    /// The sealed system volume already supplies the integrity boundary, but
    /// trust decisions still need the stable signing identifier. Reading the
    /// identifier does not perform the expensive certificate/resource check.
    private func sealedSystemSigningStatus(path: String) -> SigningStatus {
        let url = URL(fileURLWithPath: path) as CFURL
        var staticCode: SecStaticCode?
        guard SecStaticCodeCreateWithPath(url, [], &staticCode) == errSecSuccess,
              let staticCode else { return .unknown }

        var info: CFDictionary?
        let flags = SecCSFlags(rawValue: kSecCSSigningInformation)
        guard SecCodeCopySigningInformation(staticCode, flags, &info) == errSecSuccess,
              let dictionary = info as? [String: Any],
              let signingID = dictionary[kSecCodeInfoIdentifier as String] as? String,
              !signingID.isEmpty else {
            return .signed(teamID: "APPLE_PLATFORM")
        }
        return .signed(teamID: "APPLE_PLATFORM", signingID: signingID)
    }

    private func performStaticCheck(path: String) -> SigningStatus {
        let url = URL(fileURLWithPath: path) as CFURL

        var staticCode: SecStaticCode?
        let createStatus = SecStaticCodeCreateWithPath(url, [], &staticCode)
        guard createStatus == errSecSuccess, let code = staticCode else {
            Self.logger.debug("SecStaticCodeCreateWithPath failed for \(path): \(createStatus)")
            return .unknown
        }

        // Process inventory needs to establish whether the running executable has
        // a valid code signature; it must not recursively hash every resource in
        // the containing app bundle. A full resource-envelope validation can take
        // seconds for large apps and previously monopolized a CPU core at launch.
        // File/deep scans retain their own full-integrity validation paths.
        let validationFlags = SecCSFlags(rawValue: UInt32(kSecCSDoNotValidateResources))
        let validationStatus = SecStaticCodeCheckValidity(code, validationFlags, nil)

        switch validationStatus {
        case errSecSuccess:
            return extractSigningStatus(from: code, validationFlags: validationFlags)

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

    private func extractSigningStatus(
        from code: SecStaticCode,
        validationFlags: SecCSFlags
    ) -> SigningStatus {
        var info: CFDictionary?
        let flags = SecCSFlags(rawValue: kSecCSSigningInformation)
        guard SecCodeCopySigningInformation(code, flags, &info) == errSecSuccess,
              let dict = info as? [String: Any] else { return .unknown }

        let teamID = dict[kSecCodeInfoTeamIdentifier as String] as? String
        let signingID = dict[kSecCodeInfoIdentifier as String] as? String
        let hasTeamID = !(teamID ?? "").isEmpty
        return Self.statusForValidSignature(
            teamID: teamID,
            signingID: signingID,
            isAppleAnchored: !hasTeamID && satisfies("anchor apple", code: code, validationFlags: validationFlags),
            isAppleIssued: hasTeamID && satisfies("anchor apple generic", code: code, validationFlags: validationFlags)
        )
    }

    /// Maps a cryptographically valid signature to a trust status.
    ///
    /// - A Team Identifier establishes identity only under a certificate chain
    ///   issued by Apple (`anchor apple generic`). A self-signed certificate can
    ///   put any string in the Team ID field, so without the Apple chain the
    ///   signature carries no more identity than an ad-hoc one.
    /// - Apple ships some nested Xcode utilities without a Team ID; those are
    ///   recognised by the Apple anchor itself. A certificate chain alone is not
    ///   enough because a self-signed binary may also carry certificates.
    static func statusForValidSignature(
        teamID: String?,
        signingID: String? = nil,
        isAppleAnchored: Bool,
        isAppleIssued: Bool
    ) -> SigningStatus {
        if let teamID, !teamID.isEmpty {
            return isAppleIssued ? .signed(teamID: teamID, signingID: signingID) : .adHoc
        }
        if isAppleAnchored {
            return .signed(teamID: "APPLE_PLATFORM", signingID: signingID)
        }
        return .adHoc
    }

    private func satisfies(
        _ requirementText: String,
        code: SecStaticCode,
        validationFlags: SecCSFlags
    ) -> Bool {
        var requirement: SecRequirement?
        guard SecRequirementCreateWithString(
            requirementText as CFString,
            [],
            &requirement
        ) == errSecSuccess,
        let requirement else { return false }

        return SecStaticCodeCheckValidity(code, validationFlags, requirement) == errSecSuccess
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
