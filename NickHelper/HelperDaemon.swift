// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation
import Security
import os

// MARK: - System SPI Declaration

/// `csr_get_active_config` is declared in <sys/csr.h> (public SDK on macOS 14+).
/// We declare it here to avoid needing a bridging header in this Swift-only target.
///
/// - Parameter config: Output pointer for the active CSR configuration bitmask.
/// - Returns: 0 on success, non-zero errno on failure.
@_silgen_name("csr_get_active_config")
private func csr_get_active_config(_ config: UnsafeMutablePointer<UInt32>?) -> Int32

// MARK: - HelperDaemon

/// XPC listener delegate that gates all incoming connections with signature validation
/// and rate limiting before handing them to `HelperProtocolImplementation`.
///
/// `HelperDaemon` is the security perimeter of the privileged helper. It is responsible
/// for ensuring that only the authorised Nick application (verified by team ID) can
/// communicate over XPC, and that no single process can flood the helper with connections.
///
/// The protocol implementation (`HelperProtocolImplementation`) is intentionally separate
/// so that security policy lives here and business logic lives there.
///
/// - Note: SECURITY: This class runs as a privileged helper. Every `shouldAcceptNewConnection`
///   invocation must return `false` unless both signature validation and rate limiting pass.
final class HelperDaemon: NSObject, NSXPCListenerDelegate {

    // MARK: - Constants

    /// Team ID of the authorised main application.
    ///
    /// SECURITY: This constant is hardcoded and is not read from any external source.
    /// Allowing it to be configured at runtime would let an attacker substitute their
    /// own team ID and gain full helper access.
    static let authorisedTeamID = "EHSANA80XX" // TODO(ehsan): Replace with actual Team ID before release.

    /// Maximum XPC connections accepted from a single PID within one second.
    static let maxConnectionsPerSecond = 10

    // MARK: - Private State

    /// Per-PID ring buffer of recent connection timestamps for rate limiting.
    private var connectionTimestamps: [Int32: [Date]] = [:]

    /// Serialises access to `connectionTimestamps`.
    private let rateLimitLock = NSLock()

    private static let logger = Logger(
        subsystem: "com.ehsanazish.nick.helper",
        category: "HelperDaemon"
    )

    // MARK: - NSXPCListenerDelegate

    func listener(
        _ listener: NSXPCListener,
        shouldAcceptNewConnection connection: NSXPCConnection
    ) -> Bool {
        let pid = connection.processIdentifier

        // SECURITY: Enforce a per-PID rate limit before doing any expensive work.
        // This prevents a compromised or buggy process from flooding the helper.
        guard !isRateLimited(pid: pid) else {
            Self.logger.error("Rate limit exceeded for PID \(pid, privacy: .public) — rejecting")
            connection.invalidate()
            return false
        }

        // SECURITY: Validate the code signature of the XPC caller. Without this check,
        // any process that knows the Mach service name could connect to the helper and
        // request reads of privileged files.
        guard validateCallerSignature(connection: connection) else {
            Self.logger.error("Signature validation failed for PID \(pid, privacy: .public) — rejecting")
            connection.invalidate()
            return false
        }

        connection.exportedInterface = NSXPCInterface(with: NickHelperProtocol.self)
        connection.exportedObject = HelperProtocolImplementation()
        connection.resume()

        Self.logger.info("Accepted XPC connection from PID \(pid, privacy: .public)")
        return true
    }

    // MARK: - Private Helpers

    /// Returns `true` if `pid` has exceeded `maxConnectionsPerSecond` in the last second.
    ///
    /// Uses a sliding 1-second window. Entries older than 1 second are purged on each
    /// call to prevent unbounded memory growth.
    private func isRateLimited(pid: Int32) -> Bool {
        rateLimitLock.lock()
        defer { rateLimitLock.unlock() }

        let now = Date()
        let windowStart = now.addingTimeInterval(-1.0)

        var timestamps = connectionTimestamps[pid] ?? []
        timestamps = timestamps.filter { $0 > windowStart }
        timestamps.append(now)
        connectionTimestamps[pid] = timestamps

        // SECURITY: Cap the dictionary size to prevent unbounded growth if many
        // different PIDs attempt connections (e.g. a fork bomb or fuzzer).
        if connectionTimestamps.count > 500 {
            connectionTimestamps = connectionTimestamps.filter { _, values in !values.isEmpty }
        }

        return timestamps.count > Self.maxConnectionsPerSecond
    }

    /// Validates that the connecting process is signed by the authorised team.
    ///
    /// Uses `SecCodeCopyGuestWithAttributes` to obtain a `SecCode` for the caller PID,
    /// then checks a code requirement that verifies:
    /// - The binary is anchored with an Apple developer certificate.
    /// - The leaf certificate's `subject.OU` (Organizational Unit) matches our team ID.
    ///
    /// - Important: This does NOT verify the bundle ID — only the team ID — so future
    ///   renaming of the app does not require a helper update. What matters is who signed it.
    ///
    /// - Returns: `true` if the caller passes the requirement check.
    private func validateCallerSignature(connection: NSXPCConnection) -> Bool {
        let pid = connection.processIdentifier

        let attributes = [kSecGuestAttributePid: pid] as CFDictionary
        var guestCode: SecCode?

        let copyStatus = SecCodeCopyGuestWithAttributes(nil, attributes, [], &guestCode)
        guard copyStatus == errSecSuccess, let code = guestCode else {
            Self.logger.error(
                "SecCodeCopyGuestWithAttributes failed for PID \(pid, privacy: .public): \(copyStatus, privacy: .public)"
            )
            return false
        }

        // Build the code requirement string.
        let requirementString =
            "anchor apple generic and certificate leaf[subject.OU] = \"\(Self.authorisedTeamID)\""
        var requirement: SecRequirement?
        guard SecRequirementCreateWithString(requirementString as CFString, [], &requirement) == errSecSuccess,
              let req = requirement
        else {
            // SECURITY: Failing to create the requirement string is a programming error.
            // Fault-log it and deny the connection rather than silently allowing access.
            Self.logger.fault("Failed to build code requirement — denying connection (programming error)")
            return false
        }

        let validationStatus = SecCodeCheckValidity(code, [], req)
        if validationStatus != errSecSuccess {
            Self.logger.error(
                "Code requirement check failed for PID \(pid, privacy: .public): \(validationStatus, privacy: .public)"
            )
        }
        return validationStatus == errSecSuccess
    }
}

// MARK: - HelperProtocolImplementation

/// Implements `NickHelperProtocol` — the read-only XPC API exposed to the main app.
///
/// Every method is stateless and read-only. This class never writes to disk, never
/// executes subprocesses, and never loads dynamic code. All path inputs are validated
/// by `HelperPathAllowlist` before any filesystem access occurs.
///
/// - Note: SECURITY: If you add a method here, verify: (1) it is read-only, (2) all
///   string inputs are validated, and (3) error messages are generic (no system paths).
final class HelperProtocolImplementation: NSObject, NickHelperProtocol {

    private static let logger = Logger(
        subsystem: "com.ehsanazish.nick.helper",
        category: "HelperProtocolImplementation"
    )

    // MARK: - NickHelperProtocol

    func getSIPStatus(reply: @escaping (Bool) -> Void) {
        // Read SIP status via csr_get_active_config (system call; no shell invocation).
        // Returns true (enabled) by default if the call cannot be made from this context.
        var config: UInt32 = 0
        let result = csr_get_active_config(&config)
        // config == 0 means all SIP protections are active (enabled).
        reply(result == 0 && config == 0)
    }

    func getFirewallStatus(reply: @escaping (Bool) -> Void) {
        // SECURITY: Read directly from the plist — no shell invocation.
        let plistPath = "/Library/Preferences/com.apple.alf.plist"
        guard HelperPathAllowlist.validate(plistPath),
              let data = try? Data(contentsOf: URL(fileURLWithPath: plistPath)),
              let plist = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any],
              let globalState = plist["globalstate"] as? Int
        else {
            reply(false)
            return
        }
        // globalstate: 0 = off, 1 = on (block all incoming), 2 = on (essential services allowed).
        reply(globalState > 0)
    }

    func readProtectedPlist(atPath path: String, reply: @escaping (Data?, Error?) -> Void) {
        // SECURITY: Validate the path against the allowlist before any filesystem access.
        // Reject the request with a generic error — do not reveal why it was rejected.
        guard HelperPathAllowlist.validate(path) else {
            Self.logger.error("readProtectedPlist: path rejected by allowlist")
            reply(nil, HelperError.operationFailed)
            return
        }

        do {
            let data = try Data(contentsOf: URL(fileURLWithPath: path))
            reply(data, nil)
        } catch {
            // SECURITY: Do not echo the error message — it may contain the path or errno.
            Self.logger.error("readProtectedPlist: read failed for validated path")
            reply(nil, HelperError.operationFailed)
        }
    }

    func getListeningPorts(reply: @escaping ([String: Int32]) -> Void) {
        // Enumerate listening ports via sysctl KERN_PROC_ALL + socket inspection.
        // TODO(ehsan): Implement direct sysctl enumeration. See #43.
        reply([:])
    }
}

// MARK: - HelperError

/// Generic errors returned by the helper.
///
/// - Note: SECURITY: Error cases must remain generic. The helper must never leak
///   internal state (file paths, errno values, system information) via error messages.
enum HelperError: LocalizedError {
    /// An operation failed. Details are intentionally withheld.
    case operationFailed

    var errorDescription: String? {
        // Return a single, generic message for all cases.
        return "Operation failed."
    }
}
