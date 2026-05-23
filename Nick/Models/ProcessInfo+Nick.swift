// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation

// MARK: - SigningStatus

/// Code-signing status of a binary evaluated by `SignatureValidator`.
///
/// Used in both `NickProcessInfo` (running processes) and `PersistenceItem`
/// (persisted executables). Explicit `Codable` implementation is provided
/// because the `.signed(teamID:)` associated value requires a custom
/// encoding strategy for reliable round-tripping.
enum SigningStatus: Sendable, Equatable {

    // MARK: - Cases

    /// Validly signed by an Apple Developer account with the given team identifier.
    case signed(teamID: String)

    /// Signed but without a team identifier — common for local development builds.
    case adHoc

    /// No code signature present.
    case unsigned

    /// Signature is present but fails cryptographic validation (tampered binary).
    case invalid

    /// Status cannot be determined — file not found or permission denied.
    case unknown

    /// Validation has not yet run — assigned on the fast first scan; replaced
    /// asynchronously by `SignatureValidator.backfill(processes:onUpdate:)`.
    case pending

    // MARK: - Display Helpers

    /// Human-readable label for UI presentation.
    var displayName: String {
        switch self {
        case .signed(let id): return "Signed (\(id))"
        case .adHoc:          return "Ad-Hoc Signed"
        case .unsigned:       return "Unsigned"
        case .invalid:        return "Invalid Signature"
        case .unknown:        return "Unknown"
        case .pending:        return "Checking…"
        }
    }

    /// Whether this status represents a security concern.
    var isSuspicious: Bool {
        switch self {
        case .signed:   return false
        case .adHoc:    return false   // Common for legitimate dev tools
        case .unsigned: return true
        case .invalid:  return true
        case .unknown:  return false
        case .pending:  return false   // Not yet evaluated — withhold judgment
        }
    }
}

// MARK: - SigningStatus + Codable

extension SigningStatus: Codable {

    private enum CodingKeys: String, CodingKey {
        case type, teamID
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case .signed(let teamID):
            try container.encode("signed", forKey: .type)
            try container.encode(teamID, forKey: .teamID)
        case .adHoc:
            try container.encode("adHoc", forKey: .type)
        case .unsigned:
            try container.encode("unsigned", forKey: .type)
        case .invalid:
            try container.encode("invalid", forKey: .type)
        case .unknown:
            try container.encode("unknown", forKey: .type)
        case .pending:
            try container.encode("pending", forKey: .type)
        }
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let type = try container.decode(String.self, forKey: .type)
        switch type {
        case "signed":
            let teamID = try container.decodeIfPresent(String.self, forKey: .teamID) ?? ""
            self = .signed(teamID: teamID)
        case "adHoc":
            self = .adHoc
        case "unsigned":
            self = .unsigned
        case "invalid":
            self = .invalid
        case "pending":
            self = .pending
        default:
            self = .unknown
        }
    }
}

// MARK: - NickProcessInfo

/// Snapshot of a running process captured at detection time.
///
/// Named `NickProcessInfo` to avoid collision with Foundation's `ProcessInfo`
/// singleton. All properties are immutable — this is a value captured once
/// and stored in a `ThreatSignal` for correlation and display.
///
/// - Note: `startTime` may be `nil` when the kernel does not return timing
///         information for a particular process (rare, seen for kthreads).
struct NickProcessInfo: Sendable, Codable, Equatable {

    // MARK: - Properties

    /// BSD process identifier.
    let pid: Int32

    /// Absolute path to the process executable, if resolvable via `proc_pidpath`.
    let path: String

    /// Process name as reported by the kernel (up to 15 chars for `kinfo_proc`).
    let name: String

    /// PID of this process's parent.
    let parentPID: Int32

    /// Name of the parent process, resolved from the parent PID when available.
    let parentName: String?

    /// Code-signing evaluation result for the executable at `path`.
    let signingStatus: SigningStatus

    /// Username owning this process, resolved from its UID.
    let user: String?

    /// Time the process was created, derived from `kp_proc.p_starttime`.
    let startTime: Date?

    /// Command-line arguments retrieved via `KERN_PROCARGS2`.
    /// Empty for processes where argument retrieval was not performed or failed.
    let arguments: [String]
}

// MARK: - Backwards-Compatible Initialiser

extension NickProcessInfo {
    /// Creates a `NickProcessInfo` without argument data.
    /// All existing construction sites use this; `arguments` defaults to `[]`.
    init(
        pid: Int32,
        path: String,
        name: String,
        parentPID: Int32,
        parentName: String?,
        signingStatus: SigningStatus,
        user: String?,
        startTime: Date?
    ) {
        self.init(
            pid: pid, path: path, name: name, parentPID: parentPID,
            parentName: parentName, signingStatus: signingStatus,
            user: user, startTime: startTime, arguments: []
        )
    }
}
