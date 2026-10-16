// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation

public enum QuarantineFailureReason: String, Codable, Sendable, Equatable {
    case readOnlyVolume
    case permissionDenied
    case fileGone
    case fileChanged
    case inUse
    case protectionDisconnected
    case other
}

public struct QuarantineFailure: Codable, Sendable, Equatable, Error {
    public let reason: QuarantineFailureReason
    public let errorDomain: String
    public let errorCode: Int
    public let volumeName: String?
    /// A bounded, user-facing explanation supplied by the protection service
    /// when no more specific structured failure reason applies.
    public let message: String?

    public init(
        reason: QuarantineFailureReason,
        errorDomain: String,
        errorCode: Int,
        volumeName: String? = nil,
        message: String? = nil
    ) {
        self.reason = reason
        self.errorDomain = errorDomain
        self.errorCode = errorCode
        self.volumeName = volumeName
        self.message = message
    }

    public var statusLine: String {
        if let message, !message.isEmpty { return message }
        return switch reason {
        case .readOnlyVolume: "Quarantine failed — the file is on a read-only disk image"
        case .permissionDenied: "Quarantine failed — macOS denied permission to move the file"
        case .fileGone: "The file is no longer present"
        case .fileChanged: "Quarantine failed — the file changed after Nick reviewed it"
        case .inUse: "Quarantine failed — the file is currently in use"
        case .protectionDisconnected: "Real-Time Protection is not connected"
        case .other: "Quarantine failed — error \(errorDomain) \(errorCode)"
        }
    }

    public var guidance: String {
        switch reason {
        case .readOnlyVolume:
            "Eject the disk image and delete the .dmg file it came from; Nick cannot move files off a read-only volume."
        case .permissionDenied:
            "Leave the file unopened and review its permissions or System Integrity Protection status before retrying."
        case .fileGone:
            "No further quarantine action is needed because the file is no longer present."
        case .fileChanged:
            "Rescan the file before trying to quarantine it again."
        case .inUse:
            "Quit the app using the file, then retry quarantine."
        case .protectionDisconnected:
            "Open Settings and reconnect Real-Time Protection, then retry quarantine."
        case .other:
            "Leave the file unopened and retry quarantine. If it fails again, review the recorded error code."
        }
    }
}

// MARK: - File identity

/// The on-disk identity of file content at a specific point in time.
/// Paths are intentionally excluded because they can be reused after review.
struct FileIdentity: Hashable, Sendable {
    let device: Int64
    let inode: UInt64
    let size: Int64
    let modificationSeconds: Int
    let modificationNanoseconds: Int

    init(stat info: stat) {
        device = Int64(info.st_dev)
        inode = UInt64(info.st_ino)
        size = Int64(info.st_size)
        modificationSeconds = Int(info.st_mtimespec.tv_sec)
        modificationNanoseconds = Int(info.st_mtimespec.tv_nsec)
    }

    /// Identity of the file content reached by `path`; `nil` when it no longer
    /// exists. `stat` intentionally follows a final symlink so the identity
    /// matches the file reported by Endpoint Security authorization events.
    init?(path: String) {
        var info = stat()
        guard stat(path, &info) == 0 else { return nil }
        self.init(stat: info)
    }
}

/// A one-use approval for the exact file that the user reviewed.
struct OneTimeFileAllowance: Sendable {
    let identity: FileIdentity
    let sha256: String

    func permits(_ currentIdentity: FileIdentity, sha256 currentHash: String) -> Bool {
        identity == currentIdentity && sha256 == currentHash
    }
}

enum ReviewedFileAllowancePolicy {
    static func permits(
        reviewed: FileIdentity?,
        reviewedHash: String,
        current: FileIdentity,
        currentHash: String
    ) -> Bool {
        guard let reviewed, !reviewedHash.isEmpty, !currentHash.isEmpty else { return false }
        return reviewed == current && reviewedHash == currentHash
    }
}

enum QuarantineMovePolicy {
    static func matchesReviewedFile(
        reviewedIdentity: FileIdentity,
        reviewedHash: String,
        currentIdentity: FileIdentity,
        currentHash: String
    ) -> Bool {
        !reviewedHash.isEmpty
            && reviewedIdentity == currentIdentity
            && reviewedHash == currentHash
    }
}

enum FIMAcknowledgementPolicy {
    static func canAcknowledge(_ violation: IntegrityViolation, currentHash: String?) -> Bool {
        switch violation.violationType {
        case .deleted:
            return currentHash == nil
        case .created, .modified:
            return currentHash != nil && currentHash == violation.actualHash
        }
    }
}

enum EndpointSecurityPath {
    /// Resolves the path exactly as the kernel does without collapsing the
    /// canonical `/private/tmp` and `/private/var` spellings used by Endpoint
    /// Security into their user-facing aliases.
    static func canonical(_ path: String) -> String? {
        guard let resolved = realpath(path, nil) else { return nil }
        defer { free(resolved) }
        return String(cString: resolved)
    }
}

enum FileIntegrityPathPolicy {
    static func isMonitored(
        _ path: String,
        configuredPaths: [String],
        directoryPaths: Set<String>
    ) -> Bool {
        configuredPaths.contains { configuredPath in
            if directoryPaths.contains(configuredPath) {
                return path == configuredPath || path.hasPrefix(configuredPath + "/")
            }
            return path == configuredPath
        }
    }
}

// MARK: - QuarantineRecord

/// A file that has been moved to the quarantine vault.
/// Serialised as JSON and passed over XPC.
public struct QuarantineRecord: Codable, Sendable, Identifiable {
    public let id: UUID
    public let originalPath: String
    public let quarantinedPath: String
    public let hash: String
    public let threatName: String
    public let severity: String
    public let quarantinedAt: Date
    public let processPath: String
    public let pid: Int32
    /// Ownership and mode captured before Nick moves the file into its vault.
    /// These are optional so records written by earlier releases remain decodable.
    public let originalOwnerID: UInt32?
    public let originalGroupID: UInt32?
    public let originalPermissions: UInt16?
    /// True when quarantine moved the reviewed file into the vault but a later
    /// vault step failed after another file occupied the original path.
    public let isIncomplete: Bool

    public init(
        id: UUID,
        originalPath: String,
        quarantinedPath: String,
        hash: String,
        threatName: String,
        severity: String,
        quarantinedAt: Date,
        processPath: String,
        pid: Int32,
        originalOwnerID: UInt32? = nil,
        originalGroupID: UInt32? = nil,
        originalPermissions: UInt16? = nil,
        isIncomplete: Bool = false
    ) {
        self.id = id
        self.originalPath = originalPath
        self.quarantinedPath = quarantinedPath
        self.hash = hash
        self.threatName = threatName
        self.severity = severity
        self.quarantinedAt = quarantinedAt
        self.processPath = processPath
        self.pid = pid
        self.originalOwnerID = originalOwnerID
        self.originalGroupID = originalGroupID
        self.originalPermissions = originalPermissions
        self.isIncomplete = isIncomplete
    }

    private enum CodingKeys: String, CodingKey {
        case id, originalPath, quarantinedPath, hash, threatName, severity
        case quarantinedAt, processPath, pid, originalOwnerID, originalGroupID
        case originalPermissions, isIncomplete
    }

    public init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        id = try values.decode(UUID.self, forKey: .id)
        originalPath = try values.decode(String.self, forKey: .originalPath)
        quarantinedPath = try values.decode(String.self, forKey: .quarantinedPath)
        hash = try values.decode(String.self, forKey: .hash)
        threatName = try values.decode(String.self, forKey: .threatName)
        severity = try values.decode(String.self, forKey: .severity)
        quarantinedAt = try values.decode(Date.self, forKey: .quarantinedAt)
        processPath = try values.decode(String.self, forKey: .processPath)
        pid = try values.decode(Int32.self, forKey: .pid)
        originalOwnerID = try values.decodeIfPresent(UInt32.self, forKey: .originalOwnerID)
        originalGroupID = try values.decodeIfPresent(UInt32.self, forKey: .originalGroupID)
        originalPermissions = try values.decodeIfPresent(UInt16.self, forKey: .originalPermissions)
        isIncomplete = try values.decodeIfPresent(Bool.self, forKey: .isIncomplete) ?? false
    }
}

enum QuarantineRestorePolicy {
    static func canonicalPathForLegacyRecord(_ path: String) -> String {
        let standardized = URL(fileURLWithPath: path).standardizedFileURL.path
        for (alias, canonical) in [
            ("/tmp", "/private/tmp"),
            ("/var", "/private/var"),
            ("/etc", "/private/etc")
        ] where standardized == alias || standardized.hasPrefix(alias + "/") {
            return canonical + String(standardized.dropFirst(alias.count))
        }
        return standardized
    }

    static func restoredPermissions(_ storedPermissions: UInt16?) -> UInt16 {
        (storedPermissions ?? 0o600) & 0o1777
    }
}

// MARK: - RemediationReport

/// Summary of every action taken in response to a detected threat.
/// Serialised as JSON and passed over XPC.
public struct RemediationReport: Codable, Sendable {
    public let timestamp: Date
    public let threatPath: String
    public let threatName: String
    /// `nil` when quarantine failed. The original file remains in place.
    public let quarantineRecord: QuarantineRecord?
    public let actions: [RemediationAction]
}

// MARK: - RemediationAction

/// A single step performed by the remediation engine.
public struct RemediationAction: Codable, Sendable {

    public enum ActionType: String, Codable, Sendable {
        case quarantineFile
        case killProcess
        case removeLaunchItem
        case removeCronJob
        case removeLoginItem
    }

    public let type: ActionType
    public let target: String
    public let success: Bool
    public let detail: String
    public let quarantineFailure: QuarantineFailure?

    public init(
        type: ActionType,
        target: String,
        success: Bool,
        detail: String,
        quarantineFailure: QuarantineFailure? = nil
    ) {
        self.type = type
        self.target = target
        self.success = success
        self.detail = detail
        self.quarantineFailure = quarantineFailure
    }
}

// MARK: - IntegrityViolation

/// A File Integrity Monitor event: a monitored path was created, modified, or deleted.
/// Serialised as JSON and passed over XPC.
public struct IntegrityViolation: Codable, Sendable, Identifiable {

    public enum ViolationType: String, Codable, Sendable {
        case modified   // hash changed from baseline
        case created    // new file in monitored directory
        case deleted    // baselined file no longer exists
    }

    public let id: UUID
    public let path: String
    public let violationType: ViolationType
    public let expectedHash: String?
    public let actualHash: String?
    public let timestamp: Date
    public let metadata: [String: String]?

    public init(
        id: UUID = UUID(),
        path: String,
        violationType: ViolationType,
        expectedHash: String?,
        actualHash: String?,
        timestamp: Date,
        metadata: [String: String]? = nil
    ) {
        self.id = id
        self.path = path
        self.violationType = violationType
        self.expectedHash = expectedHash
        self.actualHash = actualHash
        self.timestamp = timestamp
        self.metadata = metadata
    }
}
