// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation

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
}

// MARK: - RemediationReport

/// Summary of every action taken in response to a detected threat.
/// Serialised as JSON and passed over XPC.
public struct RemediationReport: Codable, Sendable {
    public let timestamp: Date
    public let threatPath: String
    public let threatName: String
    /// `nil` when quarantine failed (file was deleted as fallback).
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

    public init(
        path: String,
        violationType: ViolationType,
        expectedHash: String?,
        actualHash: String?,
        timestamp: Date
    ) {
        self.id = UUID()
        self.path = path
        self.violationType = violationType
        self.expectedHash = expectedHash
        self.actualHash = actualHash
        self.timestamp = timestamp
    }
}
