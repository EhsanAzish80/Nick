// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation

// MARK: - ESEvent

/// A lightweight, Codable event emitted by the Endpoint Security System Extension
/// and forwarded to the container app via XPC.
///
/// `ESEvent` is intentionally minimal in Phase 1. It carries only the data needed
/// to display a live event log. Heavier correlation (into `ThreatSignal` /
/// `ThreatAlert`) happens inside `SecurityEngine` once Phase 2 wires the two
/// pipelines together.
///
/// This struct is compiled into **both** the `NickExtension` and `Nick` targets.
/// Add both targets to this file's "Target Membership" in Xcode.
///
/// - Note: Using `Int32` for PID matches `audit_token_to_pid` return type and
///   avoids implicit conversions across the XPC boundary.
public struct ESEvent: Codable, Identifiable, Sendable {

    // MARK: - Properties

    public let id: UUID
    public let timestamp: Date

    /// The ES event category (e.g. `"AUTH_EXEC"`, `"NOTIFY_OPEN"`).
    public let eventType: ESEventType

    /// Absolute path to the executable that triggered the event.
    public let processPath: String

    /// PID of the process that triggered the event.
    public let pid: Int32

    /// PID of the triggering process's parent.
    public let parentPid: Int32

    /// Absolute path of the file involved (nil for process-only events).
    public let filePath: String?

    /// Decision taken for AUTH events; `.notApplicable` for NOTIFY events.
    public let decision: ESDecision

    /// SHA-256 hash of the file involved, if computed by the scanner.
    public let sha256: String?

    /// Human-readable name of the matched threat signature (e.g. `"Trojan.Mac.Genieo"`).
    /// `nil` when no signature matched or scanning was not performed.
    public let threatName: String?

    /// Malware family of the matched threat (e.g. `"Adware"`). `nil` when no match.
    public let threatFamily: String?

    /// Code-signing validity of the process or target binary.
    /// `nil` when signing was not evaluated for this event type.
    public let isCodeSigned: Bool?

    // MARK: - Init

    public init(
        id: UUID = UUID(),
        timestamp: Date = Date(),
        eventType: ESEventType,
        processPath: String,
        pid: Int32,
        parentPid: Int32,
        filePath: String? = nil,
        decision: ESDecision,
        sha256: String? = nil,
        threatName: String? = nil,
        threatFamily: String? = nil,
        isCodeSigned: Bool? = nil
    ) {
        self.id = id
        self.timestamp = timestamp
        self.eventType = eventType
        self.processPath = processPath
        self.pid = pid
        self.parentPid = parentPid
        self.filePath = filePath
        self.decision = decision
        self.sha256 = sha256
        self.threatName = threatName
        self.threatFamily = threatFamily
        self.isCodeSigned = isCodeSigned
    }
}

// MARK: - ESEventType

/// Subset of `es_event_type_t` cases represented as strings for safe XPC transfer.
public enum ESEventType: String, Codable, Sendable {
    case authExec    = "AUTH_EXEC"
    case authOpen    = "AUTH_OPEN"
    case notifyOpen  = "NOTIFY_OPEN"
    case notifyFork  = "NOTIFY_FORK"
    case notifyExit  = "NOTIFY_EXIT"
    case notifyWrite = "NOTIFY_WRITE"
    case unknown     = "UNKNOWN"
}

// MARK: - ESDecision

/// The AUTH decision taken for an event.
public enum ESDecision: String, Codable, Sendable {
    /// Event was allowed to proceed.
    case allow
    /// Event was denied (process blocked / file access denied).
    case deny
    /// Not applicable — event was a NOTIFY (informational) event.
    case notApplicable
}
