// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation
import SwiftData

// MARK: - ThreatLogEntry

/// A persistent record of a single `ThreatAlert`, stored via SwiftData.
///
/// `ThreatLogEntry` is the forensic log record for every alert Nick raises.
/// It persists across app launches and provides the data model for the
/// `ThreatLogView` table. Severity is stored as a `String` raw value so
/// SwiftData predicates can filter on it efficiently.
///
/// Retention policy is enforced by `ThreatLogger.pruneOlderThan(days:)`.
///
/// - Note: `contributingSignalIDs` and `contributingSignalSummaries` are
///   parallel arrays — index N in IDs corresponds to index N in Summaries.
@Model
final class ThreatLogEntry {

    // MARK: - Core Identity

    /// Stable UUID copied from the source `ThreatAlert`.
    var id: UUID

    /// When the alert was raised.
    var timestamp: Date

    // MARK: - Alert Content

    /// Short display title from the alert.
    var alertTitle: String

    /// Full description of why the alert was raised.
    var alertDescription: String

    /// Natural-language explanation from `AlertExplainer` (may be `nil` if generation failed).
    var explanation: String?

    /// CoreML/rule confidence score in [0, 1].
    var score: Double

    /// Severity raw value (`"low"`, `"medium"`, `"high"`, `"critical"`).
    /// Stored as String for efficient SwiftData predicate queries.
    var severity: String

    // MARK: - Contributing Signals

    /// IDs of the `ThreatSignal` values that produced this alert.
    var contributingSignalIDs: [UUID]

    /// Human-readable one-line summaries of each contributing signal.
    var contributingSignalSummaries: [String]

    // MARK: - Process Context

    /// Absolute path of the primary process involved, if known.
    var processPath: String?

    /// Display name (last path component) of the primary process.
    var processName: String?

    /// PID of the primary process at alert time.
    var processPID: Int32?

    // MARK: - Network Context

    /// Remote IP or hostname involved in the alert, if applicable.
    var remoteAddress: String?

    /// Remote port number involved in the alert, if applicable.
    var remotePort: Int?

    // MARK: - File Context

    /// Path of the primary file involved in the alert, if applicable.
    var filePath: String?

    // MARK: - Resolution State

    /// Whether this alert has been reviewed and resolved by the user.
    var resolved: Bool

    /// Optional note left by the user when resolving the alert.
    var resolvedNote: String?

    // MARK: - Init

    /// Creates a new log entry from raw field values.
    init(
        id: UUID = UUID(),
        timestamp: Date = Date(),
        content: ThreatLogContent,
        forensics: ThreatLogForensics = ThreatLogForensics(),
        resolved: Bool = false,
        resolvedNote: String? = nil
    ) {
        self.id = id
        self.timestamp = timestamp
        self.alertTitle = content.alertTitle
        self.alertDescription = content.alertDescription
        self.explanation = content.explanation
        self.score = content.score
        self.severity = content.severity
        self.contributingSignalIDs = forensics.contributingSignalIDs
        self.contributingSignalSummaries = forensics.contributingSignalSummaries
        self.processPath = forensics.processPath
        self.processName = forensics.processName
        self.processPID = forensics.processPID
        self.remoteAddress = forensics.remoteAddress
        self.remotePort = forensics.remotePort
        self.filePath = forensics.filePath
        self.resolved = resolved
        self.resolvedNote = resolvedNote
    }

    // MARK: - Convenience Init

    /// Creates a log entry from a `ThreatAlert`.
    ///
    /// Extracts process, network, and file context from the alert's contributing signals.
    ///
    /// - Parameters:
    ///   - alert: The alert to persist.
    ///   - explanation: Pre-generated natural-language explanation, if available.
    convenience init(from alert: ThreatAlert, explanation: String? = nil) {
        let procInfo  = alert.contributingSignals.compactMap { $0.processInfo }.first
        let netInfo   = alert.contributingSignals.compactMap { $0.networkInfo }.first
        let fileInfo  = alert.contributingSignals.compactMap { $0.fileInfo }.first

        self.init(
            id: alert.id,
            timestamp: alert.timestamp,
            content: ThreatLogContent(
                alertTitle: alert.title,
                alertDescription: alert.description,
                explanation: explanation ?? alert.explanation,
                score: alert.score,
                severity: alert.severity.displayName.lowercased()
            ),
            forensics: ThreatLogForensics(
                contributingSignalIDs: alert.contributingSignals.map { $0.id },
                contributingSignalSummaries: alert.contributingSignals.map { "\($0.source.rawValue): \($0.title)" },
                processPath: procInfo?.path,
                processName: procInfo?.name,
                processPID: procInfo.map { Int32($0.pid) },
                remoteAddress: netInfo?.remoteAddress,
                remotePort: netInfo?.remotePort,
                filePath: fileInfo?.path
            )
        )
    }
}

// MARK: - Schema Versioning

/// The v1.0 schema for `ThreatLogEntry`.
///
/// Defining a `VersionedSchema` now — even with no migrations yet — ensures that
/// future releases can add `MigrationStage` entries here rather than silently
/// deleting the user's persistent store on a schema change.
enum ThreatLogSchemaV1: VersionedSchema {
    static let versionIdentifier = Schema.Version(1, 0, 0)
    static var models: [any PersistentModel.Type] { [ThreatLogEntry.self] }
}

// MARK: - ThreatLogContent

/// Groups the five descriptive fields of a `ThreatLogEntry`, reducing the
/// designated initialiser's parameter count.
struct ThreatLogContent {
    let alertTitle: String
    let alertDescription: String
    var explanation: String?
    let score: Double
    let severity: String

    init(
        alertTitle: String,
        alertDescription: String,
        explanation: String? = nil,
        score: Double,
        severity: String
    ) {
        self.alertTitle = alertTitle
        self.alertDescription = alertDescription
        self.explanation = explanation
        self.score = score
        self.severity = severity
    }
}

// MARK: - ThreatLogForensics

/// Groups the eight optional forensic context fields of a `ThreatLogEntry`,
/// reducing the designated initialiser's parameter count.
struct ThreatLogForensics {
    var contributingSignalIDs: [UUID] = []
    var contributingSignalSummaries: [String] = []
    var processPath: String? = nil
    var processName: String? = nil
    var processPID: Int32? = nil
    var remoteAddress: String? = nil
    var remotePort: Int? = nil
    var filePath: String? = nil
}

/// Migration plan anchored to v1.0.
///
/// Add stages here for each subsequent release that changes `ThreatLogEntry`.
enum ThreatLogMigrationPlan: SchemaMigrationPlan {
    static var schemas: [any VersionedSchema.Type] { [ThreatLogSchemaV1.self] }
    /// No migrations needed for v1.0 — this is the initial schema.
    static var stages: [MigrationStage] { [] }
}
