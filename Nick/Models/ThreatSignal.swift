// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation

// MARK: - FileInfo

/// File metadata captured when a threat signal is associated with a specific file on disk.
///
/// Used by `YARAEngine`, `FileSystemWatcher`, and `ProcessMonitor` to provide
/// forensic context for a detection event. All properties are optional because
/// metadata collection may be incomplete (e.g., hash computation on a large file
/// may be deferred, or file permissions may prevent reading).
struct FileInfo: Sendable, Codable, Equatable {

    /// Absolute path to the file.
    let path: String

    /// SHA-256 hash of the file contents, if computed.
    let sha256Hash: String?

    /// Shannon entropy of the file (0.0–8.0). High values suggest encryption or packing.
    let entropy: Double?

    /// Code-signing status of the file, if evaluated.
    let signingStatus: SigningStatus?

    /// File size in bytes.
    let sizeBytes: Int?
}

// MARK: - ThreatSignal

/// The universal event type emitted by all Nick monitor subsystems.
///
/// Every detection — a suspicious process, a new persistence item, a failed
/// system check — is modelled as a `ThreatSignal`. Signals are ingested by the
/// `ThreatCorrelator`, which applies rules to combine them into scored `ThreatAlert`
/// objects for the user interface.
///
/// Signals are immutable value types. Once created by a monitor they are never
/// modified; the correlator only reads them.
///
/// - Note: The `description` property stores a full-sentence human explanation of
///         the detected event. It deliberately shadows `CustomStringConvertible.description`
///         in name only — `ThreatSignal` does not conform to that protocol.
struct ThreatSignal: Identifiable, Sendable, Codable, Equatable {

    // MARK: - Properties

    /// Stable identifier, unique across the lifetime of the app.
    let id: UUID

    /// Which monitor produced this signal.
    let source: MonitorType

    /// How severe this individual signal is before correlation.
    let severity: SignalSeverity

    /// When the signal was created.
    let timestamp: Date

    /// Short, single-line summary (e.g. "Unsigned binary in /tmp").
    let title: String

    /// Full-sentence explanation of the detection, suitable for the alert detail view.
    let description: String

    /// Process metadata when the signal is associated with a running process.
    let processInfo: NickProcessInfo?

    /// Network connection metadata when the signal involves a network event.
    let networkInfo: NetworkConnectionInfo?

    /// File metadata when the signal is associated with a file on disk.
    let fileInfo: FileInfo?

    /// Freeform key-value pairs that carry monitor-specific context for correlation.
    let metadata: [String: String]

    // MARK: - Initialiser

    /// Creates a new `ThreatSignal`.
    ///
    /// - Parameters:
    ///   - id: Unique identifier. Defaults to a new `UUID`.
    ///   - source: The monitor that detected this event.
    ///   - severity: Initial severity before correlation.
    ///   - timestamp: Detection time. Defaults to `Date()`.
    ///   - title: Short summary string.
    ///   - description: Full human-readable explanation.
    ///   - processInfo: Optional process context.
    ///   - networkInfo: Optional network context.
    ///   - fileInfo: Optional file context.
    ///   - metadata: Optional freeform key-value context.
    init(
        id: UUID = UUID(),
        source: MonitorType,
        severity: SignalSeverity,
        timestamp: Date = Date(),
        title: String,
        description: String,
        processInfo: NickProcessInfo? = nil,
        networkInfo: NetworkConnectionInfo? = nil,
        fileInfo: FileInfo? = nil,
        metadata: [String: String] = [:]
    ) {
        self.id = id
        self.source = source
        self.severity = severity
        self.timestamp = timestamp
        self.title = title
        self.description = description
        self.processInfo = processInfo
        self.networkInfo = networkInfo
        self.fileInfo = fileInfo
        self.metadata = metadata
    }
}
