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
    ///   - context: Optional process/network/file context and metadata.
    init(
        id: UUID = UUID(),
        source: MonitorType,
        severity: SignalSeverity,
        timestamp: Date = Date(),
        title: String,
        description: String,
        context: ThreatSignalContext = ThreatSignalContext()
    ) {
        self.id = id
        self.source = source
        self.severity = severity
        self.timestamp = timestamp
        self.title = title
        self.description = description
        self.processInfo = context.processInfo
        self.networkInfo = context.networkInfo
        self.fileInfo = context.fileInfo
        self.metadata = context.metadata
    }
}

// MARK: - ThreatSignalContext

/// Groups the optional forensic context parameters for a `ThreatSignal`,
/// reducing the initialiser's parameter count to satisfy code quality limits.
struct ThreatSignalContext: Sendable {

    /// Process metadata when the signal is associated with a running process.
    var processInfo: NickProcessInfo?

    /// Network connection metadata when the signal involves a network event.
    var networkInfo: NetworkConnectionInfo?

    /// File metadata when the signal is associated with a file on disk.
    var fileInfo: FileInfo?

    /// Freeform key-value pairs that carry monitor-specific context for correlation.
    var metadata: [String: String]

    init(
        processInfo: NickProcessInfo? = nil,
        networkInfo: NetworkConnectionInfo? = nil,
        fileInfo: FileInfo? = nil,
        metadata: [String: String] = [:]
    ) {
        self.processInfo = processInfo
        self.networkInfo = networkInfo
        self.fileInfo = fileInfo
        self.metadata = metadata
    }
}

// MARK: - Evidence

/// Versioned evidence accepted by the shared correlation and incident pipeline.
///
/// Unlike the original monitor-specific signal envelope, this type makes the
/// subject, file identity, rule class, and observation interval explicit. The
/// legacy `ThreatSignal` conversion remains available while existing monitors
/// migrate one at a time.
struct Evidence: Identifiable, Sendable, Codable, Equatable {
    static let currentSchemaVersion = 1

    let schemaVersion: Int
    let id: UUID
    let source: MonitorType
    let subject: EvidenceSubjectIdentity
    let fileIdentity: EvidenceFileIdentity?
    let severity: SignalSeverity
    let ruleClass: EvidenceRuleClass
    let timestamps: EvidenceTimestamps
    let title: String
    let summary: String
    let processInfo: NickProcessInfo?
    let networkInfo: NetworkConnectionInfo?
    let metadata: [String: String]

    init(
        schemaVersion: Int = Evidence.currentSchemaVersion,
        id: UUID = UUID(),
        source: MonitorType,
        subject: EvidenceSubjectIdentity,
        fileIdentity: EvidenceFileIdentity? = nil,
        severity: SignalSeverity,
        ruleClass: EvidenceRuleClass,
        timestamps: EvidenceTimestamps = EvidenceTimestamps(),
        title: String,
        summary: String,
        processInfo: NickProcessInfo? = nil,
        networkInfo: NetworkConnectionInfo? = nil,
        metadata: [String: String] = [:]
    ) {
        self.schemaVersion = schemaVersion
        self.id = id
        self.source = source
        self.subject = subject
        self.fileIdentity = fileIdentity
        self.severity = severity
        self.ruleClass = ruleClass
        self.timestamps = timestamps
        self.title = title
        self.summary = summary
        self.processInfo = processInfo
        self.networkInfo = networkInfo
        self.metadata = metadata
    }

    init(signal: ThreatSignal) {
        self.init(
            id: signal.id,
            source: signal.source,
            subject: EvidenceSubjectIdentity(signal: signal),
            fileIdentity: signal.fileInfo.map {
                EvidenceFileIdentity(fileInfo: $0, metadata: signal.metadata)
            },
            severity: signal.severity,
            ruleClass: EvidenceRuleClass(signal: signal),
            timestamps: EvidenceTimestamps(
                observedAt: signal.timestamp,
                firstSeen: signal.timestamp,
                lastSeen: signal.timestamp
            ),
            title: signal.title,
            summary: signal.description,
            processInfo: signal.processInfo,
            networkInfo: signal.networkInfo,
            metadata: signal.metadata
        )
    }

    var threatSignal: ThreatSignal {
        ThreatSignal(
            id: id,
            source: source,
            severity: severity,
            timestamp: timestamps.observedAt,
            title: title,
            description: summary,
            context: ThreatSignalContext(
                processInfo: processInfo,
                networkInfo: networkInfo,
                fileInfo: fileIdentity?.fileInfo,
                metadata: metadata
            )
        )
    }
}

enum EvidenceSubjectKind: String, Sendable, Codable {
    case process
    case file
    case network
    case system
}

/// Stable identity for the thing the evidence describes.
struct EvidenceSubjectIdentity: Sendable, Codable, Equatable {
    let kind: EvidenceSubjectKind
    let stableIdentifier: String
    let processIdentifier: Int32?
    let processStartTime: Date?
    let executablePath: String?
    let signingTeamID: String?
    let signingIdentifier: String?

    init(
        kind: EvidenceSubjectKind,
        stableIdentifier: String,
        processIdentifier: Int32? = nil,
        processStartTime: Date? = nil,
        executablePath: String? = nil,
        signingTeamID: String? = nil,
        signingIdentifier: String? = nil
    ) {
        self.kind = kind
        self.stableIdentifier = stableIdentifier
        self.processIdentifier = processIdentifier
        self.processStartTime = processStartTime
        self.executablePath = executablePath
        self.signingTeamID = signingTeamID
        self.signingIdentifier = signingIdentifier
    }

    init(signal: ThreatSignal) {
        if let process = signal.processInfo {
            let signingIdentity: (String?, String?)
            if case .signed(let teamID, let signingID) = process.signingStatus {
                signingIdentity = (teamID, signingID)
            } else {
                signingIdentity = (nil, nil)
            }
            self.init(
                kind: .process,
                stableIdentifier: "process:\(process.pid):\(Self.normalized(process.path))",
                processIdentifier: process.pid,
                processStartTime: process.startTime,
                executablePath: process.path,
                signingTeamID: signingIdentity.0,
                signingIdentifier: signingIdentity.1
            )
        } else if let file = signal.fileInfo {
            self.init(
                kind: .file,
                stableIdentifier: "file:\(file.sha256Hash?.lowercased() ?? Self.normalized(file.path))"
            )
        } else if let network = signal.networkInfo {
            self.init(
                kind: .network,
                stableIdentifier: [
                    "network", String(network.pid),
                    network.remoteAddress?.lowercased() ?? "local",
                    network.remotePort.map(String.init) ?? "none",
                    network.transportProtocol.rawValue.lowercased()
                ].joined(separator: ":")
            )
        } else {
            let path = signal.metadata["path"].map(Self.normalized) ?? ""
            self.init(
                kind: path.isEmpty ? .system : .file,
                stableIdentifier: path.isEmpty
                    ? "system:\(signal.source.rawValue):\(signal.metadata["reason"] ?? signal.title)"
                    : "file:\(path)"
            )
        }
    }

    private static func normalized(_ path: String) -> String {
        guard !path.isEmpty else { return "" }
        return URL(fileURLWithPath: path).standardizedFileURL.path.lowercased()
    }
}

/// File identity captured with evidence. Device/inode/mtime are optional until
/// each source can collect them without reopening the file by path.
struct EvidenceFileIdentity: Sendable, Codable, Equatable {
    let path: String
    let deviceID: UInt64?
    let inode: UInt64?
    let modificationTime: TimeInterval?
    let sha256Hash: String?
    let sizeBytes: Int?
    let entropy: Double?
    let signingStatus: SigningStatus?

    init(
        path: String,
        deviceID: UInt64? = nil,
        inode: UInt64? = nil,
        modificationTime: TimeInterval? = nil,
        sha256Hash: String? = nil,
        sizeBytes: Int? = nil,
        entropy: Double? = nil,
        signingStatus: SigningStatus? = nil
    ) {
        self.path = path
        self.deviceID = deviceID
        self.inode = inode
        self.modificationTime = modificationTime
        self.sha256Hash = sha256Hash
        self.sizeBytes = sizeBytes
        self.entropy = entropy
        self.signingStatus = signingStatus
    }

    init(fileInfo: FileInfo, metadata: [String: String]) {
        self.init(
            path: fileInfo.path,
            deviceID: metadata["device_id"].flatMap(UInt64.init),
            inode: metadata["inode"].flatMap(UInt64.init),
            modificationTime: metadata["modification_time"].flatMap(TimeInterval.init),
            sha256Hash: fileInfo.sha256Hash,
            sizeBytes: fileInfo.sizeBytes,
            entropy: fileInfo.entropy,
            signingStatus: fileInfo.signingStatus
        )
    }

    var fileInfo: FileInfo {
        FileInfo(
            path: path,
            sha256Hash: sha256Hash,
            entropy: entropy,
            signingStatus: signingStatus,
            sizeBytes: sizeBytes
        )
    }
}

enum EvidenceRuleClass: String, Sendable, Codable, CaseIterable {
    case signature
    case behavior
    case policy
    case integrity
    case persistence
    case network
    case privacy
    case audit
    case unknown

    init(signal: ThreatSignal) {
        if let declared = signal.metadata["class"]?.trimmingCharacters(in: .whitespacesAndNewlines).lowercased(),
           let value = EvidenceRuleClass(rawValue: declared) {
            self = value
            return
        }
        switch signal.source {
        case .yara:
            self = YARAVerdictPolicy.ruleClass(
                ruleName: signal.metadata["rule"] ?? signal.title,
                metadata: signal.metadata
            ) == .signature ? .signature : .behavior
        case .process, .behavioral: self = .behavior
        case .persistence: self = .persistence
        case .network: self = .network
        case .filesystem: self = .integrity
        case .systemAudit: self = .audit
        case .avCapture: self = .privacy
        case .performance: self = .policy
        }
    }
}

struct EvidenceTimestamps: Sendable, Codable, Equatable {
    let observedAt: Date
    let firstSeen: Date
    let lastSeen: Date

    init(
        observedAt: Date = Date(),
        firstSeen: Date? = nil,
        lastSeen: Date? = nil
    ) {
        self.observedAt = observedAt
        self.firstSeen = firstSeen ?? observedAt
        self.lastSeen = lastSeen ?? observedAt
    }
}
