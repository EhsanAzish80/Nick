// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation
import Darwin

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
    static let currentSchemaVersion = 3

    let schemaVersion: Int
    let id: UUID
    let source: MonitorType
    let subject: EvidenceSubjectIdentity
    let signingIdentity: EvidenceSigningIdentity?
    let fileIdentity: EvidenceFileIdentity?
    let severity: SignalSeverity
    let ruleClass: EvidenceRuleClass
    let ruleID: String?
    let ruleTier: EvidenceRuleTier?
    let parentChain: [EvidenceAncestorIdentity]?
    /// False while evidence is derived from the legacy single-parent metadata.
    /// ML must not treat an incomplete chain as a stable learning key.
    let parentChainIsComplete: Bool?
    let pathClass: EvidencePathClass?
    let destinationClass: EvidenceDestinationClass?
    let lifecycle: EvidenceLifecycle?
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
        signingIdentity: EvidenceSigningIdentity? = nil,
        fileIdentity: EvidenceFileIdentity? = nil,
        severity: SignalSeverity,
        ruleClass: EvidenceRuleClass,
        ruleID: String? = nil,
        ruleTier: EvidenceRuleTier? = nil,
        parentChain: [EvidenceAncestorIdentity]? = nil,
        parentChainIsComplete: Bool? = nil,
        pathClass: EvidencePathClass? = nil,
        destinationClass: EvidenceDestinationClass? = nil,
        lifecycle: EvidenceLifecycle? = nil,
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
        self.signingIdentity = signingIdentity
        self.fileIdentity = fileIdentity
        self.severity = severity
        self.ruleClass = ruleClass
        self.ruleID = ruleID
        self.ruleTier = ruleTier
        self.parentChain = parentChain.map { Array($0.prefix(8)) }
        self.parentChainIsComplete = parentChainIsComplete
        self.pathClass = pathClass
        self.destinationClass = destinationClass
        self.lifecycle = lifecycle
        self.timestamps = timestamps
        self.title = title
        self.summary = summary
        self.processInfo = processInfo
        self.networkInfo = networkInfo
        self.metadata = metadata
    }

    init(signal: ThreatSignal) {
        let ruleClass = EvidenceRuleClass(signal: signal)
        self.init(
            id: signal.id,
            source: signal.source,
            subject: EvidenceSubjectIdentity(signal: signal),
            signingIdentity: EvidenceSigningIdentity(signal: signal),
            fileIdentity: signal.fileInfo.map {
                EvidenceFileIdentity(fileInfo: $0, metadata: signal.metadata)
            },
            severity: signal.severity,
            ruleClass: ruleClass,
            ruleID: EvidenceRulePolicy.ruleID(for: signal),
            ruleTier: EvidenceRulePolicy.tier(for: signal, ruleClass: ruleClass),
            parentChain: EvidenceAncestorIdentity.parentChain(signal: signal),
            parentChainIsComplete: false,
            pathClass: EvidencePathClass(signal: signal, userHomePath: Self.consoleUserHomePath()),
            destinationClass: EvidenceDestinationClass(signal: signal),
            lifecycle: EvidenceLifecycle(
                verdict: .unreviewed,
                actor: .automatic,
                timestamp: signal.timestamp
            ),
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

    private static func consoleUserHomePath() -> String? {
        var consoleStat = stat()
        guard stat("/dev/console", &consoleStat) == 0,
              let passwordEntry = getpwuid(consoleStat.st_uid),
              let directory = passwordEntry.pointee.pw_dir else { return nil }
        return String(cString: directory)
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

enum EvidenceSigningKind: String, Sendable, Codable {
    case signed
    case adHoc
    case unsigned
    case invalid
    case unknown
    case pending
}

/// Explicit signing state used by future learning gates. Unsigned and ad-hoc
/// subjects are values, not an ambiguous absence of identity.
struct EvidenceSigningIdentity: Sendable, Codable, Equatable {
    let kind: EvidenceSigningKind
    let teamID: String?
    let signingIdentifier: String?

    init(kind: EvidenceSigningKind, teamID: String? = nil, signingIdentifier: String? = nil) {
        self.kind = kind
        self.teamID = teamID
        self.signingIdentifier = signingIdentifier
    }

    init(signal: ThreatSignal) {
        guard let status = signal.processInfo?.signingStatus ?? signal.fileInfo?.signingStatus else {
            self.init(kind: .unknown)
            return
        }
        switch status {
        case .signed(let teamID, let signingID):
            self.init(kind: .signed, teamID: teamID, signingIdentifier: signingID)
        case .adHoc: self.init(kind: .adHoc)
        case .unsigned: self.init(kind: .unsigned)
        case .invalid: self.init(kind: .invalid)
        case .unknown: self.init(kind: .unknown)
        case .pending: self.init(kind: .pending)
        }
    }
}

enum EvidenceRuleTier: String, Sendable, Codable {
    case review
    case protectedDetection
}

/// Fail-closed policy for future learning. Only explicitly named low-risk
/// rules may become reviewable; unknown and security-sensitive evidence stays
/// protected even when metadata is incomplete.
enum EvidenceRulePolicy {
    private static let reviewRuleIDs: Set<String> = [
        "system_hardening",
    ]

    static func ruleID(for signal: ThreatSignal) -> String {
        if let rule = signal.metadata["rule"], !rule.isEmpty { return rule }
        if let reason = signal.metadata["reason"], !reason.isEmpty { return reason }
        let normalizedTitle = signal.title.lowercased()
            .replacingOccurrences(of: "[^a-z0-9]+", with: "-", options: .regularExpression)
            .trimmingCharacters(in: CharacterSet(charactersIn: "-"))
        return "\(signal.source.rawValue):unclassified:\(normalizedTitle.isEmpty ? signal.id.uuidString : normalizedTitle)"
    }

    static func tier(for signal: ThreatSignal, ruleClass: EvidenceRuleClass) -> EvidenceRuleTier {
        let ruleID = ruleID(for: signal)
        let pathClass = EvidencePathClass(signal: signal, userHomePath: nil)
        let hasHash = !(signal.fileInfo?.sha256Hash ?? signal.metadata["sha256"] ?? "").isEmpty
        let protectedSource = signal.source == .yara || signal.source == .persistence
        let protectedClass = ruleClass == .signature || ruleClass == .persistence || ruleClass == .integrity
        let highRiskPath = pathClass == .temporary || pathClass == .system
        guard !hasHash, !protectedSource, !protectedClass, !highRiskPath,
              reviewRuleIDs.contains(ruleID) else {
            return .protectedDetection
        }
        return .review
    }
}

struct EvidenceAncestorIdentity: Sendable, Codable, Equatable {
    let executablePath: String?
    let teamID: String?
    let signingIdentifier: String?

    static func parentChain(signal: ThreatSignal) -> [EvidenceAncestorIdentity] {
        guard signal.processInfo != nil else { return [] }
        let ancestor = EvidenceAncestorIdentity(
            executablePath: signal.metadata["parent_path"],
            teamID: signal.metadata["parent_team_id"],
            signingIdentifier: signal.metadata["parent_signing_id"]
        )
        guard ancestor.executablePath != nil || ancestor.teamID != nil || ancestor.signingIdentifier != nil else {
            return []
        }
        return [ancestor]
    }
}

enum EvidencePathClass: String, Sendable, Codable {
    case temporary
    case user
    case application
    case system
    case volume
    case other
    case unknown

    init(signal: ThreatSignal, userHomePath: String? = nil) {
        let path = signal.fileInfo?.path ?? signal.processInfo?.path ?? signal.metadata["path"]
        guard let path else { self = .unknown; return }
        if path.hasPrefix("/private/tmp/") || path.hasPrefix("/tmp/") || path.hasPrefix("/private/var/folders/") {
            self = .temporary
        } else if let userHomePath,
                  path == userHomePath || path.hasPrefix(userHomePath + "/") {
            self = .user
        } else if path.hasPrefix("/Applications/") {
            self = .application
        } else if path.hasPrefix("/System/") || path.hasPrefix("/usr/") || path.hasPrefix("/private/etc/") {
            self = .system
        } else if path.hasPrefix("/Volumes/") {
            self = .volume
        } else {
            self = .other
        }
    }
}

enum EvidenceDestinationClass: String, Sendable, Codable {
    case local
    case domain
    case ipAddress
    case unknown

    init(signal: ThreatSignal) {
        guard let address = signal.networkInfo?.remoteAddress, !address.isEmpty else {
            self = .unknown
            return
        }
        if address == "localhost" || address.hasPrefix("127.") || address == "::1" {
            self = .local
        } else if Self.isIPAddress(address) {
            self = .ipAddress
        } else {
            self = .domain
        }
    }

    private static func isIPAddress(_ value: String) -> Bool {
        var ipv4 = in_addr()
        var ipv6 = in6_addr()
        return value.withCString { pointer in
            inet_pton(AF_INET, pointer, &ipv4) == 1 || inet_pton(AF_INET6, pointer, &ipv6) == 1
        }
    }
}

enum EvidenceVerdict: String, Sendable, Codable {
    case unreviewed
    case allowed
    case dismissed
    case quarantined
}

enum EvidenceVerdictActor: String, Sendable, Codable {
    case user
    case automatic
    case migration
}

struct EvidenceLifecycle: Sendable, Codable, Equatable {
    let verdict: EvidenceVerdict
    let actor: EvidenceVerdictActor
    let timestamp: Date
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
