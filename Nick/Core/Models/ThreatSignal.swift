import Foundation

/// Severity level assigned to a detected signal.
enum ThreatSeverity: Int, Codable, Comparable, Sendable {
    case info     = 0
    case low      = 1
    case medium   = 2
    case high     = 3
    case critical = 4

    static func < (lhs: ThreatSeverity, rhs: ThreatSeverity) -> Bool {
        lhs.rawValue < rhs.rawValue
    }
}

/// A single detection event emitted by any monitor subsystem.
struct ThreatSignal: Identifiable, Codable, Sendable {
    let id: UUID
    let timestamp: Date
    let source: MonitorType
    let severity: ThreatSeverity
    let title: String
    let detail: String
    /// Optional process ID associated with the signal.
    let pid: Int32?
    /// Optional file path or network endpoint relevant to the signal.
    let resource: String?

    init(
        id: UUID = UUID(),
        timestamp: Date = Date(),
        source: MonitorType,
        severity: ThreatSeverity,
        title: String,
        detail: String,
        pid: Int32? = nil,
        resource: String? = nil
    ) {
        self.id = id
        self.timestamp = timestamp
        self.source = source
        self.severity = severity
        self.title = title
        self.detail = detail
        self.pid = pid
        self.resource = resource
    }
}
