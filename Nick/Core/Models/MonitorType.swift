import Foundation

/// Identifies which monitor subsystem produced a signal.
enum MonitorType: String, Codable, CaseIterable, Sendable {
    case processAudit      = "ProcessAudit"
    case persistenceWatch  = "PersistenceWatch"
    case networkAnalysis   = "NetworkAnalysis"
    case fileSystemWatch   = "FileSystemWatch"
    case yaraEngine        = "YARAEngine"
    case systemAudit       = "SystemAudit"
    case behavioralScorer  = "BehavioralScorer"
}
