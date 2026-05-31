// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation

// MARK: - MonitorType

/// Identifies which Nick monitor subsystem produced a `ThreatSignal`.
///
/// Each case maps directly to one detection engine in `Core/`. The
/// `ThreatCorrelator` uses this value to weight and correlate signals
/// that arrive from multiple sources simultaneously.
enum MonitorType: String, Codable, Sendable, CaseIterable {

    // MARK: - Cases

    /// Signals from `ProcessMonitor` — unsigned binaries, suspicious paths, LOLBins.
    case process = "process"

    /// Signals from `PersistenceWatcher` — new or modified LaunchAgents/Daemons.
    case persistence = "persistence"

    /// Signals from `NetworkAnalyzer` — reverse shells, unexpected listeners.
    case network = "network"

    /// Signals from `FileSystemWatcher` — FSEvents on critical directories.
    case filesystem = "filesystem"

    /// Signals from `YARAEngine` — pattern-based file matches.
    case yara = "yara"

    /// Signals from `SystemAuditor` — SIP, FileVault, Gatekeeper, firewall state.
    case systemAudit = "systemAudit"

    /// Signals from the CoreML `BehavioralScorer` — correlated anomaly patterns.
    case behavioral = "behavioral"

    /// Signals from `AVCaptureMonitor` — camera and microphone activation by unexpected processes.
    case avCapture = "avCapture"

    /// Performance-engine signals — large caches, reclaimable disk space, junk files.
    case performance = "performance"

    // MARK: - Display Helpers

    /// Human-readable label suitable for UI presentation.
    var displayName: String {
        switch self {
        case .process:     return "Process Auditor"
        case .persistence: return "Persistence Watcher"
        case .network:     return "Network Watchdog"
        case .filesystem:  return "Filesystem Watcher"
        case .yara:        return "YARA Scanner"
        case .systemAudit: return "System Audit"
        case .behavioral:  return "AI Behavioral Scorer"
        case .avCapture:   return "Camera & Microphone"
        case .performance: return "Performance Engine"
        }
    }

    /// SF Symbol name for this monitor type.
    var systemImage: String {
        switch self {
        case .process:     return "gearshape.2"
        case .persistence: return "arrow.clockwise.circle"
        case .network:     return "network"
        case .filesystem:  return "folder.badge.questionmark"
        case .yara:        return "magnifyingglass.circle"
        case .systemAudit: return "checkmark.shield"
        case .behavioral:  return "brain"
        case .avCapture:   return "camera"
        case .performance: return "speedometer"
        }
    }
}
