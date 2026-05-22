// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation

// MARK: - FeatureVector

/// A 40-dimensional feature vector extracted from a correlation window of threat signals.
///
/// `FeatureVector` is the input to the on-device CoreML behavioral scoring model.
/// Each property is normalized to a well-defined range (boolean 0/1, floats 0.0–1.0,
/// or bounded integers) to ensure stable model inference. A vector must always be fully
/// populated — missing data defaults to 0 rather than nil or NaN.
///
/// - Note: Fields map 1-to-1 with the `feature_schema.json` training schema.
///         Changing names or ordering here requires retraining the model.
struct FeatureVector: Sendable, Codable {

    // MARK: - Process Features (1–10)

    /// Feature 1: Binary has no valid code signature (0 or 1).
    var processIsUnsigned: Double

    /// Feature 2: Signed but no team identifier — common for local dev builds (0 or 1).
    var processIsAdHocSigned: Double

    /// Feature 3: Process is executing from /tmp or /var/tmp (0 or 1).
    var processInTmp: Double

    /// Feature 4: Process path contains a hidden directory component (0 or 1).
    var processInHiddenDir: Double

    /// Feature 5: Process is bash, zsh, sh, python, ruby, or perl (0 or 1).
    var processIsShell: Double

    /// Feature 6: Parent process is a .app bundle (GUI application) (0 or 1).
    var processParentIsGuiApp: Double

    /// Feature 7: Parent process is Terminal, iTerm2, or Warp (0 or 1).
    var processParentIsTerminal: Double

    /// Feature 8: Depth of the parent-child process chain (0–10, clamped).
    var processParentChainDepth: Double

    /// Feature 9: Seconds elapsed since the process started (unbounded float).
    var processAgeSeconds: Double

    /// Feature 10: Process is a known living-off-the-land binary (0 or 1).
    var processIsLolbin: Double

    // MARK: - Network Features (11–17)

    /// Feature 11: Process has an ESTABLISHED outbound TCP connection (0 or 1).
    var netHasOutboundConnection: Double

    /// Feature 12: Connected to a raw IP address with no DNS resolution (0 or 1).
    var netRemoteIsRawIP: Double

    /// Feature 13: Remote port number (integer cast to Double).
    var netRemotePort: Double

    /// Feature 14: Remote port is a common service port (80, 443, 22, 53) (0 or 1).
    var netRemotePortIsCommon: Double

    /// Feature 15: Process has a listening socket (0 or 1).
    var netIsListening: Double

    /// Feature 16: Total number of active network connections for this process.
    var netConnectionCount: Double

    /// Feature 17: Remote port is not in the common service list (0 or 1).
    var netUsesUncommonPort: Double

    // MARK: - File System Features (18–24)

    /// Feature 18: Related file event is in a temp directory (0 or 1).
    var fsFileInTmp: Double

    /// Feature 19: Shannon entropy of the associated file (0.0–8.0).
    var fsFileEntropy: Double

    /// Feature 20: File entropy is above the high-entropy threshold of 7.5 (0 or 1).
    var fsFileEntropyIsHigh: Double

    /// Feature 21: Associated file is a Mach-O binary (0 or 1).
    var fsFileIsMacho: Double

    /// Feature 22: File contains embedded URL or IP address strings (0 or 1).
    var fsFileHasEmbeddedURLs: Double

    /// Feature 23: File contains base64-encoded blobs (0 or 1).
    var fsFileHasEmbeddedBase64: Double

    /// Feature 24: 10 or more files were created in 5 seconds in temp dirs (0 or 1).
    var fsRapidCreationDetected: Double

    // MARK: - Persistence Features (25–29)

    /// Feature 25: A new LaunchAgent plist appeared during the window (0 or 1).
    var persistNewLaunchAgent: Double

    /// Feature 26: A new LaunchDaemon plist appeared during the window (0 or 1).
    var persistNewLaunchDaemon: Double

    /// Feature 27: A new cron entry was created during the window (0 or 1).
    var persistNewCronjob: Double

    /// Feature 28: The persistence mechanism's target executable is unsigned (0 or 1).
    var persistExecutableUnsigned: Double

    /// Feature 29: The persistence mechanism points to a nonexistent file (0 or 1).
    var persistExecutableMissing: Double

    // MARK: - YARA Features (30–31)

    /// Feature 30: Total number of YARA rule matches in the window.
    var yaraMatchCount: Double

    /// Feature 31: Highest severity among matched YARA rules (0–4, maps to SignalSeverity).
    var yaraMaxSeverity: Double

    // MARK: - System Audit Features (32–35)

    /// Feature 32: System Integrity Protection is disabled (0 or 1).
    var auditSipDisabled: Double

    /// Feature 33: FileVault full-disk encryption is off (0 or 1).
    var auditFilevaultDisabled: Double

    /// Feature 34: Gatekeeper is disabled (0 or 1).
    var auditGatekeeperDisabled: Double

    /// Feature 35: Application Firewall is off (0 or 1).
    var auditFirewallDisabled: Double

    // MARK: - Temporal Features (36–40)

    /// Feature 36: Seconds between file creation event and process start event.
    var temporalTimeSinceFileCreation: Double

    /// Feature 37: Seconds between process start and first observed network connection.
    var temporalTimeSinceNetConnection: Double

    /// Feature 38: Total count of signals from all monitors within the 30-second window.
    var temporalSignalsInWindow: Double

    /// Feature 39: Number of distinct monitor types that fired signals in the window.
    var temporalUniqueMonitorsFiring: Double

    /// Feature 40: Signal severity escalated (increased) within the correlation window (0 or 1).
    var temporalSeverityEscalation: Double

    // MARK: - Init

    /// Creates a fully zeroed feature vector.
    ///
    /// Use this as a baseline and set only the features that have real data.
    /// Zero is always the "safe" default — it represents absence of a signal.
    init() {
        processIsUnsigned = 0
        processIsAdHocSigned = 0
        processInTmp = 0
        processInHiddenDir = 0
        processIsShell = 0
        processParentIsGuiApp = 0
        processParentIsTerminal = 0
        processParentChainDepth = 0
        processAgeSeconds = 0
        processIsLolbin = 0
        netHasOutboundConnection = 0
        netRemoteIsRawIP = 0
        netRemotePort = 0
        netRemotePortIsCommon = 0
        netIsListening = 0
        netConnectionCount = 0
        netUsesUncommonPort = 0
        fsFileInTmp = 0
        fsFileEntropy = 0
        fsFileEntropyIsHigh = 0
        fsFileIsMacho = 0
        fsFileHasEmbeddedURLs = 0
        fsFileHasEmbeddedBase64 = 0
        fsRapidCreationDetected = 0
        persistNewLaunchAgent = 0
        persistNewLaunchDaemon = 0
        persistNewCronjob = 0
        persistExecutableUnsigned = 0
        persistExecutableMissing = 0
        yaraMatchCount = 0
        yaraMaxSeverity = 0
        auditSipDisabled = 0
        auditFilevaultDisabled = 0
        auditGatekeeperDisabled = 0
        auditFirewallDisabled = 0
        temporalTimeSinceFileCreation = 0
        temporalTimeSinceNetConnection = 0
        temporalSignalsInWindow = 0
        temporalUniqueMonitorsFiring = 0
        temporalSeverityEscalation = 0
    }

    // MARK: - Public API

    /// Returns the feature values as an ordered array of Doubles.
    ///
    /// The order matches the column order in `feature_schema.json` and the CoreML
    /// model's expected input order. Changing this order breaks model inference.
    var asArray: [Double] {
        [
            processIsUnsigned,
            processIsAdHocSigned,
            processInTmp,
            processInHiddenDir,
            processIsShell,
            processParentIsGuiApp,
            processParentIsTerminal,
            processParentChainDepth,
            processAgeSeconds,
            processIsLolbin,
            netHasOutboundConnection,
            netRemoteIsRawIP,
            netRemotePort,
            netRemotePortIsCommon,
            netIsListening,
            netConnectionCount,
            netUsesUncommonPort,
            fsFileInTmp,
            fsFileEntropy,
            fsFileEntropyIsHigh,
            fsFileIsMacho,
            fsFileHasEmbeddedURLs,
            fsFileHasEmbeddedBase64,
            fsRapidCreationDetected,
            persistNewLaunchAgent,
            persistNewLaunchDaemon,
            persistNewCronjob,
            persistExecutableUnsigned,
            persistExecutableMissing,
            yaraMatchCount,
            yaraMaxSeverity,
            auditSipDisabled,
            auditFilevaultDisabled,
            auditGatekeeperDisabled,
            auditFirewallDisabled,
            temporalTimeSinceFileCreation,
            temporalTimeSinceNetConnection,
            temporalSignalsInWindow,
            temporalUniqueMonitorsFiring,
            temporalSeverityEscalation,
        ]
    }

    /// Human-readable names for each feature, in the same order as `asArray`.
    static let featureNames: [String] = [
        "process_is_unsigned",
        "process_is_adhoc_signed",
        "process_in_tmp",
        "process_in_hidden_dir",
        "process_is_shell",
        "process_parent_is_gui_app",
        "process_parent_is_terminal",
        "process_parent_chain_depth",
        "process_age_seconds",
        "process_is_lolbin",
        "net_has_outbound_connection",
        "net_remote_is_raw_ip",
        "net_remote_port",
        "net_remote_port_is_common",
        "net_is_listening",
        "net_connection_count",
        "net_uses_uncommon_port",
        "fs_file_in_tmp",
        "fs_file_entropy",
        "fs_file_entropy_is_high",
        "fs_file_is_macho",
        "fs_file_has_embedded_urls",
        "fs_file_has_embedded_base64",
        "fs_rapid_creation_detected",
        "persist_new_launchagent",
        "persist_new_launchdaemon",
        "persist_new_cronjob",
        "persist_executable_unsigned",
        "persist_executable_missing",
        "yara_match_count",
        "yara_max_severity",
        "audit_sip_disabled",
        "audit_filevault_disabled",
        "audit_gatekeeper_disabled",
        "audit_firewall_disabled",
        "temporal_time_since_file_creation",
        "temporal_time_since_net_connection",
        "temporal_signals_in_window",
        "temporal_unique_monitors_firing",
        "temporal_severity_escalation",
    ]
}
