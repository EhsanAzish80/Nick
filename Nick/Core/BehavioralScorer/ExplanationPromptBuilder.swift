// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation

// MARK: - ExplanationPromptBuilder

/// Builds structured prompts for the Foundation Models on-device LLM.
///
/// Produces a well-formed English prompt that instructs the model to write a
/// 2–3 sentence plain-language explanation of a threat detection. The prompt
/// is deterministic and fully populated — it never passes `nil` or empty strings
/// to the model.
///
/// On macOS 14–15 (no Foundation Models), use `buildTemplatedExplanation(for:topFeatures:)`
/// instead of calling `buildPrompt(for:topFeatures:)`.
///
/// - Note: This type is stateless and thread-safe.
final class ExplanationPromptBuilder {

    // MARK: - Init

    init() {
        // Creates a new instance. No configuration required.
    }

    // MARK: - Public API

    /// Builds a Foundation Models prompt for a given alert and feature contributions.
    ///
    /// - Parameters:
    ///   - alert: The correlated threat alert to explain.
    ///   - topFeatures: Up to 5 ranked feature contributions from `BehavioralScorer`.
    /// - Returns: A fully-formed prompt string ready for Foundation Models inference.
    func buildPrompt(for alert: ThreatAlert, topFeatures: [(name: String, contribution: Double)]) -> String {
        let score = String(format: "%.2f", alert.score)
        let severity = alert.severity.displayName
        let factorsText = buildFactorsText(topFeatures)
        let context = buildContext(from: alert)

        return """
        You are a macOS security analyst explaining a threat detection to a non-technical user.

        DETECTION SUMMARY:
        - Threat score: \(score) out of 1.0
        - Severity: \(severity)
        - Title: \(alert.title)

        CONTRIBUTING FACTORS (ranked by importance):
        \(factorsText)

        CONTEXT:
        \(context)

        Write a 2-3 sentence explanation in plain English. Explain what happened, why it's suspicious, and what the user should consider doing. Do not use jargon. Do not be alarmist.
        """
    }

    /// Builds a human-readable templated explanation without Foundation Models.
    ///
    /// Used on macOS 14–15 where Foundation Models is unavailable. Selects the
    /// most appropriate template based on the top contributing features.
    ///
    /// - Parameters:
    ///   - alert: The correlated threat alert to explain.
    ///   - topFeatures: Up to 5 ranked feature contributions from `BehavioralScorer`.
    /// - Returns: A plain-English 2-3 sentence explanation string.
    func buildTemplatedExplanation(for alert: ThreatAlert, topFeatures: [(name: String, contribution: Double)]) -> String {
        let topNames = Set(topFeatures.map { $0.name })
        let processPath = alert.contributingSignals.compactMap { $0.processInfo?.path }.first ?? "an unknown process"
        let remoteIP    = alert.contributingSignals.compactMap { $0.networkInfo?.remoteAddress }.first ?? "a remote address"

        // Reverse shell pattern
        if topNames.contains("process_is_shell") && topNames.contains("net_has_outbound_connection") {
            return "Nick detected a shell process (\(processPath)) making an outbound network connection to \(remoteIP). " +
                   "This is a common pattern for reverse shells, where an attacker gains interactive access to your Mac. " +
                   "Consider terminating the process and checking for any unauthorized changes."
        }

        // Dropper / unsigned binary in /tmp pattern
        if topNames.contains("process_is_unsigned") && topNames.contains("process_in_tmp") {
            return "Nick detected an unsigned binary executing from a temporary directory (\(processPath)). " +
                   "Legitimate apps rarely run from temporary folders without a valid code signature. " +
                   "This is a common pattern for malware that downloads and executes payloads — review this process carefully."
        }

        // C2 callback pattern
        if topNames.contains("net_remote_is_raw_ip") && topNames.contains("net_uses_uncommon_port") {
            return "Nick detected a process connecting to a raw IP address on an unusual port at \(remoteIP). " +
                   "Malware often communicates with command-and-control servers using IP addresses (not domain names) to avoid DNS-based blocking. " +
                   "Investigate whether this connection is expected for \(processPath)."
        }

        // Persistence pattern
        if topNames.contains("persist_new_launchagent") || topNames.contains("persist_new_launchdaemon") {
            return "Nick detected a new persistence mechanism that will cause software to run automatically when your Mac starts. " +
                   "While some apps legitimately use this technique, it is also used by malware to survive reboots. " +
                   "Review the new startup item and remove it if you don't recognize it."
        }

        // YARA pattern
        if topNames.contains("yara_match_count") || topNames.contains("yara_max_severity") {
            return "Nick's pattern scanner matched known malware signatures associated with \(alert.title.lowercased()). " +
                   "This file or process matches patterns seen in malicious software. " +
                   "Avoid opening related files and consider removing the flagged item."
        }

        // Generic fallback
        return "Nick detected \(alert.title.lowercased()) with a threat score of \(String(format: "%.2f", alert.score)) out of 1.0. " +
               "Multiple suspicious signals were observed together, including activity from \(processPath). " +
               "\(alert.recommendedAction)"
    }

    // MARK: - Private Helpers

    private func buildFactorsText(_ topFeatures: [(name: String, contribution: Double)]) -> String {
        guard !topFeatures.isEmpty else { return "No specific contributing factors identified." }

        return topFeatures.enumerated().map { idx, feature in
            let num  = idx + 1
            let desc = featureDescription(for: feature.name)
            let pct  = String(format: "%.1f%%", feature.contribution * 100)
            return "\(num). \(feature.name): \(desc) (contribution: \(pct))"
        }.joined(separator: "\n")
    }

    private func buildContext(from alert: ThreatAlert) -> String {
        var parts: [String] = []

        if let proc = alert.contributingSignals.compactMap({ $0.processInfo }).first {
            parts.append("Process: \(proc.name) (PID \(proc.pid)) at \(proc.path)")
        }

        if let net = alert.contributingSignals.compactMap({ $0.networkInfo }).first,
           let remote = net.remoteAddress {
            parts.append("Network: \(net.transportProtocol.rawValue) connection to \(remote):\(net.remotePort ?? 0)")
        }

        if let file = alert.contributingSignals.compactMap({ $0.fileInfo }).first {
            parts.append("File: \(file.path)")
        }

        parts.append("Time: \(ISO8601DateFormatter().string(from: alert.timestamp))")
        parts.append("Contributing signals: \(alert.contributingSignals.count)")

        return parts.joined(separator: "\n")
    }

    /// Maps a feature name to a short human-readable description for the prompt.
    private static let featureDescriptions: [String: String] = [
        "process_is_unsigned":                    "Binary has no valid code signature",
        "process_is_adhoc_signed":                "Signed but no team identifier",
        "process_in_tmp":                         "Executing from temporary directory",
        "process_in_hidden_dir":                  "Running from a hidden folder",
        "process_is_shell":                       "Process is a shell interpreter",
        "process_parent_is_gui_app":              "Spawned from a GUI application",
        "process_parent_is_terminal":             "Spawned from a terminal",
        "process_parent_chain_depth":             "Deep process chain depth",
        "process_age_seconds":                    "Process recently started",
        "process_is_lolbin":                      "Living-off-the-land binary",
        "net_has_outbound_connection":            "Active outbound TCP connection",
        "net_remote_is_raw_ip":                   "Connected to raw IP address",
        "net_remote_port":                        "Specific remote port",
        "net_remote_port_is_common":              "Using common service port",
        "net_is_listening":                       "Process is listening on a socket",
        "net_connection_count":                   "Multiple active connections",
        "net_uses_uncommon_port":                 "Connecting on unusual port",
        "fs_file_in_tmp":                         "File is in temp directory",
        "fs_file_entropy":                        "High file entropy (encrypted/packed)",
        "fs_file_entropy_is_high":                "File entropy exceeds 7.5",
        "fs_file_is_macho":                       "File is an executable binary",
        "fs_file_has_embedded_urls":              "File contains embedded URLs",
        "fs_file_has_embedded_base64":            "File contains encoded data",
        "fs_rapid_creation_detected":             "Rapid file creation in temp dir",
        "persist_new_launchagent":                "New LaunchAgent persistence",
        "persist_new_launchdaemon":               "New LaunchDaemon persistence",
        "persist_new_cronjob":                    "New cron job entry",
        "persist_executable_unsigned":            "Persistence target is unsigned",
        "persist_executable_missing":             "Persistence target doesn't exist",
        "yara_match_count":                       "Matched malware patterns",
        "yara_max_severity":                      "High severity YARA match",
        "audit_sip_disabled":                     "System Integrity Protection off",
        "audit_filevault_disabled":               "FileVault disk encryption off",
        "audit_gatekeeper_disabled":              "Gatekeeper disabled",
        "audit_firewall_disabled":                "Application Firewall off",
        "temporal_time_since_file_creation":      "Rapid file-to-process sequence",
        "temporal_time_since_net_connection":     "Rapid process-to-network sequence",
        "temporal_signals_in_window":             "Many concurrent signals",
        "temporal_unique_monitors_firing":        "Multiple monitors triggered",
        "temporal_severity_escalation":           "Severity increased over time",
    ]

    private func featureDescription(for featureName: String) -> String {
        Self.featureDescriptions[featureName]
            ?? featureName.replacingOccurrences(of: "_", with: " ")
    }
}
