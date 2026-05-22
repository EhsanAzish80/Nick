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

    init() {}

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
    private func featureDescription(for featureName: String) -> String {
        switch featureName {
        case "process_is_unsigned":         return "Binary has no valid code signature"
        case "process_is_adhoc_signed":     return "Signed but no team identifier"
        case "process_in_tmp":              return "Executing from temporary directory"
        case "process_in_hidden_dir":       return "Running from a hidden folder"
        case "process_is_shell":            return "Process is a shell interpreter"
        case "process_parent_is_gui_app":   return "Spawned from a GUI application"
        case "process_parent_is_terminal":  return "Spawned from a terminal"
        case "process_parent_chain_depth":  return "Deep process chain depth"
        case "process_age_seconds":         return "Process recently started"
        case "process_is_lolbin":           return "Living-off-the-land binary"
        case "net_has_outbound_connection": return "Active outbound TCP connection"
        case "net_remote_is_raw_ip":        return "Connected to raw IP address"
        case "net_remote_port":             return "Specific remote port"
        case "net_remote_port_is_common":   return "Using common service port"
        case "net_is_listening":            return "Process is listening on a socket"
        case "net_connection_count":        return "Multiple active connections"
        case "net_uses_uncommon_port":      return "Connecting on unusual port"
        case "fs_file_in_tmp":              return "File is in temp directory"
        case "fs_file_entropy":             return "High file entropy (encrypted/packed)"
        case "fs_file_entropy_is_high":     return "File entropy exceeds 7.5"
        case "fs_file_is_macho":            return "File is an executable binary"
        case "fs_file_has_embedded_urls":   return "File contains embedded URLs"
        case "fs_file_has_embedded_base64": return "File contains encoded data"
        case "fs_rapid_creation_detected":  return "Rapid file creation in temp dir"
        case "persist_new_launchagent":     return "New LaunchAgent persistence"
        case "persist_new_launchdaemon":    return "New LaunchDaemon persistence"
        case "persist_new_cronjob":         return "New cron job entry"
        case "persist_executable_unsigned": return "Persistence target is unsigned"
        case "persist_executable_missing":  return "Persistence target doesn't exist"
        case "yara_match_count":            return "Matched malware patterns"
        case "yara_max_severity":           return "High severity YARA match"
        case "audit_sip_disabled":          return "System Integrity Protection off"
        case "audit_filevault_disabled":    return "FileVault disk encryption off"
        case "audit_gatekeeper_disabled":   return "Gatekeeper disabled"
        case "audit_firewall_disabled":     return "Application Firewall off"
        case "temporal_time_since_file_creation":  return "Rapid file-to-process sequence"
        case "temporal_time_since_net_connection": return "Rapid process-to-network sequence"
        case "temporal_signals_in_window":  return "Many concurrent signals"
        case "temporal_unique_monitors_firing":    return "Multiple monitors triggered"
        case "temporal_severity_escalation": return "Severity increased over time"
        default:                            return featureName.replacingOccurrences(of: "_", with: " ")
        }
    }
}
