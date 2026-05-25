// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation

// MARK: - CorrelationRule

/// A single rule evaluated by `ThreatCorrelator` against a window of signals.
///
/// Rules are composable: each rule defines a `match` closure that decides whether
/// a given set of signals constitutes the threat scenario and, if so, returns a
/// ready-to-emit `ThreatAlert`.
///
/// Adding new rules requires no changes to `ThreatCorrelator` — just append to
/// `CorrelationRule.standard`.
struct CorrelationRule: Sendable {

    /// Human-readable name used for debugging / logging.
    let name: String

    /// Confidence score (0–1) assigned to alerts produced by this rule.
    let score: Double

    /// The severity of alerts produced by this rule.
    let severity: SignalSeverity

    /// Evaluates the rule against a window of signals.
    ///
    /// - Parameter signals: All signals collected within the current correlation window.
    /// - Returns: A `ThreatAlert` if the rule matches, or `nil` otherwise.
    let evaluate: @Sendable ([ThreatSignal]) -> ThreatAlert?

    // MARK: - Standard Rule Set

    /// The hardcoded rules applied by `ThreatCorrelator` in Phase 1.
    static let standard: [CorrelationRule] = [
        criticalSystemAuditRule,
        systemHardeningRule,
        curlPipeShellRule,
        unsignedBinaryInTmpRule,
        reverseShellRule,
        unsignedLaunchAgentRule,
        sshKeysRule,
        shellProfileRule,
        unexpectedCaptureDeviceRule,
        lolbinRule,
        lolbinAdvancedRule,
        yaraMatchRule,
        parentChainRule,
        rawIpOutboundRule,
        multipleHighSignalsRule
    ]

    // MARK: - Rule Definitions

    /// Critical system configuration failure (SIP, FileVault, or Gatekeeper off).
    private static let criticalSystemAuditRule = CorrelationRule(
        name: "critical_system_audit",
        score: 0.9,
        severity: .critical
    ) { signals in
        let matches = signals.filter {
            $0.source == .systemAudit && $0.severity == .critical
        }
        guard let first = matches.first else { return nil }
        return ThreatAlert(
            score: 0.9,
            content: AlertContent(
                title: "Critical system security configuration issue",
                description: "A fundamental macOS security control (\(first.title)) is disabled. This significantly raises the risk of compromise.",
                severity: .critical,
                recommendedAction: first.description
            ),
            contributingSignals: matches
        )
    }

    /// Unsigned binary running from /tmp or similar writable directory.
    /// Also matches `temp_path_spawn` signals from the fast-check path, which fire
    /// before code-signing validation completes but still indicate high-risk placement.
    private static let unsignedBinaryInTmpRule = CorrelationRule(
        name: "unsigned_binary_in_tmp",
        score: 0.85,
        severity: .high
    ) { signals in
        let matches = signals.filter {
            $0.source == .process &&
            $0.severity == .high &&
            ($0.metadata["reason"] == "unsigned_temp_path" ||
             $0.metadata["reason"] == "temp_path_spawn")
        }
        guard !matches.isEmpty else { return nil }
        let names = matches.compactMap { $0.processInfo?.name }.joined(separator: ", ")
        return ThreatAlert(
            score: 0.85,
            content: AlertContent(
                title: "Unsigned binary executing from temporary directory",
                description: "Process(es) '\(names)' are unsigned and running from writable temporary locations — a common technique used by droppers and implants.",
                severity: .high,
                recommendedAction: "Terminate the process and investigate the file at the reported path."
            ),
            contributingSignals: matches
        )
    }

    /// Shell interpreter or netcat with an active outbound network connection (reverse shell indicator).
    /// Matches signals from both ConnectionScanner (reason: "reverse_shell") and
    /// ReverseShellDetector (reason: "reverse_shell_port", "netcat_connection", "temp_binary_network").
    private static let reverseShellRule = CorrelationRule(
        name: "reverse_shell",
        score: 0.95,
        severity: .critical
    ) { signals in
        let reverseShellReasons: Set<String> = [
            "reverse_shell", "reverse_shell_port", "netcat_connection", "temp_binary_network"
        ]
        let matches = signals.filter {
            $0.source == .network &&
            reverseShellReasons.contains($0.metadata["reason"] ?? "")
        }
        guard !matches.isEmpty else { return nil }
        let processes = matches.compactMap {
            $0.metadata["process"] ?? $0.processInfo?.name
        }.joined(separator: ", ")
        return ThreatAlert(
            score: 0.95,
            content: AlertContent(
                title: "Potential reverse shell detected",
                description: "Shell interpreter(s) or netcat '\(processes)' have outbound ESTABLISHED network connections on non-standard ports. This is a strong indicator of a reverse shell.",
                severity: .critical,
                recommendedAction: "Kill the process immediately, block the remote IP at your firewall, and investigate how the binary was executed."
            ),
            contributingSignals: matches
        )
    }

    /// Unsigned LaunchAgent or LaunchDaemon executable.
    private static let unsignedLaunchAgentRule = CorrelationRule(
        name: "unsigned_launch_agent",
        score: 0.7,
        severity: .high
    ) { signals in
        let matches = signals.filter {
            $0.source == .persistence &&
            ($0.severity == .high || $0.severity == .critical)
        }
        guard !matches.isEmpty else { return nil }
        let names = matches.map { $0.title }.joined(separator: "; ")
        return ThreatAlert(
            score: 0.7,
            content: AlertContent(
                title: "Unsigned persistence mechanism detected",
                description: "One or more launch agents/daemons reference unsigned executables: \(names). Malware commonly installs unsigned persistence items.",
                severity: .high,
                recommendedAction: "Inspect the plist file and its referenced executable. Remove if you do not recognise the software."
            ),
            contributingSignals: matches
        )
    }

    /// Camera or microphone activated by an unsigned or unrecognised process.
    private static let unexpectedCaptureDeviceRule = CorrelationRule(
        name:     "unexpected_capture_device",
        score:    0.85,
        severity: .high
    ) { signals in
        let matches = signals.filter { $0.source == .avCapture }
        guard !matches.isEmpty else { return nil }
        let devices   = matches.compactMap { $0.metadata["deviceName"] }.joined(separator: ", ")
        let processes = matches.compactMap { $0.metadata["process"]    }.joined(separator: ", ")
        return ThreatAlert(
            score: 0.85,
            content: AlertContent(
                title: "Unexpected capture device activation",
                description: "Device(s) '\(devices)' were activated, attributed to '\(processes)'. " +
                             "Covert camera or microphone access is a hallmark of spyware and RATs.",
                severity: .high,
                recommendedAction:
                    "Open System Settings → Privacy & Security → Camera / Microphone and audit " +
                    "which apps have permission. Revoke access for anything unexpected."
            ),
            contributingSignals: matches
        )
    }

    /// Shell interpreter piped from a concurrent download tool (curl|bash / wget|bash).
    private static let curlPipeShellRule = CorrelationRule(
        name: "curl_pipe_shell",
        score: 0.95,
        severity: .critical
    ) { signals in
        let matches = signals.filter {
            $0.source == .process &&
            ($0.metadata["reason"] == "curl_pipe_shell" ||
             $0.metadata["reason"] == "wget_pipe_shell")
        }
        guard !matches.isEmpty else { return nil }
        let details = matches.compactMap { s -> String? in
            guard let proc = s.processInfo else { return nil }
            let parent = s.metadata["parent"] ?? "unknown"
            return "'\(proc.name)' (parent: '\(parent)')"
        }.joined(separator: "; ")
        return ThreatAlert(
            score: 0.95,
            content: AlertContent(
                title: "Download-to-shell pipe attack detected",
                description: "A shell process appeared concurrently with a download tool: \(details). The 'curl|bash' pattern is the most common initial-access vector for macOS malware.",
                severity: .critical,
                recommendedAction: "Terminate the shell process immediately. Audit recently created files and any processes spawned by the affected parent."
            ),
            contributingSignals: matches
        )
    }

    /// Shell interpreter spawned from a non-terminal, non-trusted parent (LOLBin pattern).
    private static let lolbinRule = CorrelationRule(
        name: "lolbin_execution",
        score: 0.65,
        severity: .medium
    ) { signals in
        let matches = signals.filter {
            $0.source == .process &&
            $0.metadata["reason"] == "lolbin"
        }
        guard !matches.isEmpty else { return nil }
        let details = matches.compactMap { s -> String? in
            guard let proc = s.processInfo else { return nil }
            let parent = s.metadata["parent"] ?? "unknown"
            return "'\(proc.name)' spawned by '\(parent)'"
        }.joined(separator: "; ")
        return ThreatAlert(
            score: 0.65,
            content: AlertContent(
                title: "LOLBin execution detected",
                description: "Shell interpreter(s) spawned from a non-terminal parent: \(details). Malware uses this pattern to execute arbitrary commands without a visible terminal window.",
                severity: .medium,
                recommendedAction: "Identify the parent application and determine whether it has a legitimate reason to spawn a shell. Terminate if unexpected."
            ),
            contributingSignals: matches
        )
    }

    /// Advanced LOLBin technique: osascript shell, quarantine removal, base64 payload,
    /// launchctl from temp, crontab modification, mktemp execute. Emitted by LOLBinDetector
    /// but not caught by the basic lolbinRule (which only matches `reason == "lolbin"`).
    private static let lolbinAdvancedRule = CorrelationRule(
        name: "lolbin_advanced",
        score: 0.80,
        severity: .high
    ) { signals in
        let matchedReasons: Set<String> = [
            "osascript_shell", "quarantine_removal", "base64_payload",
            "launchctl_tmp", "crontab_modify", "mktemp_execute"
        ]
        let matches = signals.filter {
            $0.source == .process &&
            matchedReasons.contains($0.metadata["reason"] ?? "")
        }
        guard !matches.isEmpty else { return nil }
        let details = matches.compactMap { s -> String? in
            let reason = s.metadata["reason"] ?? "unknown"
            let name = s.processInfo?.name ?? "unknown"
            return "'\(name)' (\(reason))"
        }.joined(separator: "; ")
        return ThreatAlert(
            score: 0.80,
            content: AlertContent(
                title: "Advanced LOLBin technique detected",
                description: "Suspicious system-tool abuse pattern(s): \(details). These techniques are used for post-exploitation, persistence installation, and detection evasion.",
                severity: .high,
                recommendedAction: "Investigate each flagged process and its arguments. Terminate unexpected activity and audit recently modified persistence items."
            ),
            contributingSignals: matches
        )
    }

    /// YARA rule match on a file — emitted by FileSystemWatcher or DeepScanner.
    /// No source filter beyond `.yara` so both real-time FSEvents and manual deep scans are covered.
    private static let yaraMatchRule = CorrelationRule(
        name: "yara_match",
        score: 0.90,
        severity: .high
    ) { signals in
        let matches = signals.filter { $0.source == .yara }
        guard !matches.isEmpty else { return nil }
        let ruleNames = matches.compactMap { $0.metadata["yaraRules"] }.joined(separator: ", ")
        let paths = matches.compactMap { $0.fileInfo?.path }.joined(separator: "; ")
        return ThreatAlert(
            score: 0.90,
            content: AlertContent(
                title: "YARA threat signature matched",
                description: "YARA rule(s) [\(ruleNames.isEmpty ? "unknown" : ruleNames)] matched \(matches.count) file(s). Paths: \(paths.isEmpty ? "unknown" : paths).",
                severity: .high,
                recommendedAction: "Examine the matched files immediately. Quarantine or delete files that cannot be explained by installed software."
            ),
            contributingSignals: matches
        )
    }

    /// Three or more medium-severity signals within the correlation window.
    private static let multipleHighSignalsRule = CorrelationRule(
        name: "multiple_medium_signals",
        score: 0.75,
        severity: .high
    ) { signals in
        let mediumOrAbove = signals.filter { $0.severity >= .medium }
        guard mediumOrAbove.count >= 3 else { return nil }
        let sources = Set(mediumOrAbove.map { $0.source.rawValue }).sorted().joined(separator: ", ")
        return ThreatAlert(
            score: 0.75,
            content: AlertContent(
                title: "Multiple concurrent threat indicators",
                description: "\(mediumOrAbove.count) medium-or-higher signals observed within the correlation window across: \(sources). This pattern suggests coordinated or multi-stage activity.",
                severity: .high,
                recommendedAction: "Review the contributing signals below and investigate each affected component."
            ),
            contributingSignals: mediumOrAbove
        )
    }

    /// Shell startup/profile file modified — common persistence and privilege-escalation vector.
    /// Matches signals emitted by `FileSystemWatcher` with `reason == "shell_profile_modified"`.
    private static let shellProfileRule = CorrelationRule(
        name: "shell_profile_modified",
        score: 0.70,
        severity: .high
    ) { signals in
        let matches = signals.filter {
            $0.source == .persistence &&
            $0.metadata["reason"] == "shell_profile_modified"
        }
        guard !matches.isEmpty else { return nil }
        let paths = matches.compactMap { $0.metadata["path"] }.joined(separator: "; ")
        return ThreatAlert(
            score: 0.70,
            content: AlertContent(
                title: "Shell profile modified",
                description: "One or more shell startup files were written: \(paths). Attackers inject commands here for persistent code execution on every shell launch.",
                severity: .high,
                recommendedAction: "Inspect the modified file(s) immediately. Look for new lines at the end or obfuscated base64/eval commands and remove anything unfamiliar."
            ),
            contributingSignals: matches
        )
    }

    /// SSH `authorized_keys` modified — allows attacker persistent key-based access.
    /// Matches signals emitted by `FileSystemWatcher` with `reason == "ssh_keys_modified"`.
    private static let sshKeysRule = CorrelationRule(
        name: "ssh_keys_modified",
        score: 0.90,
        severity: .critical
    ) { signals in
        let matches = signals.filter {
            $0.source == .persistence &&
            $0.metadata["reason"] == "ssh_keys_modified"
        }
        guard !matches.isEmpty else { return nil }
        let paths = matches.compactMap { $0.metadata["path"] }.joined(separator: "; ")
        return ThreatAlert(
            score: 0.90,
            content: AlertContent(
                title: "SSH authorized_keys modified",
                description: "The SSH authorized keys file was written: \(paths). Adding a public key here grants persistent, password-free remote access.",
                severity: .critical,
                recommendedAction: "Review ~/.ssh/authorized_keys immediately. Remove any unrecognised public keys and audit recent SSH login attempts in /var/log/system.log."
            ),
            contributingSignals: matches
        )
    }

    /// Suspicious process parent-child relationship — browser/office/PDF app spawning a shell,
    /// or an app spawning a downloader, or deep shell nesting (4+ levels).
    /// Emitted by `ParentChainAnalyzer` with reasons: `browser_to_shell`, `office_to_shell`,
    /// `pdf_to_shell`, `app_to_downloader`, `deep_shell_nesting`.
    private static let parentChainRule = CorrelationRule(
        name: "suspicious_parent_chain",
        score: 0.75,
        severity: .high
    ) { signals in
        let parentChainReasons: Set<String> = [
            "browser_to_shell", "office_to_shell", "pdf_to_shell",
            "app_to_downloader", "deep_shell_nesting"
        ]
        let matches = signals.filter {
            $0.source == .process &&
            parentChainReasons.contains($0.metadata["reason"] ?? "")
        }
        guard !matches.isEmpty else { return nil }
        let isCritical = matches.contains { $0.metadata["reason"] == "deep_shell_nesting" }
        let processNames = matches.compactMap { $0.processInfo?.name }.joined(separator: ", ")
        return ThreatAlert(
            score: isCritical ? 0.90 : 0.75,
            content: AlertContent(
                title: "Suspicious process chain detected",
                description: "Process(es) '\(processNames)' exhibit a suspicious parent-child relationship. This pattern is commonly used by exploit payloads and document-based malware.",
                severity: isCritical ? .critical : .high,
                recommendedAction: "Investigate the parent application and terminate suspicious child processes. Check browser/office extensions and recently opened documents."
            ),
            contributingSignals: matches
        )
    }

    /// Outbound connection to a raw IP address without DNS resolution.
    /// Emitted by `ConnectionScanner` with `reason == "raw_ip_outbound"`.
    /// Malware and C2 beacons frequently use raw IPs to bypass DNS-based blocking.
    private static let rawIpOutboundRule = CorrelationRule(
        name: "raw_ip_outbound",
        score: 0.35,
        severity: .low
    ) { signals in
        let matches = signals.filter {
            $0.source == .network &&
            $0.metadata["reason"] == "raw_ip_outbound"
        }
        guard !matches.isEmpty else { return nil }
        let processNames = matches.compactMap { $0.processInfo?.name }.joined(separator: ", ")
        let ips = matches.compactMap { $0.networkInfo?.remoteAddress }.joined(separator: ", ")
        return ThreatAlert(
            score: 0.35,
            content: AlertContent(
                title: "Outbound connection to raw IP address",
                description: "Process(es) '\(processNames)' connected to IP address(es) without DNS resolution\(ips.isEmpty ? "" : ": \(ips)"). This is common for local network services, VPNs, and peer-to-peer connections. It may also indicate a process bypassing DNS-based security controls.",
                severity: .low,
                recommendedAction: "If you recognise these connections (local network devices, VPN, development servers), this alert is safe to dismiss. Investigate only if you see unfamiliar IP addresses on unusual ports."
            ),
            contributingSignals: matches
        )
    }

    /// Non-critical system hardening check failed or warned (firewall, stealth mode, remote login).
    /// Complements `criticalSystemAuditRule` which covers only SIP/FileVault/Gatekeeper.
    private static let systemHardeningRule = CorrelationRule(
        name: "system_hardening",
        score: 0.50,
        severity: .medium
    ) { signals in
        let hardeningChecks: Set<String> = ["firewall", "firewallStealth", "remoteLogin", "automaticUpdates", "xprotect"]
        let matches = signals.filter {
            $0.source == .systemAudit &&
            $0.severity >= .medium &&
            hardeningChecks.contains($0.metadata["check"] ?? "")
        }
        guard !matches.isEmpty else { return nil }
        let checks = matches.compactMap { $0.metadata["check"] }.joined(separator: ", ")
        return ThreatAlert(
            score: 0.50,
            content: AlertContent(
                title: "System hardening misconfiguration",
                description: "Non-critical security controls are not at their recommended settings: \(checks). While not an immediate compromise indicator, these weaken your defence-in-depth posture.",
                severity: .medium,
                recommendedAction: "Open System Settings → Privacy & Security and follow the recommendations in the System Audit tab to restore the expected configuration."
            ),
            contributingSignals: matches
        )
    }
}
