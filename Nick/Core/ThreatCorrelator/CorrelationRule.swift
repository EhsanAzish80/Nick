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
        unsignedBinaryInTmpRule,
        reverseShellRule,
        unsignedLaunchAgentRule,
        unexpectedCaptureDeviceRule,
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
            title: "Critical system security configuration issue",
            description: "A fundamental macOS security control (\(first.title)) is disabled. This significantly raises the risk of compromise.",
            severity: .critical,
            contributingSignals: matches,
            recommendedAction: first.description
        )
    }

    /// Unsigned binary running from /tmp or similar writable directory.
    private static let unsignedBinaryInTmpRule = CorrelationRule(
        name: "unsigned_binary_in_tmp",
        score: 0.85,
        severity: .high
    ) { signals in
        let matches = signals.filter {
            $0.source == .process &&
            $0.severity == .high &&
            $0.metadata["reason"] == "unsigned_temp_path"
        }
        guard !matches.isEmpty else { return nil }
        let names = matches.compactMap { $0.processInfo?.name }.joined(separator: ", ")
        return ThreatAlert(
            score: 0.85,
            title: "Unsigned binary executing from temporary directory",
            description: "Process(es) '\(names)' are unsigned and running from writable temporary locations — a common technique used by droppers and implants.",
            severity: .high,
            contributingSignals: matches,
            recommendedAction: "Terminate the process and investigate the file at the reported path."
        )
    }

    /// Shell interpreter with an active outbound network connection (reverse shell indicator).
    private static let reverseShellRule = CorrelationRule(
        name: "reverse_shell",
        score: 0.95,
        severity: .critical
    ) { signals in
        let matches = signals.filter {
            $0.source == .network &&
            $0.metadata["reason"] == "reverse_shell"
        }
        guard !matches.isEmpty else { return nil }
        let processes = matches.compactMap { $0.metadata["process"] }.joined(separator: ", ")
        return ThreatAlert(
            score: 0.95,
            title: "Potential reverse shell detected",
            description: "Shell interpreter(s) '\(processes)' have outbound ESTABLISHED network connections. This is a strong indicator of a reverse shell.",
            severity: .critical,
            contributingSignals: matches,
            recommendedAction: "Kill the process immediately, block the remote IP at your firewall, and investigate how the binary was executed."
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
            title: "Unsigned persistence mechanism detected",
            description: "One or more launch agents/daemons reference unsigned executables: \(names). Malware commonly installs unsigned persistence items.",
            severity: .high,
            contributingSignals: matches,
            recommendedAction: "Inspect the plist file and its referenced executable. Remove if you do not recognise the software."
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
            title: "Unexpected capture device activation",
            description: "Device(s) '\(devices)' were activated, attributed to '\(processes)'. " +
                         "Covert camera or microphone access is a hallmark of spyware and RATs.",
            severity: .high,
            contributingSignals: matches,
            recommendedAction:
                "Open System Settings → Privacy & Security → Camera / Microphone and audit " +
                "which apps have permission. Revoke access for anything unexpected."
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
            title: "Multiple concurrent threat indicators",
            description: "\(mediumOrAbove.count) medium-or-higher signals observed within the correlation window across: \(sources). This pattern suggests coordinated or multi-stage activity.",
            severity: .high,
            contributingSignals: mediumOrAbove,
            recommendedAction: "Review the contributing signals below and investigate each affected component."
        )
    }
}
