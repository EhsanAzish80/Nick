// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation

// MARK: - UserFacingAlertBuilder

/// Translates technical `ThreatAlert` values into consumer-friendly
/// `UserFacingAlert` values with plain-language headlines and explanations.
///
/// Uses a pattern-matching lookup table for common threat types, then falls
/// back to a generic template. Never exposes PIDs, file paths, hashes, or
/// IP addresses in the headline or explanation — those stay in `technicalDetail`.
///
/// Thread-safe and stateless — safe to call from any queue.
final class UserFacingAlertBuilder {

    // MARK: - Public API

    /// Builds a `UserFacingAlert` from a correlated `ThreatAlert`.
    func build(from alert: ThreatAlert) -> UserFacingAlert {
        let pattern = detectPattern(from: alert)

        return UserFacingAlert(
            id:              alert.id,
            headline:        pattern.headline,
            explanation:     pattern.explanation,
            severity:        mapSeverity(alert.severity),
            actions:         pattern.actions,
            technicalDetail: alert,
            timestamp:       alert.timestamp
        )
    }

    // MARK: - Pattern Detection

    private struct AlertPattern {
        let headline: String
        let explanation: String
        let actions: [UserFacingAlert.AlertAction]
    }

    private func detectPattern(from alert: ThreatAlert) -> AlertPattern {
        let signals   = alert.contributingSignals
        let monitors  = Set(signals.map(\.source))
        let features  = Set(signals.compactMap(\.processInfo).flatMap { p -> [String] in
            var flags: [String] = []
            if !p.isSigned    { flags.append("unsigned") }
            if p.isShell      { flags.append("shell") }
            if p.path.hasPrefix("/tmp") || p.path.hasPrefix("/private/tmp") { flags.append("tmp") }
            return flags
        })
        let hasNetwork     = monitors.contains(.network)
        let hasPersistence = monitors.contains(.persistence)
        let hasYARA        = monitors.contains(.yara)
        let hasFilesystem  = monitors.contains(.filesystem)
        let title          = alert.title.lowercased()

        // --- Ransomware ---
        if title.contains("ransomware") || title.contains("mass rename") || title.contains("canary") {
            return AlertPattern(
                headline: "Possible ransomware detected",
                explanation: "An app tried to rapidly encrypt or rename your files. "
                    + "This is a common sign of ransomware. "
                    + "Nick blocked the app and quarantined the threat to keep your files safe.",
                actions: [.keepBlocked, .showDetails]
            )
        }

        // --- Reverse shell ---
        if features.contains("shell") && hasNetwork {
            return AlertPattern(
                headline: "Suspicious remote access blocked",
                explanation: "A command-line tool on your Mac was connecting to an outside server. "
                    + "This can allow someone to control your Mac remotely. "
                    + "Nick blocked the connection. If you weren't using a remote tool, no action is needed.",
                actions: [.keepBlocked, .showDetails]
            )
        }

        // --- Unsigned binary in temp ---
        if features.contains("unsigned") && features.contains("tmp") {
            return AlertPattern(
                headline: "Nick blocked an untrusted app",
                explanation: "An unverified app tried to run from a temporary folder. "
                    + "Legitimate apps don't usually work this way — this is how malware often hides. "
                    + "Nick stopped it before it could do anything.",
                actions: [.keepBlocked, .allowOnce, .showDetails]
            )
        }

        // --- Persistence change ---
        if hasPersistence {
            return AlertPattern(
                headline: "New startup item detected",
                explanation: "Something was added to run automatically when your Mac starts up. "
                    + "While some apps do this normally, malware also uses this trick to stay on your Mac. "
                    + "Review this item and remove it if you don't recognize it.",
                actions: [.keepBlocked, .allowOnce, .showDetails]
            )
        }

        // --- YARA match ---
        if hasYARA {
            return AlertPattern(
                headline: "Known threat detected",
                explanation: "Nick matched a file to its threat database — this file is known to be harmful. "
                    + "It has been blocked and can be quarantined to prevent any damage. "
                    + "No action is needed unless you want to review the details.",
                actions: [.quarantine, .showDetails]
            )
        }

        // --- C2 / suspicious network ---
        if hasNetwork && !features.contains("shell") {
            return AlertPattern(
                headline: "Suspicious network activity blocked",
                explanation: "An app tried to connect to a server that Nick flagged as potentially dangerous. "
                    + "This can indicate malware trying to communicate with an attacker. "
                    + "The connection was blocked — your data is safe.",
                actions: [.keepBlocked, .allowOnce, .showDetails]
            )
        }

        // --- File integrity violation ---
        if hasFilesystem {
            return AlertPattern(
                headline: "System file change detected",
                explanation: "A file that controls how your Mac operates was modified. "
                    + "This can happen after a legitimate update, but it's also how malware hides. "
                    + "Review the change to make sure it's expected.",
                actions: [.showDetails, .dismiss]
            )
        }

        // --- Fork bomb / resource abuse ---
        if title.contains("fork") || title.contains("excessive") || title.contains("resource") {
            return AlertPattern(
                headline: "Harmful app behavior stopped",
                explanation: "An app was using your Mac's resources in a way that could slow it down or crash it. "
                    + "Nick stopped the app to protect your Mac's performance. "
                    + "If you don't recognize the app, it's safe to keep it blocked.",
                actions: [.keepBlocked, .showDetails]
            )
        }

        // --- Generic fallback ---
        return AlertPattern(
            headline: "Nick detected suspicious activity",
            explanation: "Something on your Mac triggered Nick's security checks. "
                + "Nick is monitoring the situation and has taken protective action. "
                + "Tap \"Show Details\" for more information about what was detected.",
            actions: [.showDetails, .dismiss]
        )
    }

    // MARK: - Severity Mapping

    private func mapSeverity(_ signal: SignalSeverity) -> UserFacingAlert.AlertSeverity {
        switch signal {
        case .info, .low:
            return .safe
        case .medium:
            return .warning
        case .high, .critical:
            return .critical
        }
    }
}
