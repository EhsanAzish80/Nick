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
final class UserFacingAlertBuilder: Sendable {

    static let shared = UserFacingAlertBuilder()

    // MARK: - Public API

    /// Builds a `UserFacingAlert` from a correlated `ThreatAlert`.
    func build(from alert: ThreatAlert) -> UserFacingAlert {
        let pattern = detectPattern(from: alert)

        return UserFacingAlert(
            id:              alert.id,
            headline:        pattern.headline,
            explanation:     pattern.explanation,
            assessment:      pattern.assessment,
            recommendedAction: pattern.recommendedAction,
            severity:        pattern.severity ?? mapSeverity(alert.severity),
            actions:         pattern.actions,
            technicalDetail: alert,
            timestamp:       alert.timestamp
        )
    }

    // MARK: - Pattern Detection

    private struct AlertPattern {
        let headline: String
        let explanation: String
        let assessment: String
        let recommendedAction: String
        let severity: UserFacingAlert.AlertSeverity?
        let actions: [UserFacingAlert.AlertAction]

        init(
            headline: String,
            explanation: String,
            assessment: String,
            recommendedAction: String,
            severity: UserFacingAlert.AlertSeverity? = nil,
            actions: [UserFacingAlert.AlertAction]
        ) {
            self.headline = headline
            self.explanation = explanation
            self.assessment = assessment
            self.recommendedAction = recommendedAction
            self.severity = severity
            self.actions = actions
        }
    }

    private func detectPattern(from alert: ThreatAlert) -> AlertPattern {
        let signals   = alert.contributingSignals
        let monitors  = Set(signals.map(\.source))
        let features  = Set(signals.compactMap(\.processInfo).flatMap { (p: NickProcessInfo) -> [String] in
            var flags: [String] = []
            if p.signingStatus == .unsigned || p.signingStatus == .invalid { flags.append("unsigned") }
            let shellNames: Set<String> = ["bash", "sh", "zsh", "fish", "tcsh", "csh", "dash", "ksh"]
            if shellNames.contains(p.name) || shellNames.contains((p.path as NSString).lastPathComponent) { flags.append("shell") }
            if p.path.hasPrefix("/tmp") || p.path.hasPrefix("/private/tmp") { flags.append("tmp") }
            return flags
        })
        let hasNetwork     = monitors.contains(.network)
        let hasPersistence = monitors.contains(.persistence)
        let hasYARA        = monitors.contains(.yara)
        let hasFilesystem  = monitors.contains(.filesystem)
        let hasCapture     = monitors.contains(.avCapture)
        let title          = alert.title.lowercased()
        let firstProcess   = signals.compactMap(\.processInfo).first
        let processName    = firstProcess?.name ?? signals.compactMap { $0.metadata["process"] }.first
        let displayProcess = userReadableProcessName(processName)
        let parentName     = firstProcess?.parentName.flatMap(userReadableProcessName)
        let isDeveloperWorkflow = signals.contains(where: isDeveloperWorkflowSignal)

        // Alerts persisted by an older development build can include Nick's own
        // unsigned Xcode products. They are build artifacts, not user threats.
        // This is deliberately narrow: an arbitrary executable named "Nick"
        // outside our known build roots is not trusted.
        if signals.contains(where: isNickDevelopmentArtifact) {
            return AlertPattern(
                headline: "Nick development build activity",
                explanation: "Nick scanned one of its own temporary Xcode build files. This is developer activity, not evidence of malware on your Mac.",
                assessment: "Safe developer activity",
                recommendedAction: "No action is needed. You can hide this alert.",
                severity: .safe,
                actions: [.showDetails, .dismiss]
            )
        }

        // --- Camera / microphone ---
        if hasCapture {
            let mediaType = signals.compactMap { $0.metadata["mediaType"] }.first ?? "camera or microphone"
            let device = signals.compactMap { $0.metadata["deviceName"] }.first ?? mediaType
            let isSimulatorActivity = signals.contains(where: isSimulatorCapture)
            let hasAuthoritativeAttribution = signals.allSatisfy {
                $0.metadata["attributionConfidence"] == "authoritative"
            }

            if !hasAuthoritativeAttribution {
                return AlertPattern(
                    headline: "\(device) became active",
                    explanation: "Nick observed \(mediaType) activity, but macOS did not provide reliable information about which app owned the session. Older Nick versions guessed from recently launched processes; names such as Mail, Node, or Photos in those alerts were not evidence that those apps used your \(mediaType).",
                    assessment: "Informational activity",
                    recommendedAction: "If this matches an app you were using, such as Driftor checking whether you are present, no action is needed. If it is unexpected, check the macOS privacy indicator and review \(mediaType) permissions in System Settings → Privacy & Security.",
                    severity: .safe,
                    actions: [.showDetails, .dismiss]
                )
            }

            if isSimulatorActivity {
                return AlertPattern(
                    headline: "\(device) was used by iOS Simulator",
                    explanation: "\(displayProcess ?? "An Apple simulator service") accessed the \(mediaType) while running inside Xcode's iOS Simulator. "
                        + "Simulator components use ad-hoc signatures, so that signature alone is not evidence of malware.",
                    assessment: "Likely safe developer activity",
                    recommendedAction: "Keep it if you were using Xcode or Simulator. Otherwise, quit Simulator and check whether the camera indicator turns off.",
                    severity: .safe,
                    actions: [.showDetails, .dismiss]
                )
            }

            let isUntrusted = firstProcess.map {
                $0.signingStatus == .unsigned || $0.signingStatus == .invalid
            } ?? false
            return AlertPattern(
                headline: "\(displayProcess ?? "An unidentified app") used your \(mediaType)",
                explanation: "\(device) became active and Nick attributed the activity to \(displayProcess ?? "an unidentified app"). "
                    + (isUntrusted
                        ? "The app does not have a valid code signature, which makes this activity more concerning."
                        : "Camera or microphone use can be normal; this event alone does not prove the app is dangerous."),
                assessment: isUntrusted ? "Potentially dangerous" : "Needs your review",
                recommendedAction: "If you expected this, keep the app. If not, quit it and remove its \(mediaType) permission in System Settings → Privacy & Security.",
                severity: isUntrusted ? .critical : .warning,
                actions: [.showDetails, .dismiss]
            )
        }

        // --- Ransomware ---
        if title.contains("ransomware") || title.contains("mass rename") || title.contains("canary") {
            return AlertPattern(
                headline: "Possible ransomware detected",
                explanation: "An app rapidly changed several files, which can happen during encryption or mass renaming. "
                    + "That pattern is associated with ransomware, but Nick needs the app and file context before calling it a confirmed infection.",
                assessment: "Potentially dangerous",
                recommendedAction: "Pause work in the named app and review the affected files. If you do not recognize the app, quit it before continuing.",
                actions: [.showDetails, .dismiss]
            )
        }

        // --- Developer shell / build workflow ---
        // Shell and transfer utilities are dual-use. Attribute the concrete parent
        // and executable instead of treating names such as curl, zsh, or swift-build
        // as malware identities.
        if isDeveloperWorkflow && !hasYARA && !hasPersistence {
            let origin = parentName.map { "\($0) started \(displayProcess ?? "a command-line tool")" }
                ?? "Nick could not identify the app that started \(displayProcess ?? "this command-line tool")"
            return AlertPattern(
                headline: "Developer command needs context",
                explanation: "\(origin). This is common during builds, SSH sessions, package downloads, and local development. The same tools can also be misused by scripts, so Nick is showing the exact origin instead of calling the tool itself malware.",
                assessment: "Likely developer activity",
                recommendedAction: "Keep it if you started this build, terminal, SSH, or editor task. If not, review the origin and command details before allowing this behavior.",
                severity: .warning,
                actions: [.showDetails, .dismiss]
            )
        }

        // --- Reverse shell ---
        if features.contains("shell") && hasNetwork {
            return AlertPattern(
                headline: "Possible remote access detected",
                explanation: "A command-line tool on your Mac was connecting to an outside server. "
                    + "This pattern can be a remote shell, but it is also normal when you intentionally use SSH or developer tools. "
                    + "Nick detected the connection; this alert does not mean the connection was blocked.",
                assessment: "Potentially dangerous",
                recommendedAction: "If you started an SSH or remote-development session, keep it. Otherwise, quit the named process and review how it started.",
                actions: [.showDetails, .dismiss]
            )
        }

        // --- Unsigned binary in temp ---
        if features.contains("unsigned") && features.contains("tmp") {
            return AlertPattern(
                headline: "An untrusted app ran from a temporary folder",
                explanation: "An unverified app ran from a temporary folder. "
                    + "Installers sometimes do this, but malware also uses temporary folders to hide downloaded programs. "
                    + "Nick flagged the app; check its name and origin before assuming it is harmful.",
                assessment: "Potentially dangerous",
                recommendedAction: "Keep it only if it belongs to an installer or app you just opened. Otherwise, quit it and show the file in Finder before deleting anything.",
                actions: [.showDetails, .dismiss]
            )
        }

        // --- Persistence change ---
        if hasPersistence {
            return AlertPattern(
                headline: "New startup item detected",
                explanation: "Something was added to run automatically when your Mac starts up. "
                    + "While some apps do this normally, malware also uses this trick to stay on your Mac. "
                    + "Review this item and remove it if you don't recognize it.",
                assessment: "Needs your review",
                recommendedAction: "Keep it if you recognize the app. Otherwise, show its location before removing it.",
                actions: [.keepBlocked, .allowOnce, .showDetails]
            )
        }

        // --- YARA match ---
        if hasYARA {
            // A YARA rule is pattern evidence, not identity evidence. Severity
            // expresses the rule author's concern; it does not turn a heuristic
            // into a confirmed malicious hash.
            let signedSoftware = signals.contains(where: isSignedInstalledSoftware)
            return AlertPattern(
                headline: signedSoftware
                    ? "Signed software matched a detection rule"
                    : "A file matched a suspicious behavior pattern",
                explanation: signedSoftware
                    ? "\(displayProcess ?? "A signed app") matched a broad malware-detection pattern. Its valid signature and installed location are important evidence that this may be legitimate updater or application code; a rule match alone is not proof of malware."
                    : "A file contains instructions sometimes used to change startup settings or perform other sensitive actions. Legitimate installers, developer builds, and security tools can contain the same instructions, so this is not a confirmed malware detection.",
                assessment: "Needs your review",
                recommendedAction: "Check the file name, location, and detection rule. Accept it if you recognize the app or build; quarantine it only after reviewing the file.",
                severity: .warning,
                actions: [.keepBlocked, .allowOnce, .quarantine, .showDetails, .dismiss]
            )
        }

        // --- C2 / suspicious network ---
        if hasNetwork && !features.contains("shell") {
            return AlertPattern(
                headline: "An app made an unusual network connection",
                explanation: "An app tried to connect to a server that Nick flagged as potentially dangerous. "
                    + "This can be malware communication, but raw IP addresses and uncommon ports are also used by legitimate software. "
                    + "Nick observed this connection; passive monitoring does not block it.",
                assessment: "Needs your review",
                recommendedAction: "Keep the app if you recognize it and expected network activity. Otherwise, quit it and review the destination in Details.",
                actions: [.showDetails, .dismiss]
            )
        }

        // --- File integrity violation ---
        if hasFilesystem {
            return AlertPattern(
                headline: "System file change detected",
                explanation: "A file that controls how your Mac operates was modified. "
                    + "This can happen after a legitimate update, but it's also how malware hides. "
                    + "Review the change to make sure it's expected.",
                assessment: "Needs your review",
                recommendedAction: "Keep the change if it followed an app or macOS update. Otherwise, show the file and review its source.",
                actions: [.showDetails, .dismiss]
            )
        }

        // --- Fork bomb / resource abuse ---
        if title.contains("fork") || title.contains("excessive") || title.contains("resource") {
            return AlertPattern(
                headline: "An app may be overwhelming your Mac",
                explanation: "An app was using your Mac's resources in a way that could slow it down or crash it. "
                    + "Nick detected the pattern, but this alert alone does not confirm that the app was stopped or that it is malware.",
                assessment: "Potentially disruptive",
                recommendedAction: "Quit the app if your Mac is slow or unresponsive. Keep it running only if you recognize it and expected the workload.",
                actions: [.showDetails, .dismiss]
            )
        }

        // --- Generic fallback ---
        return AlertPattern(
            headline: genericHeadline(alert: alert, processName: displayProcess),
            explanation: genericExplanation(alert: alert, processName: displayProcess),
            assessment: "Needs your review",
            recommendedAction: cleanRecommendation(alert.recommendedAction),
            actions: [.showDetails, .dismiss]
        )
    }

    private func isSimulatorCapture(_ signal: ThreatSignal) -> Bool {
        guard signal.source == .avCapture, let path = signal.processInfo?.path else { return false }
        return path.contains("/CoreSimulator/") || path.contains(".simruntime/")
    }

    private func isDeveloperWorkflowSignal(_ signal: ThreatSignal) -> Bool {
        guard let process = signal.processInfo else { return false }
        let processName = process.name.lowercased()
        let parentName = process.parentName?.lowercased() ?? ""
        let developerTools = [
            "xcode", "swift", "swift-build", "sourcekit", "terminal", "iterm",
            "warp", "code", "visual studio code", "git", "ssh", "sshd"
        ]
        let commandLineTools: Set<String> = [
            "bash", "zsh", "sh", "fish", "curl", "git", "ssh", "scp", "rsync",
            "swift", "swift-build", "xcodebuild", "make", "cmake", "python", "node"
        ]
        let hasDeveloperParent = developerTools.contains { parentName.contains($0) }
        let isKnownTool = commandLineTools.contains(processName)
        let isSystemTool = process.path.hasPrefix("/usr/bin/") || process.path.hasPrefix("/bin/")
        let isValidlySigned: Bool
        if case .signed = process.signingStatus { isValidlySigned = true } else { isValidlySigned = false }
        return hasDeveloperParent || (isKnownTool && isSystemTool && isValidlySigned)
    }

    private func isSignedInstalledSoftware(_ signal: ThreatSignal) -> Bool {
        let path = signal.fileInfo?.path ?? signal.processInfo?.path ?? ""
        let installedPath = path.hasPrefix("/Applications/")
            || path.hasPrefix("/Library/")
            || path.hasPrefix("/System/")
        let signingStatus = signal.fileInfo?.signingStatus ?? signal.processInfo?.signingStatus
        guard installedPath, let signingStatus else { return false }
        if case .signed(let teamID) = signingStatus { return !teamID.isEmpty }
        return false
    }

    private func isNickDevelopmentArtifact(_ signal: ThreatSignal) -> Bool {
        let paths = [
            signal.fileInfo?.path,
            signal.metadata["path"],
            signal.metadata["script_path"],
            signal.processInfo?.path,
        ].compactMap { $0?.lowercased() }

        return paths.contains { path in
            let isNickProduct = path.contains("/nick.app/contents/")
                || path.hasSuffix("/nick.debug.dylib")
                || path.hasSuffix("/macos/nick")
            let isKnownBuildRoot = path.contains("/nickperformanceaudit")
                || path.contains("/deriveddata/")
                || path.contains("/build/products/")
            return isNickProduct && isKnownBuildRoot
        }
    }

    private func userReadableProcessName(_ name: String?) -> String? {
        guard let name, !name.isEmpty, name != "unknown" else { return nil }
        if name == "shazamd" { return "Shazam service" }
        return name
    }

    private func genericHeadline(alert: ThreatAlert, processName: String?) -> String {
        if let processName {
            return "\(processName) needs your review"
        }
        return alert.title.isEmpty ? "Security activity needs your review" : alert.title
    }

    private func genericExplanation(alert: ThreatAlert, processName: String?) -> String {
        let process = alert.contributingSignals.compactMap(\.processInfo).first
        let subject: String
        if let processName, let parent = process?.parentName, !parent.isEmpty {
            subject = "\(parent) started \(processName), which triggered a security check."
        } else {
            subject = processName.map { "\($0) triggered a security check." }
            ?? "Nick observed an event that matched a security check."
        }
        let detail = alert.description.trimmingCharacters(in: .whitespacesAndNewlines)
        return "\(subject) This does not by itself prove that your Mac is infected. "
            + (detail.isEmpty ? "Use the technical details if you need more context." : detail)
    }

    private func cleanRecommendation(_ recommendation: String) -> String {
        let trimmed = recommendation.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.isEmpty || trimmed.lowercased() == "investigate." {
            return "Open the details and check whether you recognize the app or file before deleting anything."
        }
        return trimmed
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
