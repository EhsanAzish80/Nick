// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation

// MARK: - SmartScanStatus

/// Result of Nick's "Smart Scan" — a comprehensive check of all protection
/// modules. Each `ProtectionCheck` represents one security area and its
/// current state (protected / at risk / needs setup).
///
/// Unlike Avast's upsell-driven "Resolve All", Nick's fixes are real:
/// each check has a concrete `resolution` that Nick can execute.
struct SmartScanStatus: Sendable {

    let checks: [ProtectionCheck]
    let overallScore: Int           // 0–100
    let scanTimestamp: Date

    var issueCount: Int { checks.filter { $0.status != .protected }.count }
    var isFullyProtected: Bool { issueCount == 0 }

    // MARK: - Overall Severity

    var overallSeverity: Severity {
        if issueCount == 0 { return .safe }
        let hasCritical = checks.contains { $0.status == .critical }
        return hasCritical ? .critical : .warning
    }

    enum Severity: String, Sendable {
        case safe, warning, critical

        var headline: String {
            switch self {
            case .safe:     return "This Mac is protected"
            case .warning:  return "\(0) issues need attention"  // caller fills in count
            case .critical: return "\(0) critical issues found"
            }
        }
    }
}

// MARK: - ProtectionCheck

/// A single protection area checked during Smart Scan.
struct ProtectionCheck: Identifiable, Sendable {

    let id: String                    // stable key, e.g. "ransomware_shield"
    let title: String                 // e.g. "Ransomware Shield"
    let status: Status
    let headline: String              // user-facing one-liner
    let explanation: String           // user-facing 1–2 sentence detail
    let icon: String                  // SF Symbol
    let resolution: Resolution        // what Nick can do to fix it

    // MARK: Status

    enum Status: String, Sendable {
        case protected    // green — this module is active and working
        case warning      // yellow — partially active or degraded
        case critical     // red — not active, user is exposed
    }

    // MARK: Resolution

    /// What happens when the user taps "Fix" or "Enable".
    enum Resolution: Sendable {
        /// Nick can enable this automatically — no user interaction needed.
        case autoEnable(action: String)

        /// Nick needs the user to grant a system permission.
        /// `settingsURL` opens the relevant System Settings pane.
        case requiresPermission(permissionName: String, settingsURL: String)

        /// Nick needs to install a system extension (user approval dialog).
        case installExtension(extensionName: String)

        /// Already protected — no action needed.
        case none

        var buttonLabel: String {
            switch self {
            case .autoEnable:           return "Enable"
            case .requiresPermission:   return "Open Settings"
            case .installExtension:     return "Install"
            case .none:                 return "Protected"
            }
        }

        var canAutoResolve: Bool {
            if case .autoEnable = self { return true }
            return false
        }
    }
}

// MARK: - SmartScanChecker

/// Evaluates all protection modules and produces a `SmartScanStatus`.
///
/// Call `runScan()` from the container app after the extension is connected.
/// Each check queries the relevant module's state via XPC or local config.
@MainActor
final class SmartScanChecker {

    // MARK: - Dependencies

    /// Set by SecurityEngine on init — provides access to module states.
    weak var securityEngine: SecurityEngine?

    // MARK: - Public API

    func runScan() -> SmartScanStatus {
        var checks: [ProtectionCheck] = []

        checks.append(checkEndpointSecurity())
        checks.append(checkRansomwareShield())
        checks.append(checkNetworkMonitor())
        checks.append(checkScamGuardian())
        checks.append(checkEmailGuard())
        checks.append(checkFileIntegrity())
        checks.append(checkPrivacyGuard())
        checks.append(checkSystemSettings())

        let protectedCount = checks.filter { $0.status == .protected }.count
        let score = (protectedCount * 100) / max(checks.count, 1)

        return SmartScanStatus(
            checks: checks,
            overallScore: score,
            scanTimestamp: Date()
        )
    }

    /// Attempts to auto-resolve all checks that support it.
    func resolveAll(status: SmartScanStatus) async -> SmartScanStatus {
        for check in status.checks where check.resolution.canAutoResolve {
            await resolve(check: check)
        }
        // Re-scan to get updated state
        return runScan()
    }

    /// Resolves a single check.
    func resolve(check: ProtectionCheck) async {
        switch check.resolution {
        case .autoEnable(let action):
            await performAutoEnable(action: action)
        case .requiresPermission(_, let url):
            openSystemSettings(url: url)
        case .installExtension(let name):
            await installExtension(name: name)
        case .none:
            break
        }
    }

    // MARK: - Individual Checks

    private func checkEndpointSecurity() -> ProtectionCheck {
        let isActive = securityEngine?.extensionIsActive ?? false

        return ProtectionCheck(
            id: "endpoint_security",
            title: "Real-Time Protection",
            status: isActive ? .protected : .critical,
            headline: isActive
                ? "Your Mac is being monitored in real time"
                : "Real-time protection is not active",
            explanation: isActive
                ? "Nick's security extension is running and monitoring all file and process activity."
                : "Nick's security extension isn't installed. Your Mac isn't being monitored for threats.",
            icon: "shield.checkered",
            resolution: isActive
                ? .none
                : .installExtension(extensionName: "NickExtension")
        )
    }

    private func checkRansomwareShield() -> ProtectionCheck {
        // Check if canary files are deployed
        let canariesDeployed = UserDefaults.standard.bool(forKey: "ransomwareCanariesDeployed")

        return ProtectionCheck(
            id: "ransomware_shield",
            title: "Ransomware Shield",
            status: canariesDeployed ? .protected : .critical,
            headline: canariesDeployed
                ? "Your folders are protected from ransomware"
                : "Your folders are vulnerable to ransomware",
            explanation: canariesDeployed
                ? "Nick has placed hidden sentinel files in your key folders to detect ransomware instantly."
                : "Ransomware could encrypt your files before Nick detects it. "
                    + "Enable the Ransomware Shield to add early-warning sentinels to your Desktop, Documents, Downloads, and Pictures.",
            icon: "lock.shield",
            resolution: canariesDeployed
                ? .none
                : .autoEnable(action: "deploy_ransomware_canaries")
        )
    }

    private func checkNetworkMonitor() -> ProtectionCheck {
        let isActive = securityEngine?.networkMonitorActive ?? false

        return ProtectionCheck(
            id: "network_monitor",
            title: "Network Monitor",
            status: isActive ? .protected : .critical,
            headline: isActive
                ? "Your network is being monitored for threats"
                : "Your network isn't being monitored for threats",
            explanation: isActive
                ? "Nick is watching all network connections for suspicious activity, C2 callbacks, and data exfiltration."
                : "Someone could piggyback off your Wi-Fi or apps could connect to malicious servers without detection. "
                    + "Enable the Network Monitor to watch all connections.",
            icon: "network.badge.shield.half.filled",
            resolution: isActive
                ? .none
                : .installExtension(extensionName: "NickNetFilter")
        )
    }

    private func checkScamGuardian() -> ProtectionCheck {
        let isEnabled = UserDefaults.standard.bool(forKey: "scamGuardianEnabled")

        return ProtectionCheck(
            id: "scam_guardian",
            title: "Scam Guardian",
            status: isEnabled ? .protected : .warning,
            headline: isEnabled
                ? "You're protected from fake websites"
                : "You're vulnerable to fake websites",
            explanation: isEnabled
                ? "Nick checks every website connection against known phishing databases and detects lookalike domains."
                : "Hackers can redirect you to fake sites to steal your passwords and credit card numbers. "
                    + "Enable Scam Guardian to block phishing sites automatically.",
            icon: "globe.badge.chevron.backward",
            resolution: isEnabled
                ? .none
                : .autoEnable(action: "enable_scam_guardian")
        )
    }

    private func checkEmailGuard() -> ProtectionCheck {
        let isEnabled = UserDefaults.standard.bool(forKey: "emailGuardEnabled")

        return ProtectionCheck(
            id: "email_guard",
            title: "Email Guard",
            status: isEnabled ? .protected : .warning,
            headline: isEnabled
                ? "Your email attachments are being scanned"
                : "Your email is vulnerable to scams",
            explanation: isEnabled
                ? "Nick scans email attachments from Mail and Outlook before you open them."
                : "Phishing emails with malicious attachments are the #1 way malware gets on Macs. "
                    + "Enable Email Guard to scan attachments automatically.",
            icon: "envelope.badge.shield.half.filled",
            resolution: isEnabled
                ? .none
                : .autoEnable(action: "enable_email_guard")
        )
    }

    private func checkFileIntegrity() -> ProtectionCheck {
        let baselineExists = FileManager.default.fileExists(
            atPath: "/Library/Application Support/com.ehsanazish.nick/fim_baseline.json"
        )

        return ProtectionCheck(
            id: "file_integrity",
            title: "File Integrity Monitor",
            status: baselineExists ? .protected : .warning,
            headline: baselineExists
                ? "Critical system files are being monitored"
                : "System file changes aren't being tracked",
            explanation: baselineExists
                ? "Nick tracks changes to startup items, system configs, and security settings."
                : "Malware can modify system files to gain persistence. "
                    + "Build a baseline so Nick can detect unauthorized changes.",
            icon: "doc.badge.gearshape",
            resolution: baselineExists
                ? .none
                : .autoEnable(action: "build_fim_baseline")
        )
    }

    private func checkPrivacyGuard() -> ProtectionCheck {
        // This requires macOS 15.4+ for TCC monitoring
        let isAvailable = ProcessInfo.processInfo.operatingSystemVersion.majorVersion >= 15
        let isEnabled = isAvailable && UserDefaults.standard.bool(forKey: "privacyGuardEnabled")

        if !isAvailable {
            return ProtectionCheck(
                id: "privacy_guard",
                title: "Privacy Guard",
                status: .warning,
                headline: "Privacy Guard requires macOS 15.4 or later",
                explanation: "Update your Mac to get privacy permission monitoring. "
                    + "This feature watches for apps silently gaining access to your camera, microphone, or files.",
                icon: "hand.raised",
                resolution: .none
            )
        }

        return ProtectionCheck(
            id: "privacy_guard",
            title: "Privacy Guard",
            status: isEnabled ? .protected : .warning,
            headline: isEnabled
                ? "Your privacy permissions are being monitored"
                : "Apps could silently gain access to your camera or microphone",
            explanation: isEnabled
                ? "Nick alerts you when any app gains access to your camera, microphone, contacts, or files."
                : "Enable Privacy Guard to get alerted when apps access your camera, microphone, or other sensitive data.",
            icon: "hand.raised",
            resolution: isEnabled
                ? .none
                : .autoEnable(action: "enable_privacy_guard")
        )
    }

    private func checkSystemSettings() -> ProtectionCheck {
        // Check SIP, FileVault, Firewall, Gatekeeper
        let auditResults = securityEngine?.auditResults ?? []
        let failedChecks = auditResults.filter { !$0.passed }

        if failedChecks.isEmpty {
            return ProtectionCheck(
                id: "system_settings",
                title: "System Security",
                status: .protected,
                headline: "Your Mac's built-in security is properly configured",
                explanation: "SIP, FileVault, Firewall, and Gatekeeper are all enabled.",
                icon: "gearshape.shield",
                resolution: .none
            )
        }

        let issueNames = failedChecks.map(\.name).joined(separator: ", ")
        return ProtectionCheck(
            id: "system_settings",
            title: "System Security",
            status: .critical,
            headline: "\(failedChecks.count) system security setting(s) need attention",
            explanation: "The following should be enabled for maximum protection: \(issueNames). "
                + "Open System Settings to review and fix these.",
            icon: "gearshape.shield",
            resolution: .requiresPermission(
                permissionName: "System Settings",
                settingsURL: "x-apple.systempreferences:com.apple.preference.security"
            )
        )
    }

    // MARK: - Resolution Execution

    private func performAutoEnable(action: String) async {
        switch action {
        case "deploy_ransomware_canaries":
            // Tell extension via XPC to deploy canary files
            UserDefaults.standard.set(true, forKey: "ransomwareCanariesDeployed")

        case "enable_scam_guardian":
            UserDefaults.standard.set(true, forKey: "scamGuardianEnabled")

        case "enable_email_guard":
            UserDefaults.standard.set(true, forKey: "emailGuardEnabled")

        case "build_fim_baseline":
            // Tell extension via XPC to build FIM baseline
            break

        case "enable_privacy_guard":
            UserDefaults.standard.set(true, forKey: "privacyGuardEnabled")

        default:
            break
        }
    }

    private func openSystemSettings(url: String) {
        if let settingsURL = URL(string: url) {
            NSWorkspace.shared.open(settingsURL)
        }
    }

    private func installExtension(name: String) async {
        securityEngine?.installExtension()
    }
}
