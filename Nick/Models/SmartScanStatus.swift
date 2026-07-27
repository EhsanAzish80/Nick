// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import AppKit
import Foundation
import NetworkExtension
import OSLog
import SystemExtensions

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

        /// macOS only activates bundled system extensions from /Applications.
        /// Reveal the current build so the user can move it there first.
        case revealAppForInstallation

        /// Feature is pending platform approval (e.g. Apple entitlement review).
        /// Shows a disabled informational button — no user action possible.
        case pendingApproval(reason: String)

        /// Already protected — no action needed.
        case none

        var buttonLabel: String {
            switch self {
            case .autoEnable:           return "Enable"
            case .requiresPermission:   return "Open Settings"
            case .installExtension:     return "Install"
            case .revealAppForInstallation: return "Show App"
            case .pendingApproval:      return "Pending Approval"
            case .none:                 return "Protected"
            }
        }

        var canAutoResolve: Bool {
            if case .autoEnable = self { return true }
            return false
        }
    }
}

// MARK: - FixAllSummary

/// Summary of a "Fix All" operation: how many items were auto-fixed and
/// which still require manual action.
struct FixAllSummary {
    let fixedCount: Int
    let totalAutoFixable: Int
    let skippedChecks: [ProtectionCheck]  // items still needing attention after fix all
}

// MARK: - SmartScanStatus + Helpers

extension SmartScanStatus {
    /// Returns a new `SmartScanStatus` with the given check replaced by `check`.
    func replacing(check updatedCheck: ProtectionCheck) -> SmartScanStatus {
        var newChecks = checks
        if let idx = newChecks.firstIndex(where: { $0.id == updatedCheck.id }) {
            newChecks[idx] = updatedCheck
        }
        let protectedCount = newChecks.filter { $0.status == .protected }.count
        let score = (protectedCount * 100) / max(newChecks.count, 1)
        return SmartScanStatus(checks: newChecks, overallScore: score, scanTimestamp: scanTimestamp)
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

    /// Required to trigger system-extension installation.
    weak var extensionManager: ExtensionManager?

    /// XPC client used to wire Smart Scan fix actions to the running extension.
    weak var xpcClient: ExtensionXPCClient?

    // MARK: - Summary of last Fix All run

    private(set) var lastFixAllSummary: FixAllSummary?

    /// Non-nil after a failed FIM baseline build; cleared at the start of the next enable attempt.
    private(set) var fimBuildError: String?

    /// Loaded from macOS Network Extension preferences before each user-visible
    /// scan. A provider heartbeat alone is not enough: macOS can retain the
    /// health file after the user disables the filter.
    private var networkFilterPreferenceEnabled = false

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

    /// Refreshes protection state that can only be read asynchronously.
    /// Call this immediately before presenting Smart Scan or setup results.
    func refreshLiveProtectionState() async {
        let manager = NEFilterManager.shared()
        do {
            try await manager.loadFromPreferences()
            networkFilterPreferenceEnabled = manager.isEnabled
        } catch {
            // Fail closed in the UI: inability to verify must never appear green.
            networkFilterPreferenceEnabled = false
        }
    }

    /// An old content filter can remain enabled across app updates. If its
    /// health record predates Nick's current fail-open policy, turn it off
    /// before guiding the user through installation of the replacement.
    func disableOutdatedNetworkFilterIfNeeded() async {
        guard
            let path = NetworkProtectionSharedStore.healthURL()?.path,
            let data = FileManager.default.contents(atPath: path),
            let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
            !Self.isCurrentNetworkFilterHealth(
                object,
                now: Date().timeIntervalSince1970
            )
        else {
            return
        }

        await NetworkFilterInstaller.shared.disableFilter()
    }

    /// Attempts to auto-resolve all checks that support it.
    func resolveAll(status: SmartScanStatus) async -> SmartScanStatus {
        let autoFixable = status.checks.filter { $0.resolution.canAutoResolve }
        for check in autoFixable {
            await resolve(check: check)
        }
        // Re-scan to get updated state
        await refreshLiveProtectionState()
        let newStatus = runScan()
        // Compute summary: how many moved to .protected vs still need attention
        let fixedCount = autoFixable.filter { old in
            newStatus.checks.first(where: { $0.id == old.id })?.status == .protected
        }.count
        let skipped = newStatus.checks.filter { $0.status != .protected }
        lastFixAllSummary = FixAllSummary(
            fixedCount: fixedCount,
            totalAutoFixable: autoFixable.count,
            skippedChecks: skipped
        )
        return newStatus
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
        case .revealAppForInstallation:
            NSWorkspace.shared.activateFileViewerSelecting([Bundle.main.bundleURL])
        case .pendingApproval, .none:
            break
        }
    }

    // MARK: - Individual Checks

    private func checkEndpointSecurity() -> ProtectionCheck {
        let isActive = isEndpointSecurityActive
        let extensionFullDiskAccessReady =
            endpointExtensionHealth?["fullDiskAccessReady"] as? Bool == true
        let appFullDiskAccessReady = Self.hasFullDiskAccess
        let fullDiskAccessReady =
            extensionFullDiskAccessReady && appFullDiskAccessReady
        let appIsInstalled = Bundle.main.bundleURL.path.hasPrefix("/Applications/")
        let managerState = extensionManager?.extensionState ?? .unknown

        if !isActive && !appIsInstalled {
            return ProtectionCheck(
                id: "endpoint_security",
                title: "Real-Time Protection",
                status: .critical,
                headline: "Move Nick to Applications first",
                explanation: "macOS only allows Nick to install its security extension when Nick.app is running from the Applications folder.",
                icon: "shield.checkered",
                resolution: .revealAppForInstallation
            )
        }

        if !isActive, managerState == .needsUserApproval {
            return ProtectionCheck(
                id: "endpoint_security",
                title: "Real-Time Protection",
                status: .warning,
                headline: "Approve Nick's security extension",
                explanation: "macOS is waiting for your approval in System Settings → General → Login Items & Extensions.",
                icon: "shield.checkered",
                resolution: .requiresPermission(
                    permissionName: "System Extensions",
                    settingsURL: "x-apple.systempreferences:com.apple.LoginItems-Settings.extension"
                )
            )
        }

        if !isActive, managerState == .installing {
            return ProtectionCheck(
                id: "endpoint_security",
                title: "Real-Time Protection",
                status: .warning,
                headline: "Installing security extension…",
                explanation: "Nick will verify protection only after the extension starts and confirms its Endpoint Security client is active.",
                icon: "shield.checkered",
                resolution: .none
            )
        }

        if !isActive, managerState == .installed {
            return ProtectionCheck(
                id: "endpoint_security",
                title: "Real-Time Protection",
                status: .warning,
                headline: "Allow Full Disk Access to start protection",
                explanation: "Nick's security extension is installed. Endpoint Security and Email Guard need Full Disk Access before the extension can start monitoring protected locations. Turn on both Nick and NickExtension, then return here.",
                icon: "shield.checkered",
                resolution: .requiresPermission(
                    permissionName: "Full Disk Access",
                    settingsURL: "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles"
                )
            )
        }

        if !isActive, managerState == .failed, let error = extensionManager?.lastError {
            return ProtectionCheck(
                id: "endpoint_security",
                title: "Real-Time Protection",
                status: .critical,
                headline: "Security extension installation failed",
                explanation: ExtensionManager.userFacingInstallationError(error),
                icon: "shield.checkered",
                resolution: .installExtension(extensionName: "NickExtension")
            )
        }

        if isActive, !fullDiskAccessReady {
            return ProtectionCheck(
                id: "endpoint_security",
                title: "Real-Time Protection",
                status: .warning,
                headline: "Allow Full Disk Access for complete protection",
                explanation: "Nick's security extension is running, but macOS is limiting protected locations such as Mail data. In Full Disk Access, turn on both Nick and NickExtension, then return here.",
                icon: "shield.checkered",
                resolution: .requiresPermission(
                    permissionName: "Full Disk Access",
                    settingsURL: "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles"
                )
            )
        }

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
        let extensionActive = isEndpointSecurityActive
        let canariesDeployed = (endpointExtensionHealth?["canaryCount"] as? Int ?? 0) > 0
        let isProtected = extensionActive && canariesDeployed

        return ProtectionCheck(
            id: "ransomware_shield",
            title: "Ransomware Shield",
            status: isProtected ? .protected : .warning,
            headline: isProtected
                ? "Your folders are protected from ransomware"
                : extensionActive ? "Ransomware sentinels are not verified" : "Waiting for Real-Time Protection",
            explanation: isProtected
                ? "Nick verified hidden sentinel files and the extension that monitors them."
                : extensionActive
                    ? "Deploy and verify sentinel files before treating ransomware monitoring as active."
                    : "Ransomware monitoring requires Nick's Endpoint Security extension to be active.",
            icon: "lock.shield",
            resolution: isProtected
                ? .none
                : extensionActive
                    ? .autoEnable(action: "deploy_ransomware_canaries")
                    : .none
        )
    }

    private func checkNetworkMonitor() -> ProtectionCheck {
        // NickNetFilter requires the `content-filter-provider` entitlement (pending Apple
        // approval). Nick already monitors connections passively via lsof / NWPathMonitor.
        // Active blocking will be added once the entitlement is granted.
        let passiveMonitorActive = securityEngine?.activePipelineStatus == .running
        return ProtectionCheck(
            id: "network_monitor",
            title: "Network Monitor",
            status: passiveMonitorActive ? .protected : .warning,
            headline: passiveMonitorActive ? "Passive network monitoring active" : "Network monitoring is not running",
            explanation: passiveMonitorActive
                ? "Nick observes connection metadata. This does not mean the Network Extension content filter is installed or blocking traffic."
                : "Nick is not currently collecting network connection metadata.",
            icon: "network.badge.shield.half.filled",
            resolution: .none
        )
    }

    private func checkScamGuardian() -> ProtectionCheck {
        let isActive = isNetworkFilterActive
        let installerState = NetworkFilterInstaller.shared.state

        if !isActive, case .awaitingApproval = installerState {
            return ProtectionCheck(
                id: "scam_guardian",
                title: "Scam Guardian",
                status: .warning,
                headline: "Approve Nick's Network Filter",
                explanation: "macOS is waiting for you to allow the Network Extension in System Settings → General → Login Items & Extensions.",
                icon: "globe.badge.chevron.backward",
                resolution: .requiresPermission(
                    permissionName: "Network Extensions",
                    settingsURL: "x-apple.systempreferences:com.apple.LoginItems-Settings.extension"
                )
            )
        }

        if !isActive, case .failed(let message) = installerState {
            return ProtectionCheck(
                id: "scam_guardian",
                title: "Scam Guardian",
                status: .warning,
                headline: "Network Filter installation failed",
                explanation: message,
                icon: "globe.badge.chevron.backward",
                resolution: .installExtension(extensionName: "NickNetFilter")
            )
        }

        return ProtectionCheck(
            id: "scam_guardian",
            title: "Scam Guardian",
            status: isActive ? .protected : .warning,
            headline: isActive ? "Phishing and lookalike blocking is active" : "Active website blocking is not enabled",
            explanation: isActive
                ? "Nick's Network Filter is running and checking outbound connections for phishing and lookalike domains."
                : "Install and enable Nick's Network Filter to let Scam Guardian block known phishing and lookalike domains.",
            icon: "globe.badge.chevron.backward",
            resolution: isActive ? .none : .installExtension(extensionName: "NickNetFilter")
        )
    }

    private func checkEmailGuard() -> ProtectionCheck {
        let extensionActive = isEndpointSecurityActive
        let health = endpointExtensionHealth
        let scannerReady = extensionActive
            && Self.isEmailScannerReady(health, now: Date().timeIntervalSince1970)
        let signatureCount = health?["signatureCount"] as? Int ?? 0
        let yaraReady = health?["yaraRulesReady"] as? Bool == true

        return ProtectionCheck(
            id: "email_guard",
            title: "Email Guard",
            status: scannerReady ? .protected : .warning,
            headline: scannerReady
                ? "Email attachment screening is active"
                : extensionActive
                    ? "Email scanner is not ready"
                    : "Email attachment monitoring is not active",
            explanation: scannerReady
                ? "Nick watches supported Apple Mail and Outlook attachment locations and screens supported files with \(yaraReady ? "bundled YARA rules" : "local signatures")\(signatureCount > 0 ? " and \(signatureCount) known-malware signatures" : ""). No scanner catches every malicious attachment, so keep macOS and your mail provider's protections enabled."
                : extensionActive
                    ? "Email Guard needs working YARA rules and Full Disk Access for the security extension. Nick will not claim attachment screening until both are verified."
                    : "Email Guard requires Nick's Endpoint Security extension to be active.",
            icon: "envelope.badge.shield.half.filled",
            resolution: .none
        )
    }

    private func checkFileIntegrity() -> ProtectionCheck {
        // Surface the error from the last failed enable attempt as the check headline.
        if let errorMsg = fimBuildError {
            return ProtectionCheck(
                id: "file_integrity",
                title: "File Integrity Monitor",
                status: .warning,
                headline: errorMsg,
                explanation: "Make sure Nick's security extension is running, then try again.",
                icon: "doc.badge.gearshape",
                resolution: .autoEnable(action: "build_fim_baseline")
            )
        }

        let baselineCount = endpointExtensionHealth?["fimBaselineCount"] as? Int ?? 0
        let baselineExists = baselineCount > 0

        let extensionConnected = isEndpointSecurityActive
        if !extensionConnected {
            return ProtectionCheck(
                id: "file_integrity",
                title: "File Integrity Monitor",
                status: .warning,
                headline: "Waiting for security extension",
                explanation: baselineExists
                    ? "A baseline exists, but Nick cannot verify that the extension is monitoring it."
                    : "File monitoring requires Nick's Endpoint Security extension.",
                icon: "doc.badge.gearshape",
                resolution: .none
            )
        }

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
        let extensionActive = isEndpointSecurityActive

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
            status: extensionActive ? .protected : .warning,
            headline: extensionActive
                ? "Privacy permission changes are being monitored"
                : "Privacy permission monitoring is not active",
            explanation: extensionActive
                ? "Nick's verified security extension watches for changes to macOS privacy permissions."
                : "Privacy permission-change monitoring requires Nick's Endpoint Security extension.",
            icon: "hand.raised",
            resolution: .none
        )
    }

    private func checkSystemSettings() -> ProtectionCheck {
        // Check SIP, FileVault, Firewall, Gatekeeper
        let auditResults = securityEngine?.auditResults ?? []
        let failedChecks = auditResults.filter { $0.status == .fail }
        let inconclusiveChecks = auditResults.filter {
            $0.status == .warning || $0.status == .unknown
        }

        if auditResults.count == SystemCheckType.allCases.count,
           failedChecks.isEmpty,
           inconclusiveChecks.isEmpty {
            return ProtectionCheck(
                id: "system_settings",
                title: "System Security",
                status: .protected,
                headline: "Your Mac's built-in security is properly configured",
                explanation: "SIP, FileVault, Firewall, and Gatekeeper are all enabled.",
                icon: "gearshape",
                resolution: .none
            )
        }

        if auditResults.isEmpty || (!inconclusiveChecks.isEmpty && failedChecks.isEmpty) {
            return ProtectionCheck(
                id: "system_settings",
                title: "System Security",
                status: .warning,
                headline: auditResults.isEmpty ? "System security has not been verified" : "Some system checks were inconclusive",
                explanation: auditResults.isEmpty
                    ? "Run Smart Scan again after Nick finishes checking SIP, FileVault, Firewall, Gatekeeper, updates, and XProtect."
                    : "Nick could not confirm: \(inconclusiveChecks.map { $0.check.displayName }.joined(separator: ", ")).",
                icon: "gearshape",
                resolution: .none
            )
        }

        let issueNames = failedChecks.map { $0.check.displayName }.joined(separator: ", ")
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

    /// Verifies the actual sentinel files instead of trusting a preference flag.
    private func hasDeployedCanaryFiles() -> Bool {
        let fm = FileManager.default
        let home = fm.homeDirectoryForCurrentUser
        let protectedFolders = ["Desktop", "Documents", "Downloads", "Pictures"]
        return protectedFolders.contains { folder in
            let url = home.appendingPathComponent(folder, isDirectory: true)
            guard let names = try? fm.contentsOfDirectory(atPath: url.path) else { return false }
            return names.contains { $0.hasPrefix(".~nick_canary_") && $0.hasSuffix(".tmp") }
        }
    }

    /// XPC is required for timeline events and commands, but it is not the
    /// source of truth for whether Endpoint Security itself is protecting the
    /// Mac. The extension writes this heartbeat only after its ES client starts
    /// and subscribes successfully.
    private var isEndpointSecurityActive: Bool {
        guard
            let object = endpointExtensionHealth,
            object["active"] as? Bool == true,
            let runningVersion = object["version"] as? String,
            runningVersion == Self.bundledEndpointExtensionVersion,
            let updatedAt = object["updatedAt"] as? TimeInterval
        else {
            return false
        }

        let age = Date().timeIntervalSince1970 - updatedAt
        return age >= 0 && age <= 30
    }

    private var endpointExtensionHealth: [String: Any]? {
        let path = "/Library/Application Support/com.ehsanazish.nick/extension_health.json"
        guard
            let data = FileManager.default.contents(atPath: path),
            let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else {
            return nil
        }
        return object
    }

    /// Full Disk Access has no public grant API. An actual open of the protected
    /// TCC database is a stronger proof than trusting a preference or assuming
    /// that the app appearing in System Settings means its switch is enabled.
    private static var hasFullDiskAccess: Bool {
        guard let handle = FileHandle(
            forReadingAtPath: "/Library/Application Support/com.apple.TCC/TCC.db"
        ) else {
            return false
        }
        try? handle.close()
        return true
    }

    static func isEmailScannerReady(
        _ object: [String: Any]?,
        now: TimeInterval
    ) -> Bool {
        guard
            let object,
            object["active"] as? Bool == true,
            object["emailGuardActive"] as? Bool == true,
            object["emailScannerReady"] as? Bool == true,
            object["fullDiskAccessReady"] as? Bool == true,
            let updatedAt = object["updatedAt"] as? TimeInterval
        else {
            return false
        }
        let age = now - updatedAt
        return age >= 0 && age <= 30
    }

    private var isNetworkFilterActive: Bool {
        guard networkFilterPreferenceEnabled else { return false }

        guard
            let path = NetworkProtectionSharedStore.healthURL()?.path,
            let data = FileManager.default.contents(atPath: path),
            let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else {
            return false
        }

        return Self.isCurrentNetworkFilterHealth(
            object,
            now: Date().timeIntervalSince1970
        )
    }

    private static var bundledEndpointExtensionVersion: String? {
        let extensionURL = Bundle.main.bundleURL
            .appendingPathComponent("Contents/Library/SystemExtensions")
            .appendingPathComponent("com.ehsanazish.nick.NickExtension.systemextension")
        return Bundle(url: extensionURL)?
            .object(forInfoDictionaryKey: kCFBundleVersionKey as String) as? String
    }

    /// Old filter builds wrote only `active`, which made Smart Scan trust an
    /// unsafe configuration forever after an app update. Requiring an explicit
    /// behavior version makes updates re-run guided setup and replace it.
    static func isCurrentNetworkFilterHealth(
        _ object: [String: Any],
        now: TimeInterval
    ) -> Bool {
        guard
            object["active"] as? Bool == true,
            object["configurationVersion"] as? Int
                == NetworkProtectionConfiguration.configurationVersion,
            object["failOpen"] as? Bool == true,
            let updatedAt = object["updatedAt"] as? TimeInterval
        else {
            return false
        }
        let age = now - updatedAt
        return age >= 0 && age <= 30
    }

    // MARK: - Resolution Execution

    private func performAutoEnable(action: String) async {
        switch action {
        case "deploy_ransomware_canaries":
            deployRansomwareCanaries()

        case "enable_scam_guardian":
            UserDefaults.standard.set(true, forKey: "scamGuardianEnabled")

        case "enable_email_guard":
            UserDefaults.standard.set(true, forKey: "emailGuardEnabled")

        case "build_fim_baseline":
            fimBuildError = nil
            guard let client = xpcClient else {
                fimBuildError = "Extension not running — install or start Nick's security extension first"
                return
            }
            // Ask the running extension to rebuild the FIM baseline on disk.
            let success = await withCheckedContinuation { continuation in
                client.requestRebuildFIMBaseline { result in continuation.resume(returning: result) }
            }
            // Give the extension a moment to write the baseline file
            try? await Task.sleep(nanoseconds: 500_000_000)
            // Verify the file was actually created
            let baselinePath = "/Library/Application Support/com.ehsanazish.nick/fim_baseline.json"
            if success && FileManager.default.fileExists(atPath: baselinePath) {
                UserDefaults.standard.set(true, forKey: "nickFIMBaselineBuilt")
            } else {
                fimBuildError = "Baseline build failed — make sure Nick's extension is running and has Full Disk Access"
            }

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
        if name == "NickNetFilter" {
            await NetworkFilterInstaller.shared.installAndEnable()
        } else {
            extensionManager?.installExtension()
        }
    }

    /// Sentinel creation belongs in the logged-in app: a root system extension's
    /// `~` resolves to `/var/root`, not the user's Desktop and Documents.
    private func deployRansomwareCanaries() {
        let fm = FileManager.default
        let home = fm.homeDirectoryForCurrentUser
        for folder in ["Desktop", "Documents", "Downloads", "Pictures"] {
            let directory = home.appendingPathComponent(folder, isDirectory: true)
            guard fm.fileExists(atPath: directory.path) else { continue }
            let existing = (try? fm.contentsOfDirectory(atPath: directory.path)) ?? []
            guard !existing.contains(where: {
                $0.hasPrefix(".~nick_canary_") && $0.hasSuffix(".tmp")
            }) else { continue }

            let name = ".~nick_canary_\(UUID().uuidString.prefix(8)).tmp"
            var url = directory.appendingPathComponent(name)
            let content = "NICK_CANARY_DO_NOT_MODIFY_\(Date())"
            try? content.write(to: url, atomically: true, encoding: .utf8)
            var values = URLResourceValues()
            values.isHidden = true
            try? url.setResourceValues(values)
        }
        UserDefaults.standard.set(hasDeployedCanaryFiles(), forKey: "ransomwareCanariesDeployed")
    }

    // MARK: - Single-check rescan

    /// Re-evaluates the check with the given `id` and returns the updated result.
    /// Used to refresh a single row after an individual "Enable" action.
    func rescanCheck(id: String) -> ProtectionCheck? {
        switch id {
        case "endpoint_security":  return checkEndpointSecurity()
        case "ransomware_shield":  return checkRansomwareShield()
        case "network_monitor":    return checkNetworkMonitor()
        case "scam_guardian":      return checkScamGuardian()
        case "email_guard":        return checkEmailGuard()
        case "file_integrity":     return checkFileIntegrity()
        case "privacy_guard":      return checkPrivacyGuard()
        case "system_settings":    return checkSystemSettings()
        default:                   return nil
        }
    }
}

// MARK: - Network Filter Installation

@MainActor
final class NetworkFilterInstaller: NSObject, OSSystemExtensionRequestDelegate {
    static let shared = NetworkFilterInstaller()
    private static let logger = Logger(
        subsystem: "com.ehsanazish.nick",
        category: "NetworkFilterInstaller"
    )

    enum State: Equatable {
        case idle
        case submitting
        case awaitingApproval
        case configuring
        case failed(String)
    }

    private(set) var state: State = .idle
    private var continuation: CheckedContinuation<Void, Never>?
    private var shouldOpenSettingsForCurrentRequest = false
    private var activeInstallation: Task<Void, Never>?

    func installAndEnable() async {
        if let activeInstallation {
            await activeInstallation.value
            return
        }

        let installation = Task { @MainActor [weak self] in
            guard let self else { return }
            await self.performInstallAndEnable()
        }
        activeInstallation = installation
        await installation.value
        activeInstallation = nil
    }

    private func performInstallAndEnable() async {
        switch state {
        case .submitting, .configuring:
            return
        case .awaitingApproval:
            await submitActivationRequest(openSettingsIfApprovalIsStillNeeded: true)
            return
        case .idle, .failed:
            break
        }

        await submitActivationRequest(openSettingsIfApprovalIsStillNeeded: true)
    }

    private func submitActivationRequest(openSettingsIfApprovalIsStillNeeded: Bool) async {
        Self.logger.info("Submitting Network Filter system-extension activation")
        state = .submitting
        shouldOpenSettingsForCurrentRequest = openSettingsIfApprovalIsStillNeeded
        await withCheckedContinuation { continuation in
            self.continuation = continuation
            let request = OSSystemExtensionRequest.activationRequest(
                forExtensionWithIdentifier: "com.ehsanazish.nick.NickNetFilter",
                queue: .main
            )
            request.delegate = self
            OSSystemExtensionManager.shared.submitRequest(request)
        }
    }

    func disableFilter() async {
        let manager = NEFilterManager.shared()
        do {
            try await manager.loadFromPreferences()
            guard manager.isEnabled else { return }
            manager.isEnabled = false
            try await manager.saveToPreferences()
            state = .idle
        } catch {
            state = .failed(
                "Nick could not disable the older Network Filter automatically. Open System Settings → General → Login Items & Extensions → Network Extensions and turn off Nick before continuing."
            )
        }
    }

    nonisolated func request(
        _: OSSystemExtensionRequest,
        actionForReplacingExtension _: OSSystemExtensionProperties,
        withExtension _: OSSystemExtensionProperties
    ) -> OSSystemExtensionRequest.ReplacementAction {
        .replace
    }

    nonisolated func requestNeedsUserApproval(_: OSSystemExtensionRequest) {
        Task { @MainActor in
            Self.logger.info("Network Filter system extension requires user approval")
            state = .awaitingApproval
            finishCurrentAction()
            if shouldOpenSettingsForCurrentRequest {
                openExtensionSettings()
            }
            shouldOpenSettingsForCurrentRequest = false
        }
    }

    nonisolated func request(
        _: OSSystemExtensionRequest,
        didFinishWithResult _: OSSystemExtensionRequest.Result
    ) {
        Task { @MainActor in
            Self.logger.info("Network Filter system extension activation completed")
            shouldOpenSettingsForCurrentRequest = false
            state = .configuring
            if let errorMessage = await configureFilter() {
                state = .failed(errorMessage)
            } else {
                state = .idle
            }
            finishCurrentAction()
        }
    }

    nonisolated func request(_: OSSystemExtensionRequest, didFailWithError error: Error) {
        Task { @MainActor in
            Self.logger.error(
                "Network Filter system extension activation failed: \(error.localizedDescription, privacy: .public)"
            )
            shouldOpenSettingsForCurrentRequest = false
            state = .failed(error.localizedDescription)
            finishCurrentAction()
        }
    }

    private func configureFilter() async -> String? {
        let manager = NEFilterManager.shared()
        do {
            try await manager.loadFromPreferences()
            let configuration = NEFilterProviderConfiguration()
            configuration.filterSockets = true
            configuration.filterPackets = false
            configuration.filterDataProviderBundleIdentifier =
                "com.ehsanazish.nick.NickNetFilter"
            configuration.vendorConfiguration =
                NetworkProtectionConfiguration().vendorConfiguration
            manager.providerConfiguration = configuration
            manager.localizedDescription = "Nick Scam Guardian"
            manager.isEnabled = true
            try await manager.saveToPreferences()
            try? await Task.sleep(for: .milliseconds(500))
            try await manager.loadFromPreferences()

            guard manager.isEnabled else {
                return "The Network Filter was installed, but macOS did not enable it. Open System Settings and enable Nick under Network Extensions."
            }

            Self.logger.info("Network Filter preferences are installed and enabled")
            if await waitForLiveHealth() {
                Self.logger.info("Network Filter provider reported live health")
                return nil
            }

            Self.logger.error(
                "Network Filter is enabled in preferences but its provider did not report health"
            )
            return "The Network Filter is installed, but macOS has not started it. Open System Settings → General → Login Items & Extensions → Network Extensions, turn Nick on, then return to Nick."
        } catch {
            Self.logger.error(
                "Network Filter configuration failed: \(error.localizedDescription, privacy: .public)"
            )
            return error.localizedDescription
        }
    }

    private func waitForLiveHealth() async -> Bool {
        for _ in 0..<20 {
            if let path = NetworkProtectionSharedStore.healthURL()?.path,
               let data = FileManager.default.contents(atPath: path),
               let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
               SmartScanChecker.isCurrentNetworkFilterHealth(
                   object,
                   now: Date().timeIntervalSince1970
               ) {
                return true
            }
            try? await Task.sleep(for: .seconds(1))
        }
        return false
    }

    private func finishCurrentAction() {
        continuation?.resume()
        continuation = nil
    }

    private func openExtensionSettings() {
        guard let url = URL(
            string: "x-apple.systempreferences:com.apple.LoginItems-Settings.extension"
        ) else { return }
        NSWorkspace.shared.open(url)
    }
}
