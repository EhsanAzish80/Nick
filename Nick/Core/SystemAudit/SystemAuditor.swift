// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation
import Observation
import os

// MARK: - SystemAuditorError

/// Errors that `SystemAuditor` can throw.
enum SystemAuditorError: LocalizedError {

    /// A required system tool could not be found or executed.
    case toolUnavailable(path: String)

    /// The command output did not match any expected format.
    case unexpectedOutput(command: String, output: String)

    var errorDescription: String? {
        switch self {
        case .toolUnavailable(let path):
            return "Required system tool not found: \(path)"
        case .unexpectedOutput(let cmd, let out):
            return "Unexpected output from '\(cmd)': \(out)"
        }
    }
}

// MARK: - SystemAuditor

/// Reads macOS security configuration and reports the results as `SystemCheckResult` values.
///
/// `SystemAuditor` is a read-only, snapshot-mode monitor. It runs each check once
/// when `start()` is called (or `runAllChecks()` directly) and stores the results.
/// There is no continuous polling — call `refresh()` to re-run all checks.
///
/// Each check shells out to a specific Apple system utility with a hardcoded path
/// and no user-supplied input, making command injection impossible by design.
///
/// - Note: `remoteLogin` check requires elevated privileges (via `systemsetup`).
///         If permissions are denied it returns `.unknown` gracefully.
@Observable
@MainActor
final class SystemAuditor: MonitorProtocol {

    // MARK: - MonitorProtocol

    let monitorType: MonitorType = .systemAudit
    private(set) var isRunning = false

    // MARK: - Published State

    /// Results from the most recent `runAllChecks()` invocation.
    private(set) var results: [SystemCheckResult] = []

    /// Signals derived from failed or warned checks.
    private var pendingSignals: [ThreatSignal] = []

    // MARK: - Private

    private static let logger = Logger(
        subsystem: "com.ehsanazish.nick",
        category: "SystemAuditor"
    )

    // MARK: - MonitorProtocol

    /// Runs all security checks once and stores the results.
    func start() async throws {
        guard !isRunning else { return }
        isRunning = true
        defer { isRunning = false }
        let checkResults = await runAllChecks()
        results = checkResults
        pendingSignals = checkResults.compactMap { makeSignal(from: $0) }
        Self.logger.info("System audit complete — \(checkResults.count) checks, \(self.pendingSignals.count) signals")
    }

    /// No-op. `SystemAuditor` is not a continuous monitor.
    func stop() async {
        isRunning = false
    }

    func latestSignals() async -> [ThreatSignal] {
        let signals = pendingSignals
        pendingSignals = []
        return signals
    }

    // MARK: - Public API

    /// Executes all security checks and returns their results.
    ///
    /// - Returns: One `SystemCheckResult` per `SystemCheckType` case.
    func runAllChecks() async -> [SystemCheckResult] {
        await withTaskGroup(of: SystemCheckResult.self) { group in
            for checkType in SystemCheckType.allCases {
                group.addTask { await self.runCheck(checkType) }
            }
            var collected: [SystemCheckResult] = []
            for await result in group { collected.append(result) }
            // Sort by check type order for stable UI display
            return collected.sorted { $0.check.rawValue < $1.check.rawValue }
        }
    }

    /// Runs a single named security check.
    ///
    /// - Parameter type: The check to execute.
    /// - Returns: A `SystemCheckResult` describing the outcome.
    func runCheck(_ type: SystemCheckType) async -> SystemCheckResult {
        Self.logger.debug("Running check: \(type.rawValue)")
        switch type {
        case .sip:              return await checkSIP()
        case .fileVault:        return await checkFileVault()
        case .gatekeeper:       return await checkGatekeeper()
        case .firewall:         return await checkFirewall()
        case .firewallStealth:  return await checkFirewallStealth()
        case .xprotect:         return await checkXProtect()
        case .automaticUpdates: return await checkAutomaticUpdates()
        case .remoteLogin:      return await checkRemoteLogin()
        }
    }

    // MARK: - Individual Checks

    private func checkSIP() async -> SystemCheckResult {
        let output = (try? await runCommand("/usr/bin/csrutil", args: ["status"])) ?? ""
        let enabled = output.lowercased().contains("enabled")
        let disabled = output.lowercased().contains("disabled")

        let status: CheckStatus
        if enabled { status = .pass }
        else if disabled { status = .fail }
        else { status = .unknown }

        return SystemCheckResult(
            id: UUID(),
            check: .sip,
            status: status,
            currentValue: enabled ? "Enabled" : (disabled ? "Disabled" : "Unknown"),
            expectedValue: "Enabled",
            description: "System Integrity Protection prevents modifications to system files, even by root.",
            recommendation: status == .fail ? "Re-enable SIP by booting to Recovery Mode and running `csrutil enable`." : nil
        )
    }

    private func checkFileVault() async -> SystemCheckResult {
        let output = (try? await runCommand("/usr/bin/fdesetup", args: ["status"])) ?? ""
        let isOn = output.contains("FileVault is On")
        let isOff = output.contains("FileVault is Off")

        let status: CheckStatus
        if isOn { status = .pass }
        else if isOff { status = .fail }
        else { status = .unknown }

        return SystemCheckResult(
            id: UUID(),
            check: .fileVault,
            status: status,
            currentValue: isOn ? "On" : (isOff ? "Off" : "Unknown"),
            expectedValue: "On",
            description: "FileVault encrypts the startup disk, protecting data if your Mac is lost or stolen.",
            recommendation: status == .fail ? "Enable FileVault in System Settings → Privacy & Security → FileVault." : nil
        )
    }

    private func checkGatekeeper() async -> SystemCheckResult {
        let output = (try? await runCommand("/usr/sbin/spctl", args: ["--status"])) ?? ""
        let enabled = output.lowercased().contains("assessments enabled")
        let disabled = output.lowercased().contains("assessments disabled")

        let status: CheckStatus
        if enabled { status = .pass }
        else if disabled { status = .fail }
        else { status = .unknown }

        return SystemCheckResult(
            id: UUID(),
            check: .gatekeeper,
            status: status,
            currentValue: enabled ? "Assessments enabled" : (disabled ? "Assessments disabled" : "Unknown"),
            expectedValue: "Assessments enabled",
            description: "Gatekeeper verifies that apps are notarised by Apple before allowing them to run.",
            recommendation: status == .fail ? "Run `sudo spctl --master-enable` in Terminal to re-enable Gatekeeper." : nil
        )
    }

    private func checkFirewall() async -> SystemCheckResult {
        let fwPath = "/usr/libexec/ApplicationFirewall/socketfilterfw"
        let output = (try? await runCommand(fwPath, args: ["--getglobalstate"])) ?? ""
        let enabled = output.lowercased().contains("enabled")
        let disabled = output.lowercased().contains("disabled")

        let status: CheckStatus
        if enabled { status = .pass }
        else if disabled { status = .fail }
        else { status = .unknown }

        return SystemCheckResult(
            id: UUID(),
            check: .firewall,
            status: status,
            currentValue: enabled ? "Enabled" : (disabled ? "Disabled" : "Unknown"),
            expectedValue: "Enabled",
            description: "The Application Firewall controls which apps may accept incoming network connections.",
            recommendation: status == .fail ? "Enable the firewall in System Settings → Network → Firewall." : nil
        )
    }

    private func checkFirewallStealth() async -> SystemCheckResult {
        let fwPath = "/usr/libexec/ApplicationFirewall/socketfilterfw"
        let output = (try? await runCommand(fwPath, args: ["--getstealthmode"])) ?? ""
        let enabled = output.lowercased().contains("enabled")
        let disabled = output.lowercased().contains("disabled")

        let status: CheckStatus
        if enabled { status = .pass }
        else if disabled { status = .warning }
        else { status = .unknown }

        return SystemCheckResult(
            id: UUID(),
            check: .firewallStealth,
            status: status,
            currentValue: enabled ? "Enabled" : (disabled ? "Disabled" : "Unknown"),
            expectedValue: "Enabled",
            description: "Stealth mode causes your Mac to ignore unsolicited probe packets, reducing network visibility.",
            recommendation: status == .warning ? "Enable stealth mode in System Settings → Network → Firewall → Options." : nil
        )
    }

    private func checkXProtect() async -> SystemCheckResult {
        let plistPath = "/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist"
        guard
            let data = try? Data(contentsOf: URL(fileURLWithPath: plistPath)),
            let plist = try? PropertyListSerialization.propertyList(from: data, format: nil),
            let dict = plist as? [String: Any],
            let versionString = dict["CFBundleShortVersionString"] as? String
        else {
            return SystemCheckResult(
                id: UUID(), check: .xprotect, status: .unknown,
                currentValue: "Unreadable", expectedValue: "Up to date",
                description: "Could not read XProtect version. Full Disk Access may be required.",
                recommendation: nil
            )
        }

        // Check modification date of the bundle as a proxy for freshness
        let attrs = try? FileManager.default.attributesOfItem(atPath: plistPath)
        let modDate = attrs?[.modificationDate] as? Date ?? Date.distantPast
        let daysSinceUpdate = Calendar.current.dateComponents([.day], from: modDate, to: Date()).day ?? 999
        let isStale = daysSinceUpdate > 30

        return SystemCheckResult(
            id: UUID(),
            check: .xprotect,
            status: isStale ? .warning : .pass,
            currentValue: "Version \(versionString) (updated \(daysSinceUpdate)d ago)",
            expectedValue: "Updated within 30 days",
            description: "XProtect provides signature-based malware detection. Definitions should stay current.",
            recommendation: isStale ? "Ensure automatic updates are enabled so XProtect definitions are refreshed." : nil
        )
    }

    private func checkAutomaticUpdates() async -> SystemCheckResult {
        let output = (try? await runCommand(
            "/usr/bin/defaults",
            args: ["read", "/Library/Preferences/com.apple.SoftwareUpdate", "AutomaticCheckEnabled"]
        )) ?? ""
        let trimmed = output.trimmingCharacters(in: .whitespacesAndNewlines)
        let isEnabled = trimmed == "1"
        let isDisabled = trimmed == "0"

        let status: CheckStatus
        if isEnabled { status = .pass }
        else if isDisabled { status = .warning }
        else { status = .unknown }

        return SystemCheckResult(
            id: UUID(),
            check: .automaticUpdates,
            status: status,
            currentValue: isEnabled ? "Enabled" : (isDisabled ? "Disabled" : "Unknown"),
            expectedValue: "Enabled",
            description: "Automatic update checks ensure security patches are applied promptly.",
            recommendation: status == .warning ? "Enable automatic updates in System Settings → General → Software Update." : nil
        )
    }

    private func checkRemoteLogin() async -> SystemCheckResult {
        // SECURITY: systemsetup requires elevated privileges on some macOS versions.
        // If it fails, return .unknown rather than crashing or hanging.
        let output = (try? await runCommand("/usr/sbin/systemsetup", args: ["-getremotelogin"])) ?? ""
        let isOff = output.lowercased().contains("off")
        let isOn  = output.lowercased().contains("on")

        let status: CheckStatus
        if isOff { status = .pass }
        else if isOn { status = .warning }
        else { status = .unknown }

        return SystemCheckResult(
            id: UUID(),
            check: .remoteLogin,
            status: status,
            currentValue: isOff ? "Off" : (isOn ? "On" : "Unknown"),
            expectedValue: "Off",
            description: "Remote Login enables SSH access to your Mac. Disable it unless actively needed.",
            recommendation: status == .warning ? "Disable Remote Login in System Settings → General → Sharing." : nil
        )
    }

    // MARK: - Signal Conversion

    private func makeSignal(from result: SystemCheckResult) -> ThreatSignal? {
        guard result.status == .fail || result.status == .warning else { return nil }
        return ThreatSignal(
            source: .systemAudit,
            severity: result.impliedSeverity,
            title: "\(result.check.displayName): \(result.currentValue)",
            description: result.description,
            metadata: ["check": result.check.rawValue, "value": result.currentValue]
        )
    }

    // MARK: - Private Helpers

    /// Runs a system command asynchronously and returns its standard output.
    ///
    /// - Parameters:
    ///   - path: Absolute path to the executable. Must be hardcoded — never user-supplied.
    ///   - args: Arguments to pass. Must be hardcoded — never user-supplied.
    ///
    /// - Returns: The combined stdout output as a `String`.
    /// - Throws: `SystemAuditorError.toolUnavailable` if the executable doesn't exist.
    ///
    /// - Note: `waitUntilExit()` is called on a detached thread via `terminationHandler`
    ///         so the calling async task is never blocked.
    func runCommand(_ path: String, args: [String]) async throws -> String {
        guard FileManager.default.isExecutableFile(atPath: path) else {
            throw SystemAuditorError.toolUnavailable(path: path)
        }

        return try await withCheckedThrowingContinuation { continuation in
            let process = Process()
            process.executableURL = URL(fileURLWithPath: path)
            process.arguments = args

            let outputPipe = Pipe()
            process.standardOutput = outputPipe
            process.standardError = Pipe() // discard stderr

            process.terminationHandler = { _ in
                let data = outputPipe.fileHandleForReading.readDataToEndOfFile()
                let output = String(data: data, encoding: .utf8) ?? ""
                continuation.resume(returning: output)
            }

            do {
                try process.run()
            } catch {
                continuation.resume(throwing: error)
            }
        }
    }
}
