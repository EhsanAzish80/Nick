// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import AppKit
import SwiftUI

/// Runs a lightweight protection audit whenever Nick opens. Healthy installs
/// pass through without showing UI; incomplete installs get one guided step at
/// a time instead of leaving the user to discover Smart Scan on their own.
struct ProtectionSetupGate<Content: View>: View {

    @Environment(SecurityEngine.self) private var engine
    @Environment(ExtensionXPCClient.self) private var xpcClient

    @State private var checker = SmartScanChecker()
    @State private var extensionManager = ExtensionManager()
    @State private var status: SmartScanStatus?
    @State private var isChecking = true
    @State private var isPresentingSetup = false

    private let content: Content

    init(@ViewBuilder content: () -> Content) {
        self.content = content()
    }

    var body: some View {
        Group {
            if isChecking {
                VStack(spacing: 12) {
                    ProgressView()
                    Text("Checking protection…")
                        .font(.nickBodySmall)
                        .foregroundStyle(Color.textSecondary)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
                .background(Color.backgroundPrimary)
            } else if isPresentingSetup, let status {
                ProtectionSetupView(
                    status: status,
                    checker: checker,
                    onStatusChange: updateStatus,
                    onFinish: { isPresentingSetup = false }
                )
            } else {
                content
            }
        }
        .task {
            checker.securityEngine = engine
            checker.xpcClient = xpcClient
            checker.extensionManager = extensionManager
            xpcClient.connect()

            // Allow extension health/XPC state to settle so an update does not
            // briefly show setup for protections that are already active.
            try? await Task.sleep(for: .seconds(1))
            await checker.disableOutdatedNetworkFilterIfNeeded()
            await checker.refreshLiveProtectionState()
            let freshStatus = checker.runScan()
            updateStatus(freshStatus)
            isPresentingSetup = freshStatus.checks.contains(where: needsGuidance)
            isChecking = false
        }
        .onChange(of: xpcClient.isConnected) {
            refresh()
        }
        .onChange(of: extensionManager.extensionState) {
            refresh()
        }
    }

    private func refresh() {
        guard !isChecking else { return }
        Task { @MainActor in
            await checker.refreshLiveProtectionState()
            updateStatus(checker.runScan())
            isPresentingSetup = status?.checks.contains(where: needsGuidance) == true
        }
    }

    private func updateStatus(_ newStatus: SmartScanStatus) {
        if let status, setupFingerprint(status) == setupFingerprint(newStatus) {
            return
        }
        status = newStatus
        if isPresentingSetup,
           !newStatus.checks.contains(where: needsGuidance) {
            isPresentingSetup = false
        }
    }

    private func setupFingerprint(_ status: SmartScanStatus) -> [String] {
        status.checks.map {
            [
                $0.id,
                $0.status.rawValue,
                $0.headline,
                $0.explanation,
                $0.resolution.buttonLabel,
            ].joined(separator: "|")
        }
    }

    private func needsGuidance(_ check: ProtectionCheck) -> Bool {
        guard check.status != .protected else { return false }
        switch check.resolution {
        case .autoEnable, .requiresPermission, .installExtension, .revealAppForInstallation, .none:
            return true
        case .pendingApproval:
            return false
        }
    }
}

private struct ProtectionSetupView: View {

    let status: SmartScanStatus
    let checker: SmartScanChecker
    let onStatusChange: (SmartScanStatus) -> Void
    let onFinish: () -> Void

    @Environment(\.scenePhase) private var scenePhase
    @State private var isWorking = false

    private var guidedChecks: [ProtectionCheck] {
        status.checks.filter { check in
            guard check.status != .protected else { return false }
            switch check.resolution {
            case .autoEnable, .requiresPermission, .installExtension, .revealAppForInstallation, .none:
                return true
            case .pendingApproval:
                return false
            }
        }
    }

    private var currentCheck: ProtectionCheck? { guidedChecks.first }
    private var completedCount: Int {
        status.checks.filter { $0.status == .protected }.count
    }

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 10) {
                Image(nsImage: NSApp.applicationIconImage)
                    .resizable()
                    .frame(width: 40, height: 40)
                VStack(alignment: .leading, spacing: 2) {
                    Text("Set up Nick protection")
                        .font(.title2.bold())
                    Text("\(completedCount) of \(status.checks.count) checks ready")
                        .font(.nickBodySmall)
                        .foregroundStyle(Color.textSecondary)
                }
                Spacer()
            }
            .padding(24)

            ProgressView(value: Double(completedCount), total: Double(status.checks.count))
                .tint(Color.statusGreen)
                .padding(.horizontal, 24)

            Divider()
                .padding(.top, 20)

            if let check = currentCheck {
                setupCard(check)
            } else {
                allSetView
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Color.backgroundPrimary)
        .task(id: currentCheck?.id) {
            // Approval happens outside Nick. Poll only while this guided screen
            // is visible so it advances as soon as macOS reports healthy state.
            while !Task.isCancelled, currentCheck != nil {
                try? await Task.sleep(for: .seconds(2))
                await refresh()
            }
        }
        .onChange(of: scenePhase) {
            if scenePhase == .active {
                Task { await refresh() }
            }
        }
    }

    @ViewBuilder
    private func setupCard(_ check: ProtectionCheck) -> some View {
        VStack(spacing: 24) {
            Spacer()

            Image(systemName: check.icon)
                .font(.system(size: 46))
                .foregroundStyle(Color.statusOrange)
                .frame(width: 84, height: 84)
                .background(Color.statusOrange.opacity(0.12), in: Circle())

            VStack(spacing: 8) {
                Text(check.title)
                    .font(.title.bold())
                Text(check.headline)
                    .font(.headline)
                Text(setupExplanation(for: check))
                    .font(.body)
                    .foregroundStyle(Color.textSecondary)
                    .multilineTextAlignment(.center)
                    .frame(maxWidth: 560)
            }

            if isFullDiskAccessStep(check) {
                VStack(alignment: .leading, spacing: 10) {
                    permissionRow("Nick", detail: "Allows scans of protected user data")
                    permissionRow(
                        "NickExtension",
                        detail: "Allows real-time and Email Guard monitoring"
                    )
                    Text("Turn on both switches in System Settings. macOS may ask you to quit and reopen Nick.")
                        .font(.nickBodySmall)
                        .foregroundStyle(Color.textSecondary)
                }
                .frame(maxWidth: 500, alignment: .leading)
            }

            VStack(spacing: 10) {
                Button(isWorking ? workingLabel(for: check) : actionLabel(for: check)) {
                    resolve(check)
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.large)
                .disabled(isWorking)

                Button("Continue to Nick for now") {
                    onFinish()
                }
                .buttonStyle(.plain)
                .foregroundStyle(Color.textSecondary)
            }

            Spacer()
        }
        .padding(32)
    }

    private var allSetView: some View {
        VStack(spacing: 20) {
            Spacer()
            Image(systemName: "checkmark.shield.fill")
                .font(.system(size: 58))
                .foregroundStyle(Color.statusGreen)
            Text("Protection is ready")
                .font(.title.bold())
            Text("Nick verified each available protection component on this Mac.")
                .foregroundStyle(Color.textSecondary)
            Button("Continue to Nick", action: onFinish)
                .buttonStyle(.borderedProminent)
                .controlSize(.large)
            Spacer()
        }
        .padding(32)
    }

    private func resolve(_ check: ProtectionCheck) {
        isWorking = true
        Task { @MainActor in
            await checker.resolve(check: check)
            try? await Task.sleep(for: .seconds(1))
            await refresh()
            isWorking = false
        }
    }

    @MainActor
    private func refresh() async {
        await checker.refreshLiveProtectionState()
        onStatusChange(checker.runScan())
    }

    private func actionLabel(for check: ProtectionCheck) -> String {
        if isFullDiskAccessStep(check) {
            return "Open Full Disk Access"
        }
        switch check.resolution {
        case .requiresPermission: return "Open System Settings"
        case .revealAppForInstallation: return "Show Nick in Finder"
        case .installExtension: return "Install and Continue"
        case .autoEnable: return "Enable and Continue"
        case .pendingApproval, .none: return "Check Again"
        }
    }

    private func workingLabel(for check: ProtectionCheck) -> String {
        switch check.resolution {
        case .installExtension: return "Installing…"
        case .autoEnable: return "Enabling…"
        default: return "Checking…"
        }
    }

    private func setupExplanation(for check: ProtectionCheck) -> String {
        if check.id == "scam_guardian" {
            let privacyExplanation = """
            Nick's Network Filter checks connection destinations against known phishing and lookalike domains. It does not inspect page contents or save browsing history. Behavioral anomalies are allowed and reported—they never cut off normal browsing.
            """
            if check.headline != "Active website blocking is not enabled" {
                return "\(check.explanation)\n\n\(privacyExplanation)"
            }
            return privacyExplanation
        }
        return check.explanation
    }

    private func isFullDiskAccessStep(_ check: ProtectionCheck) -> Bool {
        guard case .requiresPermission(let name, _) = check.resolution else {
            return false
        }
        return name == "Full Disk Access"
    }

    private func permissionRow(_ name: String, detail: String) -> some View {
        HStack(spacing: 10) {
            Image(systemName: "circle")
                .foregroundStyle(Color.statusOrange)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 1) {
                Text(name)
                    .font(.headline)
                Text(detail)
                    .font(.nickBodySmall)
                    .foregroundStyle(Color.textSecondary)
            }
        }
        .accessibilityElement(children: .combine)
    }
}
