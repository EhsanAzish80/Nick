// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation

// MARK: - Protection page copy

enum SimpleProtectionCopy {

    /// Navigation subtitle, e.g. "Everything is on" or "2 of 4 paused".
    static func subtitle(for cards: [ProtectionCard]) -> String {
        let notOn = cards.filter { $0.status != .on }.count
        if notOn == 0 { return "Everything is on" }
        return "\(notOn) of \(cards.count) need\(notOn == 1 ? "s" : "") attention"
    }

    /// One line on what each group covers, shown under its title.
    static func explanation(for group: ProtectionCard.Group) -> String {
        switch group {
        case .appsAndDownloads:
            "Nick checks every app and download the moment it arrives and stops anything harmful from opening."
        case .websitesAndEmail:
            "Nick warns you before you open a scam website or a risky email attachment."
        case .filesAndRansomware:
            "Nick watches your documents and steps in if something starts locking or changing lots of them."
        case .cameraAndMicrophone:
            "Nick tells you when an app starts using your camera or microphone."
        }
    }
}

// MARK: - Fix rows

/// A "Fix" row shown under a protection group that isn't fully on.
struct ProtectionFix: Equatable {
    enum Action: Equatable {
        case allowSecurityExtension
        case allowWebFilter
        case restartWebFilter
        case setUpRansomwareWatch
    }

    let message: String
    let buttonTitle: String
    let action: Action

    static let securityExtensionURL = "x-apple.systempreferences:com.apple.LoginItems-Settings.extension"

    static func fix(for card: ProtectionCard, networkState: NetworkProtectionManager.State) -> ProtectionFix? {
        guard card.status != .on else { return nil }
        switch card.group {
        case .appsAndDownloads, .cameraAndMicrophone:
            return ProtectionFix(
                message: "Allow Nick’s security extension in System Settings to turn this back on.",
                buttonTitle: "Open Settings",
                action: .allowSecurityExtension
            )
        case .websitesAndEmail:
            switch networkState {
            case .awaitingApproval:
                return ProtectionFix(
                    message: "Allow Nick’s web filter in System Settings to finish turning this on.",
                    buttonTitle: "Open Settings",
                    action: .allowWebFilter
                )
            case .failed:
                return ProtectionFix(
                    message: "The web filter stopped unexpectedly.",
                    buttonTitle: "Try Again",
                    action: .restartWebFilter
                )
            case .enabled, .disabled, .loading:
                return nil
            }
        case .filesAndRansomware:
            if card.status == .paused {
                return ProtectionFix(
                    message: "Allow Nick’s security extension in System Settings to turn this back on.",
                    buttonTitle: "Open Settings",
                    action: .allowSecurityExtension
                )
            }
            return ProtectionFix(
                message: "Ransomware watch needs a one-time set-up.",
                buttonTitle: "Set Up",
                action: .setUpRansomwareWatch
            )
        }
    }
}

// MARK: - Mac security settings, in plain words

struct SimpleMacSetting: Identifiable, Equatable {
    enum State: String, Equatable {
        case ok = "OK"
        case needsFixing = "Needs fixing"
        case check = "Check"
        case unknown = "Unknown"
    }

    let check: SystemCheckType
    let state: State

    var id: String { check.rawValue }

    var title: String {
        switch check {
        case .fileVault:        "Disk encryption (FileVault)"
        case .gatekeeper:       "App checks (Gatekeeper)"
        case .sip:              "System protection"
        case .firewall:         "Firewall"
        case .firewallStealth:  "Stealth mode"
        case .automaticUpdates: "Automatic updates"
        case .xprotect:         "Apple’s malware list"
        case .remoteLogin:      "Remote Login"
        }
    }

    var explanation: String {
        switch check {
        case .fileVault:        "Keeps your files unreadable if your Mac is lost or stolen."
        case .gatekeeper:       "Only lets apps from identified developers open."
        case .sip:
            state == .ok
                ? "Stops apps from changing core parts of macOS."
                : "Turned off. It can only be turned back on from macOS Recovery."
        case .firewall:         "Blocks unwanted incoming connections."
        case .firewallStealth:  "Makes your Mac harder to find on public Wi-Fi."
        case .automaticUpdates: "Installs Apple’s security fixes for you."
        case .xprotect:         "Apple’s built-in list of known malware is up to date."
        case .remoteLogin:
            state == .ok
                ? "Other computers can’t sign in to this Mac."
                : "Other computers can sign in to this Mac over the network."
        }
    }

    /// `nil` when there's no System Settings pane that fixes it.
    var fix: MacSettingsSummary.Fix? {
        guard state == .needsFixing || state == .check else { return nil }
        let fix = MacSettingsSummary.fix(for: check)
        return fix.url == nil ? nil : fix
    }

    static func settings(from results: [SystemCheckResult]) -> [SimpleMacSetting] {
        results
            .map { result in
                let state: State
                switch result.status {
                case .pass:    state = .ok
                case .fail:    state = .needsFixing
                case .warning: state = .check
                case .unknown: state = .unknown
                }
                return SimpleMacSetting(check: result.check, state: state)
            }
            .sorted { lhs, rhs in
                if (lhs.state == .ok) != (rhs.state == .ok) { return rhs.state == .ok }
                return MacSettingsSummary.priority(lhs.check) < MacSettingsSummary.priority(rhs.check)
            }
    }
}
