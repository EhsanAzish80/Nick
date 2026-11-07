// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation

/// The single lifecycle/status vocabulary rendered for a persisted incident.
/// Evidence availability only controls actions; it never rewrites status.
enum IncidentDisplayStatus: String, Equatable, Sendable {
    case needsReview = "Needs review"
    case blocked = "Blocked"
    case quarantined = "Quarantined"
    case remediationNeeded = "Remediation needed"
    case resolved = "Resolved"
    case observed = "Observed"

    var contributesToProtectionStatus: Bool {
        switch self {
        case .needsReview, .blocked, .quarantined, .remediationNeeded: true
        case .resolved, .observed: false
        }
    }

    init(alert: ThreatAlert, incident: SecurityIncident? = nil) {
        if incident?.actions.contains(where: { $0.action == .quarantineFailed }) == true
            || alert.contributingSignals.contains(where: {
                $0.metadata["remediationStatus"] == "quarantine-failed"
            }) {
            self = .remediationNeeded
        } else if incident?.actions.contains(where: { $0.action == .quarantined }) == true {
            self = .quarantined
        } else if alert.isBlockedTamperEvidence || alert.contributingSignals.contains(where: {
            $0.metadata["detectionKind"] == "credential-access"
                && $0.metadata["endpointDecision"] == "deny"
        }) {
            self = .blocked
        } else if let incident,
                  incident.state != .new || !incident.isVisible {
            // Automatic evidence cleanup (for example, a command ending) is
            // not a review decision. Keep protected findings actionable until
            // the user reviews, resolves, allows, dismisses, or quarantines.
            let hasUserDecision = incident.state == .reviewed
                || incident.actions.contains {
                    $0.actor == .user && [
                        IncidentActionKind.reviewed, .hidden, .dismissed, .resolved,
                        .allowedOnce, .alwaysAllowed, .quarantined
                    ].contains($0.action)
                }
            if alert.hasProtectedEvidence && !hasUserDecision {
                self = .needsReview
            } else {
                self = .resolved
            }
        } else if alert.severity == .info {
            self = .observed
        } else if alert.hasProtectedEvidence || alert.isActionableUserFinding {
            self = .needsReview
        } else {
            self = .observed
        }
    }
}

extension SecurityIncident {
    /// The canonical user-visible lifecycle for this incident. All surfaces
    /// consume this value instead of reinterpreting severity or evidence state.
    /// Acknowledgment clears attention, never the recorded enforcement outcome.
    var requiresAttention: Bool {
        if displayStatus == .remediationNeeded { return true }
        return displayStatus.contributesToProtectionStatus && state != .reviewed
    }

    var displayStatus: IncidentDisplayStatus {
        IncidentDisplayStatus(alert: alert, incident: self)
    }
}

/// Presentation-only attribution and lifecycle for behavior incidents.
/// Responsible-app metadata never participates in detection, trust, tier,
/// severity, suppression, or correlation policy.
struct BehaviorIncidentPresentation: Equatable, Sendable {
    let isBehavior: Bool
    let status: IncidentDisplayStatus
    let responsibleLine: String
    let responsibleAppName: String
    let bundleID: String?
    let teamID: String?
    let signing: String
    let appPath: String?
    let chain: String
    let actor: String
    let actorSigning: String
    let matchedCommand: String?

    init(alert: ThreatAlert, incident: SecurityIncident? = nil) {
        let signal = alert.contributingSignals.first { signal in
            signal.metadata["class"] == "behavior"
                || signal.metadata["detectionKind"]?.hasSuffix("-behavior") == true
                || signal.metadata["responsibleAppName"] != nil
        } ?? alert.contributingSignals.first
        let metadata = signal?.metadata ?? [:]
        isBehavior = signal.map {
            $0.metadata["class"] == "behavior"
                || $0.metadata["detectionKind"]?.hasSuffix("-behavior") == true
        } ?? false
        let rawChain = metadata["responsibleChain"].flatMap(Self.nonEmpty)
            ?? metadata["chain"].flatMap(Self.nonEmpty)
        let rawChainParts = rawChain?.components(separatedBy: " → ").compactMap(Self.namedComponent) ?? []
        let serviceRole: String?
        if metadata["responsibleAppName"].flatMap(Self.namedComponent) == nil,
           let process = signal?.processInfo,
           case .signed(let team, let identifier) = process.signingStatus,
           team == "APPLE_PLATFORM" {
            serviceRole = AppleSyncRenamePolicy.displayRole(signingID: identifier)
        } else { serviceRole = nil }
        responsibleAppName = serviceRole ?? metadata["responsibleAppName"].flatMap(Self.namedComponent)
            ?? signal?.processInfo?.parentName.flatMap(Self.namedComponent)
            ?? rawChainParts.dropLast().last
            ?? "Unknown app"
        bundleID = metadata["responsibleAppBundleID"].flatMap(Self.nonEmpty)
        teamID = metadata["responsibleAppTeamID"].flatMap(Self.nonEmpty)
        signing = serviceRole != nil ? "Apple platform" : (metadata["responsibleAppSigning"].flatMap(Self.nonEmpty) ?? "Unknown")
        appPath = metadata["responsibleAppPath"].flatMap(Self.nonEmpty)
        chain = serviceRole ?? rawChain ?? "Unknown app"
        let chainParts = chain.components(separatedBy: " → ").filter { !$0.isEmpty }
        responsibleLine = chainParts.count > 1
            ? "\(responsibleAppName) ran this · via \(chainParts.dropFirst().joined(separator: " → "))"
            : "\(responsibleAppName) ran this"
        if let process = signal?.processInfo {
            actor = Self.nonEmpty(process.name)
                ?? Self.nonEmpty(process.path).map { URL(fileURLWithPath: $0).lastPathComponent }
                ?? "unknown process"
        } else {
            actor = "unknown process"
        }
        actorSigning = signal?.processInfo?.signingStatus.behaviorDisplayName ?? "Unknown"
        matchedCommand = metadata["matchedCommand"].flatMap(Self.nonEmpty)

        status = incident?.displayStatus ?? IncidentDisplayStatus(alert: alert)
    }

    private static func nonEmpty(_ value: String) -> String? { value.isEmpty ? nil : value }

    private static func namedComponent(_ value: String) -> String? {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, !["unknown", "unknown app", "?"].contains(trimmed.lowercased()) else {
            return nil
        }
        return trimmed
    }
}

private extension SigningStatus {
    var behaviorDisplayName: String {
        switch self {
        case .signed(let teamID, _): return teamID == "APPLE_PLATFORM" ? "Apple platform" : "Signed · \(teamID)"
        case .adHoc: return "Ad-hoc signed"
        case .unsigned: return "Unsigned"
        case .invalid: return "Invalid signature"
        case .unknown, .pending: return "Unknown"
        }
    }
}
