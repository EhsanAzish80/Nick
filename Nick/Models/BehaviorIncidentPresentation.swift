// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation

/// Presentation-only attribution and lifecycle for behavior incidents.
/// Responsible-app metadata never participates in detection, trust, tier,
/// severity, suppression, or correlation policy.
struct BehaviorIncidentPresentation: Equatable, Sendable {
    enum Status: String, Equatable, Sendable {
        case needsReview = "Needs review"
        case blocked = "Blocked"
        case remediationNeeded = "Remediation needed"
        case observed = "Observed"
    }

    let isBehavior: Bool
    let status: Status
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

    init(alert: ThreatAlert) {
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
        responsibleAppName = metadata["responsibleAppName"].flatMap(Self.nonEmpty) ?? "Unknown app"
        bundleID = metadata["responsibleAppBundleID"].flatMap(Self.nonEmpty)
        teamID = metadata["responsibleAppTeamID"].flatMap(Self.nonEmpty)
        signing = metadata["responsibleAppSigning"].flatMap(Self.nonEmpty) ?? "Unknown"
        appPath = metadata["responsibleAppPath"].flatMap(Self.nonEmpty)
        chain = metadata["responsibleChain"].flatMap(Self.nonEmpty) ?? "Unknown app"
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

        let remediationFailed = alert.contributingSignals.contains {
            $0.metadata["remediationStatus"] == "quarantine-failed"
        }
        if remediationFailed {
            status = .remediationNeeded
        } else if alert.isBlockedTamperEvidence {
            status = .blocked
        } else if isBehavior && alert.hasProtectedEvidence {
            status = .needsReview
        } else {
            status = .observed
        }
    }

    private static func nonEmpty(_ value: String) -> String? { value.isEmpty ? nil : value }
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
