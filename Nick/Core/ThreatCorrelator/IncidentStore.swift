// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation

enum IncidentState: String, Codable, Sendable {
    case new
    case reviewed
    case resolved
    case allowed
}

enum IncidentActionKind: String, Codable, Sendable {
    case detected
    case reviewed
    case hidden
    case dismissed
    case resolved
    case allowedOnce
    case alwaysAllowed
}

struct IncidentActionRecord: Codable, Sendable, Equatable {
    let action: IncidentActionKind
    let actor: EvidenceVerdictActor
    let timestamp: Date
}

/// Persisted security incident. Evidence and its L0 classification live beside
/// the alert so lifecycle decisions survive process restarts without rebuilding
/// meaning from display strings.
struct SecurityIncident: Identifiable, Codable, Sendable, Equatable {
    static let currentSchemaVersion = 1

    let schemaVersion: Int
    let id: UUID
    let key: String
    var alert: ThreatAlert
    var evidence: [Evidence]
    var state: IncidentState
    var actions: [IncidentActionRecord]
    var isVisible: Bool
    var permanentlyDismissed: Bool

    init(
        id: UUID = UUID(),
        key: String,
        alert: ThreatAlert,
        evidence: [Evidence],
        state: IncidentState = .new,
        actions: [IncidentActionRecord] = [],
        isVisible: Bool = true,
        permanentlyDismissed: Bool = false
    ) {
        schemaVersion = Self.currentSchemaVersion
        self.id = id
        self.key = key
        self.alert = alert
        self.evidence = evidence
        self.state = state
        self.actions = actions
        self.isVisible = isVisible
        self.permanentlyDismissed = permanentlyDismissed
    }
}

struct IncidentIngestResult {
    let visibleAlerts: [ThreatAlert]
    let newlyActionable: [ThreatAlert]
}

/// The only policy and persistence boundary after deterministic correlation.
/// Trust, suppression, cooldowns and incident deduplication are deliberately
/// evaluated here once, irrespective of which monitor supplied the evidence.
@MainActor
final class IncidentStore {
    static let persistenceKey = "nickSecurityIncidentsV1"

    private let defaults: UserDefaults
    private(set) var incidents: [SecurityIncident]
    private var trustedProcessList: TrustedProcessList
    private var suppressionRules: [SuppressionRule]
    private var expectedCooldowns: [String: TimeInterval]

    init(
        defaults: UserDefaults = .standard,
        trustedProcessList: TrustedProcessList = TrustedProcessList(),
        suppressionRules: [SuppressionRule] = []
    ) {
        self.defaults = defaults
        self.trustedProcessList = trustedProcessList
        self.suppressionRules = suppressionRules
        self.expectedCooldowns = defaults.dictionary(forKey: "nickExpectedAlertCooldowns") as? [String: TimeInterval] ?? [:]
        if let data = defaults.data(forKey: Self.persistenceKey),
           let restored = try? JSONDecoder().decode([SecurityIncident].self, from: data) {
            incidents = restored
        } else if let data = defaults.data(forKey: "nickPersistedAlerts"),
                  let alerts = try? JSONDecoder().decode([ThreatAlert].self, from: data) {
            incidents = alerts.map(Self.migratedIncident)
        } else {
            incidents = []
        }
        persist()
    }

    var visibleAlerts: [ThreatAlert] {
        incidents.filter(\.isVisible).map(\.alert).sorted { $0.score > $1.score }
    }

    func configure(trustedProcessList: TrustedProcessList, suppressionRules: [SuppressionRule]) {
        self.trustedProcessList = trustedProcessList
        self.suppressionRules = suppressionRules
    }

    func ingest(_ candidates: [ThreatAlert]) -> IncidentIngestResult {
        pruneExpiredCooldowns()
        var newlyActionable: [ThreatAlert] = []

        for rawCandidate in candidates {
            let candidate = applyTrustedDowngrade(to: rawCandidate)
            guard !isSuppressed(candidate), !isCoolingDown(candidate) else { continue }
            let key = Self.incidentKey(for: candidate)
            if let index = incidents.firstIndex(where: { $0.key == key }) {
                let prior = incidents[index]
                guard !prior.permanentlyDismissed else { continue }
                let escalated = candidate.severity > prior.alert.severity
                let incomingEvidence = candidate.contributingSignals.map(Evidence.init(signal:))
                let existingIDs = Set(prior.evidence.map(\.id))
                let addsEvidence = incomingEvidence.contains { !existingIDs.contains($0.id) }
                guard addsEvidence || escalated || !prior.isVisible else { continue }
                incidents[index].alert = prior.alert.mergingOccurrence(candidate)
                incidents[index].evidence = incomingEvidence
                incidents[index].state = .new
                incidents[index].isVisible = true
                incidents[index].actions.append(action(.detected, actor: .automatic))
                if !prior.isVisible || escalated {
                    newlyActionable.append(incidents[index].alert)
                }
            } else {
                var incident = SecurityIncident(
                    key: key,
                    alert: candidate,
                    evidence: candidate.contributingSignals.map(Evidence.init(signal:))
                )
                incident.actions.append(action(.detected, actor: .automatic))
                incidents.append(incident)
                if candidate.severity != .info { newlyActionable.append(candidate) }
            }
        }

        persist()
        return IncidentIngestResult(visibleAlerts: visibleAlerts, newlyActionable: newlyActionable)
    }

    func perform(_ kind: IncidentActionKind, alertID: UUID) {
        guard let index = incidents.firstIndex(where: { $0.alert.id == alertID }) else { return }
        incidents[index].actions.append(action(kind, actor: .user))
        switch kind {
        case .reviewed:
            incidents[index].state = .reviewed
        case .hidden:
            incidents[index].state = .reviewed
            incidents[index].isVisible = false
        case .dismissed:
            incidents[index].state = .resolved
            incidents[index].isVisible = false
            incidents[index].permanentlyDismissed = true
        case .resolved:
            incidents[index].state = .resolved
            incidents[index].isVisible = false
        case .allowedOnce:
            incidents[index].state = .allowed
            incidents[index].isVisible = false
            if isEligibleForExpectedCooldown(incidents[index].alert) {
                expectedCooldowns[incidents[index].key] = Date().addingTimeInterval(86_400).timeIntervalSince1970
            }
        case .alwaysAllowed:
            incidents[index].state = .allowed
            incidents[index].isVisible = false
        case .detected:
            incidents[index].state = .new
        }
        persist()
    }

    func clear() {
        incidents.removeAll()
        expectedCooldowns.removeAll()
        defaults.removeObject(forKey: Self.persistenceKey)
        defaults.removeObject(forKey: "nickPersistedAlerts")
        defaults.removeObject(forKey: "nickExpectedAlertCooldowns")
    }

    func removeIncidents(where shouldRemove: (SecurityIncident) -> Bool) {
        incidents.removeAll(where: shouldRemove)
        persist()
    }

    private func persist() {
        let bounded = Array(incidents.sorted { $0.alert.lastSeen > $1.alert.lastSeen }.prefix(100))
        if let data = try? JSONEncoder().encode(bounded) {
            defaults.set(data, forKey: Self.persistenceKey)
        }
        defaults.set(expectedCooldowns, forKey: "nickExpectedAlertCooldowns")
        // Compatibility while the UI and older 4.x builds still know this key.
        if let data = try? JSONEncoder().encode(visibleAlerts) {
            defaults.set(data, forKey: "nickPersistedAlerts")
        }
    }

    private static func migratedIncident(_ alert: ThreatAlert) -> SecurityIncident {
        SecurityIncident(
            key: incidentKey(for: alert),
            alert: alert,
            evidence: alert.contributingSignals.map(Evidence.init(signal:)),
            actions: [action(.detected, actor: .migration)]
        )
    }

    /// Cross-source identity intentionally omits monitor source. Two monitors
    /// describing the same rule and subject update one incident.
    static func incidentKey(for alert: ThreatAlert) -> String {
        let subjects = Set(alert.contributingSignals.map { signal -> String in
            let rule = EvidenceRulePolicy.ruleID(for: signal).lowercased()
            if let hash = signal.fileInfo?.sha256Hash, !hash.isEmpty { return "\(rule)|hash:\(hash.lowercased())" }
            if let file = signal.fileInfo?.path ?? signal.metadata["path"] { return "\(rule)|file:\(normalize(file))" }
            if let process = signal.processInfo {
                let signing = EvidenceSigningIdentity(signal: signal)
                return "\(rule)|process:\(signing.teamID ?? "-"):\(signing.signingIdentifier ?? normalize(process.path))"
            }
            if let network = signal.networkInfo {
                return "\(rule)|network:\(network.remoteAddress ?? "local"):\(network.remotePort.map(String.init) ?? "-")"
            }
            return "\(rule)|subject:\(EvidenceSubjectIdentity(signal: signal).stableIdentifier)"
        }).sorted()
        return ([alert.title.lowercased()] + subjects).joined(separator: "||")
    }

    private func applyTrustedDowngrade(to alert: ThreatAlert) -> ThreatAlert {
        let signals = alert.contributingSignals
        guard !signals.isEmpty, !signals.contains(where: { $0.source == .persistence }) else { return alert }
        let trustedCount = signals.filter { signal in
            guard let process = signal.processInfo else { return false }
            return trustedProcessList.isTrusted(process)
        }.count
        let fraction = Double(trustedCount) / Double(signals.count)
        if fraction == 1 { return alert.with(severity: .info) }
        if fraction > 0 { return alert.with(severity: alert.severity.downgraded) }
        return alert
    }

    private func isSuppressed(_ alert: ThreatAlert) -> Bool {
        let nonSuppressibleReasons: Set<String> = [
            "reverse_shell", "reverse_shell_port", "netcat_connection",
            "temp_binary_network", "raw_ip_outbound", "ssh_key_added",
            "shell_profile_modified",
        ]
        if alert.severity == .critical || alert.contributingSignals.contains(where: {
            $0.source == .persistence || $0.source == .yara || $0.source == .systemAudit ||
                nonSuppressibleReasons.contains($0.metadata["reason"] ?? "")
        }) { return false }

        let context = SuppressionRule.contextFingerprint(for: alert)
        for rule in suppressionRules where rule.isActive {
            if let learnedContext = rule.behaviorContext, learnedContext != context { continue }
            let needle = rule.value.lowercased()
            guard !needle.isEmpty else { continue }
            switch rule.type {
            case .ruleName:
                if alert.title.lowercased().contains(needle) { return true }
            case .processName:
                if alert.contributingSignals.compactMap(\.processInfo?.name).contains(where: { $0.lowercased().contains(needle) }) { return true }
            case .signedProcess:
                let identities = alert.contributingSignals.compactMap { signal -> String? in
                    let identity = EvidenceSigningIdentity(signal: signal)
                    guard let team = identity.teamID, let signing = identity.signingIdentifier else { return nil }
                    return "\(team.lowercased())|\(signing.lowercased())"
                }
                if identities.contains(needle) { return true }
            case .path:
                let paths = alert.contributingSignals.compactMap { $0.fileInfo?.path ?? $0.metadata["path"] }
                if paths.contains(where: { normalize($0).hasPrefix(normalize(needle)) }) { return true }
            }
        }
        return false
    }

    private func isCoolingDown(_ alert: ThreatAlert) -> Bool {
        guard isEligibleForExpectedCooldown(alert) else { return false }
        return (expectedCooldowns[Self.incidentKey(for: alert)] ?? 0) > Date().timeIntervalSince1970
    }

    private func isEligibleForExpectedCooldown(_ alert: ThreatAlert) -> Bool {
        guard alert.severity < .critical,
              !alert.contributingSignals.contains(where: { $0.source == .yara }) else { return false }
        let reviewable: Set<String> = ["shell_profile_modified", "ssh_keys_modified"]
        return alert.contributingSignals.filter { $0.source == .persistence }.allSatisfy {
            reviewable.contains($0.metadata["reason"] ?? "")
        }
    }

    private func pruneExpiredCooldowns() {
        let now = Date().timeIntervalSince1970
        expectedCooldowns = expectedCooldowns.filter { $0.value > now }
    }

    private static func action(_ kind: IncidentActionKind, actor: EvidenceVerdictActor) -> IncidentActionRecord {
        IncidentActionRecord(action: kind, actor: actor, timestamp: Date())
    }

    private func action(_ kind: IncidentActionKind, actor: EvidenceVerdictActor) -> IncidentActionRecord {
        Self.action(kind, actor: actor)
    }

    private static func normalize(_ path: String) -> String {
        URL(fileURLWithPath: path).standardizedFileURL.path.lowercased()
    }

    private func normalize(_ path: String) -> String { Self.normalize(path) }
}
