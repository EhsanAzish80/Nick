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
    private(set) var firstTimestamp: Date
    private(set) var lastTimestamp: Date
    private(set) var count: Int

    /// Compatibility accessor for callers that previously read the single
    /// action timestamp. It now represents the most recent occurrence.
    var timestamp: Date { lastTimestamp }

    init(action: IncidentActionKind, actor: EvidenceVerdictActor, timestamp: Date) {
        self.action = action
        self.actor = actor
        self.firstTimestamp = timestamp
        self.lastTimestamp = timestamp
        self.count = 1
    }

    mutating func recordOccurrence(at timestamp: Date) {
        firstTimestamp = min(firstTimestamp, timestamp)
        lastTimestamp = max(lastTimestamp, timestamp)
        count += 1
    }

    private enum CodingKeys: String, CodingKey {
        case action, actor, timestamp, firstTimestamp, lastTimestamp, count
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        action = try container.decode(IncidentActionKind.self, forKey: .action)
        actor = try container.decode(EvidenceVerdictActor.self, forKey: .actor)
        let legacyTimestamp = try container.decodeIfPresent(Date.self, forKey: .timestamp)
        firstTimestamp = try container.decodeIfPresent(Date.self, forKey: .firstTimestamp)
            ?? legacyTimestamp ?? .distantPast
        lastTimestamp = try container.decodeIfPresent(Date.self, forKey: .lastTimestamp)
            ?? legacyTimestamp ?? firstTimestamp
        count = max(1, try container.decodeIfPresent(Int.self, forKey: .count) ?? 1)
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(action, forKey: .action)
        try container.encode(actor, forKey: .actor)
        try container.encode(firstTimestamp, forKey: .firstTimestamp)
        try container.encode(lastTimestamp, forKey: .lastTimestamp)
        try container.encode(count, forKey: .count)
    }
}

struct IncidentDismissalTombstone: Codable, Sendable, Equatable {
    let incidentKey: String
    let alertDeduplicationKey: String
    let dismissedAt: Date
}

struct LearnedReviewEntry: Codable, Sendable, Equatable, Identifiable {
    let id: UUID
    let teamID: String
    let signingIdentifier: String
    let ruleID: String
    let contextKey: String
    let reason: String
    let createdAt: Date
    var lastConfirmedAt: Date
    var expiresAt: Date
    var confirmedIncidentIDs: Set<UUID>

    var identityKey: String { "\(teamID.lowercased())|\(signingIdentifier.lowercased())" }
    var confirmationCount: Int { confirmedIncidentIDs.count }

    init(
        id: UUID,
        teamID: String,
        signingIdentifier: String,
        ruleID: String,
        contextKey: String,
        reason: String,
        createdAt: Date,
        lastConfirmedAt: Date,
        expiresAt: Date,
        confirmedIncidentIDs: Set<UUID>
    ) {
        self.id = id
        self.teamID = teamID
        self.signingIdentifier = signingIdentifier
        self.ruleID = ruleID
        self.contextKey = contextKey
        self.reason = reason
        self.createdAt = createdAt
        self.lastConfirmedAt = lastConfirmedAt
        self.expiresAt = expiresAt
        self.confirmedIncidentIDs = confirmedIncidentIDs
    }

    private enum CodingKeys: String, CodingKey {
        case id, teamID, signingIdentifier, ruleID, contextKey, reason
        case createdAt, lastConfirmedAt, expiresAt, confirmedIncidentIDs, confirmationCount
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decode(UUID.self, forKey: .id)
        teamID = try container.decode(String.self, forKey: .teamID)
        signingIdentifier = try container.decode(String.self, forKey: .signingIdentifier)
        ruleID = try container.decode(String.self, forKey: .ruleID)
        contextKey = try container.decode(String.self, forKey: .contextKey)
        reason = try container.decode(String.self, forKey: .reason)
        createdAt = try container.decode(Date.self, forKey: .createdAt)
        lastConfirmedAt = try container.decode(Date.self, forKey: .lastConfirmedAt)
        expiresAt = try container.decode(Date.self, forKey: .expiresAt)
        confirmedIncidentIDs = try container.decodeIfPresent(Set<UUID>.self, forKey: .confirmedIncidentIDs) ?? []
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(id, forKey: .id)
        try container.encode(teamID, forKey: .teamID)
        try container.encode(signingIdentifier, forKey: .signingIdentifier)
        try container.encode(ruleID, forKey: .ruleID)
        try container.encode(contextKey, forKey: .contextKey)
        try container.encode(reason, forKey: .reason)
        try container.encode(createdAt, forKey: .createdAt)
        try container.encode(lastConfirmedAt, forKey: .lastConfirmedAt)
        try container.encode(expiresAt, forKey: .expiresAt)
        try container.encode(
            confirmedIncidentIDs.sorted { $0.uuidString < $1.uuidString },
            forKey: .confirmedIncidentIDs
        )
        try container.encode(confirmationCount, forKey: .confirmationCount)
    }
}

struct IncidentStoreSnapshot: Codable, Sendable, Equatable {
    static let currentSchemaVersion = 1

    let schemaVersion: Int
    var incidents: [SecurityIncident]
    var dismissalTombstones: [IncidentDismissalTombstone]
    var expectedCooldowns: [String: TimeInterval]
    var evictedIncidentCount: Int
    var learnedReviewEntries: [LearnedReviewEntry]

    init(
        schemaVersion: Int = Self.currentSchemaVersion,
        incidents: [SecurityIncident],
        dismissalTombstones: [IncidentDismissalTombstone],
        expectedCooldowns: [String: TimeInterval],
        evictedIncidentCount: Int = 0,
        learnedReviewEntries: [LearnedReviewEntry] = []
    ) {
        self.schemaVersion = schemaVersion
        self.incidents = incidents
        self.dismissalTombstones = dismissalTombstones
        self.expectedCooldowns = expectedCooldowns
        self.evictedIncidentCount = max(0, evictedIncidentCount)
        self.learnedReviewEntries = learnedReviewEntries
    }

    private enum CodingKeys: String, CodingKey {
        case schemaVersion, incidents, dismissalTombstones, expectedCooldowns, evictedIncidentCount
        case learnedReviewEntries
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        schemaVersion = try container.decode(Int.self, forKey: .schemaVersion)
        incidents = try container.decode([SecurityIncident].self, forKey: .incidents)
        dismissalTombstones = try container.decode([IncidentDismissalTombstone].self, forKey: .dismissalTombstones)
        expectedCooldowns = try container.decode([String: TimeInterval].self, forKey: .expectedCooldowns)
        evictedIncidentCount = max(0, try container.decodeIfPresent(Int.self, forKey: .evictedIncidentCount) ?? 0)
        learnedReviewEntries = try container.decodeIfPresent([LearnedReviewEntry].self, forKey: .learnedReviewEntries) ?? []
    }
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
    static let dismissalPersistenceKey = "nickDismissedIncidentKeysV1"
    static let maximumPersistedIncidents = 100
    static let maximumDismissalTombstones = 500
    static let maximumIncidentsPerRule = 20
    static let maximumLearnedEntriesPerIdentity = 20
    static let learnedEntryLifetime: TimeInterval = 30 * 86_400

    private let legacyTestDefaults: UserDefaults?
    private(set) var incidents: [SecurityIncident]
    private var trustedProcessList: TrustedProcessList
    private var suppressionRules: [SuppressionRule]
    private var expectedCooldowns: [String: TimeInterval]
    private var dismissalTombstones: [IncidentDismissalTombstone]
    private(set) var evictedIncidentCount = 0
    private(set) var learnedReviewEntries: [LearnedReviewEntry] = []
    private var verdictLearningEnabled = false
    private let now: () -> Date
    private let identityValidator: (String, String, String) -> Bool
    private var privilegedPersistence: ((Data) -> Void)?
    private var lastPrivilegedPayload: Data?

    init(
        defaults: UserDefaults? = nil,
        trustedProcessList: TrustedProcessList = TrustedProcessList(),
        suppressionRules: [SuppressionRule] = [],
        persistOnInit: Bool = true,
        now: @escaping () -> Date = Date.init,
        identityValidator: @escaping (String, String, String) -> Bool = {
            SignatureValidator.shared.validatesDeveloperIdentity(
                binaryPath: $0,
                teamID: $1,
                signingIdentifier: $2
            )
        }
    ) {
        self.legacyTestDefaults = defaults
        self.trustedProcessList = trustedProcessList
        self.suppressionRules = suppressionRules
        self.now = now
        self.identityValidator = identityValidator
        self.expectedCooldowns = defaults?.dictionary(forKey: "nickExpectedAlertCooldowns") as? [String: TimeInterval] ?? [:]
        self.dismissalTombstones = defaults?.data(forKey: Self.dismissalPersistenceKey)
            .flatMap { try? JSONDecoder().decode([IncidentDismissalTombstone].self, from: $0) } ?? []
        if let data = defaults?.data(forKey: Self.persistenceKey),
           let restored = try? JSONDecoder().decode([SecurityIncident].self, from: data) {
            incidents = restored
        } else if let data = defaults?.data(forKey: "nickPersistedAlerts"),
                  let alerts = try? JSONDecoder().decode([ThreatAlert].self, from: data) {
            incidents = alerts.map(Self.migratedIncident)
        } else {
            incidents = []
        }
        migrateLegacyDismissals()
        migrateLegacyDismissedAlertKeys(from: defaults)
        boundInMemory()
        if persistOnInit { persist() }
    }

    var visibleAlerts: [ThreatAlert] {
        incidents.filter(\.isVisible).map(\.alert).sorted { $0.score > $1.score }
    }

    var dismissedAlertDeduplicationKeys: Set<String> {
        Set(dismissalTombstones.map(\.alertDeduplicationKey))
    }

    var legacyDismissalTombstones: [IncidentDismissalTombstone] {
        dismissalTombstones
            .filter { Self.isLegacyTombstone($0) }
            .sorted { $0.dismissedAt > $1.dismissedAt }
    }

    func installPrivilegedSnapshot(
        _ payload: Data,
        persistence: @escaping (Data) -> Void
    ) throws {
        let snapshot = try Self.decodeSnapshot(payload)
        incidents = snapshot.incidents
        dismissalTombstones = snapshot.dismissalTombstones
        expectedCooldowns = snapshot.expectedCooldowns
        evictedIncidentCount = snapshot.evictedIncidentCount
        learnedReviewEntries = snapshot.learnedReviewEntries
        migrateLegacyDismissals()
        boundInMemory()
        privilegedPersistence = persistence
        lastPrivilegedPayload = try encodedSnapshot()
    }

    func prepareLegacyMigration(defaults: UserDefaults = .standard) throws -> Data {
        let legacy = IncidentStore(
            defaults: defaults,
            trustedProcessList: trustedProcessList,
            suppressionRules: suppressionRules,
            persistOnInit: false,
            now: now,
            identityValidator: identityValidator
        )
        return try legacy.encodedSnapshot()
    }

    func removeLegacyPersistence(defaults: UserDefaults = .standard) {
        defaults.removeObject(forKey: Self.persistenceKey)
        defaults.removeObject(forKey: Self.dismissalPersistenceKey)
        defaults.removeObject(forKey: "nickPersistedAlerts")
        defaults.removeObject(forKey: "nickDismissedAlertKeys")
        defaults.removeObject(forKey: "nickExpectedAlertCooldowns")
    }

    func configure(
        trustedProcessList: TrustedProcessList,
        suppressionRules: [SuppressionRule],
        verdictLearningEnabled: Bool = false
    ) {
        self.trustedProcessList = trustedProcessList
        self.suppressionRules = suppressionRules
        self.verdictLearningEnabled = verdictLearningEnabled
    }

    func ingest(_ candidates: [ThreatAlert]) -> IncidentIngestResult {
        pruneExpiredCooldowns()
        pruneExpiredLearnedEntries()
        var newlyActionable: [ThreatAlert] = []

        for rawCandidate in candidates {
            let candidate = applyLearnedPriority(to: applyTrustedDowngrade(to: rawCandidate))
            guard !isSuppressed(candidate), !isCoolingDown(candidate) else { continue }
            let key = Self.incidentKey(for: candidate)
            guard !isDismissed(candidate, incidentKey: key) else { continue }
            if let index = incidents.firstIndex(where: { $0.key == key }) {
                let prior = incidents[index]
                let escalated = candidate.severity > prior.alert.severity
                let incomingEvidence = candidate.contributingSignals.map(Evidence.init(signal:))
                incidents[index].alert = prior.alert.mergingOccurrence(candidate)
                incidents[index].evidence = incomingEvidence
                if escalated {
                    incidents[index].state = .new
                    incidents[index].isVisible = true
                    recordAction(.detected, actor: .automatic, at: index)
                    newlyActionable.append(incidents[index].alert)
                }
            } else {
                var incident = SecurityIncident(
                    key: key,
                    alert: candidate,
                    evidence: candidate.contributingSignals.map(Evidence.init(signal:))
                )
                incident.actions.append(Self.action(.detected, actor: .automatic))
                incidents.append(incident)
                if candidate.severity != .info || Self.requiresVisibleNotification(candidate) {
                    newlyActionable.append(candidate)
                }
            }
        }

        persist()
        return IncidentIngestResult(visibleAlerts: visibleAlerts, newlyActionable: newlyActionable)
    }

    func performAuthenticatedUserAction(_ kind: IncidentActionKind, alertID: UUID) {
        guard let index = incidents.firstIndex(where: { $0.alert.id == alertID }) else { return }
        if verdictLearningEnabled, [.dismissed, .alwaysAllowed].contains(kind) {
            recordLearning(from: incidents[index], action: kind)
        }
        recordAction(kind, actor: .user, at: index)
        switch kind {
        case .reviewed:
            incidents[index].state = .reviewed
        case .hidden:
            incidents[index].state = .reviewed
            incidents[index].isVisible = false
        case .dismissed:
            recordDismissal(for: incidents[index])
            incidents.remove(at: index)
            persist()
            return
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
        dismissalTombstones.removeAll()
        expectedCooldowns.removeAll()
        evictedIncidentCount = 0
        learnedReviewEntries.removeAll()
        legacyTestDefaults?.removeObject(forKey: Self.persistenceKey)
        legacyTestDefaults?.removeObject(forKey: Self.dismissalPersistenceKey)
        legacyTestDefaults?.removeObject(forKey: "nickPersistedAlerts")
        legacyTestDefaults?.removeObject(forKey: "nickExpectedAlertCooldowns")
        persist()
    }

    func removeIncidents(where shouldRemove: (SecurityIncident) -> Bool) {
        incidents.removeAll(where: shouldRemove)
        persist()
    }

    func resetLearnedEntry(id: UUID) {
        learnedReviewEntries.removeAll { $0.id == id }
        persist()
    }

    func resetAllLearnedEntries() {
        learnedReviewEntries.removeAll()
        persist()
    }

    func resetLegacyDismissal(incidentKey: String) {
        dismissalTombstones.removeAll {
            Self.isLegacyTombstone($0) && $0.incidentKey == incidentKey
        }
        persist()
    }

    func exportLearnedEntries() throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        return try encoder.encode(learnedReviewEntries.sorted { $0.lastConfirmedAt > $1.lastConfirmedAt })
    }

    private func persist() {
        boundInMemory()
        if let defaults = legacyTestDefaults {
            if let data = try? JSONEncoder().encode(incidents) {
                defaults.set(data, forKey: Self.persistenceKey)
            }
            if let data = try? JSONEncoder().encode(dismissalTombstones) {
                defaults.set(data, forKey: Self.dismissalPersistenceKey)
            }
            defaults.set(expectedCooldowns, forKey: "nickExpectedAlertCooldowns")
            if let data = try? JSONEncoder().encode(visibleAlerts) {
                defaults.set(data, forKey: "nickPersistedAlerts")
            }
        }
        guard let privilegedPersistence,
              let payload = try? encodedSnapshot(),
              payload != lastPrivilegedPayload else { return }
        lastPrivilegedPayload = payload
        privilegedPersistence(payload)
    }

    private func encodedSnapshot() throws -> Data {
        let snapshot = IncidentStoreSnapshot(
            incidents: incidents,
            dismissalTombstones: dismissalTombstones,
            expectedCooldowns: expectedCooldowns,
            evictedIncidentCount: evictedIncidentCount,
            learnedReviewEntries: learnedReviewEntries
        )
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        return try encoder.encode(snapshot)
    }

    private static func decodeSnapshot(_ payload: Data) throws -> IncidentStoreSnapshot {
        let snapshot = try JSONDecoder().decode(IncidentStoreSnapshot.self, from: payload)
        guard snapshot.schemaVersion == IncidentStoreSnapshot.currentSchemaVersion else {
            throw DecodingError.dataCorrupted(.init(
                codingPath: [],
                debugDescription: "Unsupported incident-store schema"
            ))
        }
        return snapshot
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
            if let process = signal.processInfo {
                let signing = EvidenceSigningIdentity(signal: signal)
                let actor = signing.teamID.flatMap { team in
                    signing.signingIdentifier.map { "signed:\(team.lowercased()):\($0.lowercased())" }
                } ?? "path:\(normalize(process.path))"
                return "\(rule)|actor:\(actor)"
            }
            if let file = signal.fileInfo?.path ?? signal.metadata["path"] { return "\(rule)|file:\(normalize(file))" }
            if let network = signal.networkInfo {
                return "\(rule)|network:\(network.remoteAddress ?? "local"):\(network.remotePort.map(String.init) ?? "-")"
            }
            return "\(rule)|subject:\(EvidenceSubjectIdentity(signal: signal).stableIdentifier)"
        }).sorted()
        return ([alert.title.lowercased()] + subjects).joined(separator: "||")
    }

    static func requiresVisibleNotification(_ alert: ThreatAlert) -> Bool {
        alert.contributingSignals.contains {
            $0.metadata["rule"] == "nick_documented_uninstall"
        }
    }

    private func applyTrustedDowngrade(to alert: ThreatAlert) -> ThreatAlert {
        let signals = alert.contributingSignals
        guard !signals.isEmpty, !isProtected(alert) else { return alert }
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
        guard !isProtected(alert) else { return false }

        let context = SuppressionRule.contextFingerprint(for: alert)
        for rule in suppressionRules where rule.isActive {
            if let learnedContext = rule.behaviorContext, learnedContext != context { continue }
            let needle = rule.value.lowercased()
            guard !needle.isEmpty else { continue }
            switch rule.type {
            case .ruleName:
                let ruleIDs = alert.contributingSignals.map { EvidenceRulePolicy.ruleID(for: $0).lowercased() }
                if ruleIDs.contains(needle) || alert.title.lowercased() == needle { return true }
            case .processName:
                let processes = alert.contributingSignals.compactMap(\.processInfo)
                // Identity-bearing processes must use a signedProcess rule; a
                // mutable display name must never override their identity.
                if processes.contains(where: { process in
                    let hasIdentity: Bool
                    if case .signed(let teamID, let signingID) = process.signingStatus {
                        hasIdentity = !teamID.isEmpty && !(signingID ?? "").isEmpty
                    } else {
                        hasIdentity = false
                    }
                    return !hasIdentity && process.name.lowercased() == needle
                }) { return true }
            case .signedProcess:
                let identities = alert.contributingSignals.compactMap { signal -> String? in
                    let identity = EvidenceSigningIdentity(signal: signal)
                    guard let team = identity.teamID, let signing = identity.signingIdentifier else { return nil }
                    return "\(team.lowercased())|\(signing.lowercased())"
                }
                if identities.contains(needle) { return true }
            case .path:
                let paths = alert.contributingSignals.compactMap { $0.fileInfo?.path ?? $0.metadata["path"] }
                let root = normalize(needle).trimmingCharacters(in: CharacterSet(charactersIn: "/"))
                if paths.contains(where: {
                    let candidate = normalize($0).trimmingCharacters(in: CharacterSet(charactersIn: "/"))
                    return candidate == root || candidate.hasPrefix(root + "/")
                }) { return true }
            }
        }
        return false
    }

    private func isCoolingDown(_ alert: ThreatAlert) -> Bool {
        guard !isProtected(alert) else { return false }
        guard isEligibleForExpectedCooldown(alert) else { return false }
        return (expectedCooldowns[Self.incidentKey(for: alert)] ?? 0) > Date().timeIntervalSince1970
    }

    private func isEligibleForExpectedCooldown(_ alert: ThreatAlert) -> Bool {
        guard !isProtected(alert), alert.severity < .critical else { return false }
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

    private func recordAction(_ kind: IncidentActionKind, actor: EvidenceVerdictActor, at index: Int) {
        let now = Date()
        if let existing = incidents[index].actions.firstIndex(where: { $0.action == kind && $0.actor == actor }) {
            incidents[index].actions[existing].recordOccurrence(at: now)
        } else {
            incidents[index].actions.append(
                IncidentActionRecord(action: kind, actor: actor, timestamp: now)
            )
        }
    }

    private func isProtected(_ alert: ThreatAlert) -> Bool {
        alert.hasProtectedEvidence
    }

    private func isDismissed(_ alert: ThreatAlert, incidentKey: String) -> Bool {
        dismissalTombstones.contains { tombstone in
            if Self.isLegacyTombstone(tombstone) {
                return !isProtected(alert)
                    && tombstone.alertDeduplicationKey == alert.deduplicationKey
            }
            return tombstone.incidentKey == incidentKey
        }
    }

    private static func isLegacyTombstone(_ tombstone: IncidentDismissalTombstone) -> Bool {
        tombstone.incidentKey.hasPrefix("legacy-alert-dedup:")
    }

    private func applyLearnedPriority(to alert: ThreatAlert) -> ThreatAlert {
        guard verdictLearningEnabled, !isProtected(alert),
              let key = learningKey(for: alert),
              learnedReviewEntries.contains(where: {
                  $0.expiresAt > now()
                      && $0.identityKey == key.identityKey
                      && $0.ruleID == key.ruleID
                      && $0.contextKey == key.contextKey
                      && $0.confirmationCount >= 2
              }) else { return alert }
        return alert.with(severity: .info)
    }

    private func recordLearning(from incident: SecurityIncident, action: IncidentActionKind) {
        guard let key = learningKey(for: incident.alert) else { return }
        let timestamp = now()
        if let index = learnedReviewEntries.firstIndex(where: {
            $0.identityKey == key.identityKey && $0.ruleID == key.ruleID && $0.contextKey == key.contextKey
        }) {
            let inserted = learnedReviewEntries[index].confirmedIncidentIDs.insert(incident.id).inserted
            guard inserted else { return }
            learnedReviewEntries[index].lastConfirmedAt = timestamp
            learnedReviewEntries[index].expiresAt = timestamp.addingTimeInterval(Self.learnedEntryLifetime)
        } else {
            learnedReviewEntries.append(LearnedReviewEntry(
                id: UUID(),
                teamID: key.teamID,
                signingIdentifier: key.signingIdentifier,
                ruleID: key.ruleID,
                contextKey: key.contextKey,
                reason: "User marked a matching review finding as \(action.rawValue).",
                createdAt: timestamp,
                lastConfirmedAt: timestamp,
                expiresAt: timestamp.addingTimeInterval(Self.learnedEntryLifetime),
                confirmedIncidentIDs: [incident.id]
            ))
        }
        enforceLearnedEntryCap(for: key.identityKey)
    }

    private func learningKey(for alert: ThreatAlert) -> (
        teamID: String, signingIdentifier: String, identityKey: String, ruleID: String, contextKey: String
    )? {
        let evidence = alert.contributingSignals.map(Evidence.init(signal:))
        guard !evidence.isEmpty,
              evidence.allSatisfy({ $0.ruleTier == .review }),
              let first = evidence.first,
              let identity = first.signingIdentity,
              identity.kind == .signed,
              let teamID = identity.teamID, !teamID.isEmpty,
              let signingIdentifier = identity.signingIdentifier, !signingIdentifier.isEmpty,
              let process = first.processInfo,
              TrustedProcessList.trustRejectionReason(for: process) == nil,
              evidence.allSatisfy({ item in
                  item.signingIdentity?.kind == .signed
                      && item.signingIdentity?.teamID == teamID
                      && item.signingIdentity?.signingIdentifier == signingIdentifier
                      && item.ruleID == first.ruleID
                      && item.ruleTier == .review
                      && item.processInfo.map {
                          identityValidator($0.path, teamID, signingIdentifier)
                      } == true
              }),
              let ruleID = first.ruleID else { return nil }
        let parents = (first.parentChain ?? []).prefix(8).map { ancestor in
            if let team = ancestor.teamID, let signing = ancestor.signingIdentifier {
                return "signed:\(team.lowercased())|\(signing.lowercased())"
            }
            if let path = ancestor.executablePath {
                return "name:\(URL(fileURLWithPath: path).lastPathComponent.lowercased())"
            }
            return "unknown"
        }.joined(separator: ">")
        let context = [
            "parents=\(parents)",
            "path=\(first.pathClass?.rawValue ?? "none")",
            "destination=\(first.destinationClass?.rawValue ?? "none")"
        ].joined(separator: ";")
        return (teamID, signingIdentifier, "\(teamID.lowercased())|\(signingIdentifier.lowercased())", ruleID, context)
    }

    private func pruneExpiredLearnedEntries() {
        let timestamp = now()
        learnedReviewEntries.removeAll { $0.expiresAt <= timestamp }
    }

    private func enforceLearnedEntryCap(for identityKey: String) {
        let matching = learnedReviewEntries
            .filter { $0.identityKey == identityKey }
            .sorted { $0.lastConfirmedAt > $1.lastConfirmedAt }
        let retained = Set(matching.prefix(Self.maximumLearnedEntriesPerIdentity).map(\.id))
        learnedReviewEntries.removeAll { $0.identityKey == identityKey && !retained.contains($0.id) }
    }

    private func migrateLegacyDismissals() {
        for incident in incidents where incident.permanentlyDismissed {
            recordDismissal(for: incident)
        }
        incidents.removeAll(where: \.permanentlyDismissed)
    }

    /// Nick 4.6.x stored permanent dismissals only as alert deduplication keys.
    /// Preserve those keys even though the dismissed alert itself is no longer
    /// available to reconstruct the newer incident identity.
    private func migrateLegacyDismissedAlertKeys(from defaults: UserDefaults?) {
        guard let defaults else { return }
        for deduplicationKey in defaults.stringArray(forKey: "nickDismissedAlertKeys") ?? [] {
            guard !deduplicationKey.isEmpty,
                  !dismissalTombstones.contains(where: {
                      $0.alertDeduplicationKey == deduplicationKey
                  }) else { continue }
            dismissalTombstones.append(IncidentDismissalTombstone(
                incidentKey: "legacy-alert-dedup:\(deduplicationKey)",
                alertDeduplicationKey: deduplicationKey,
                dismissedAt: now()
            ))
        }
    }

    private func recordDismissal(for incident: SecurityIncident) {
        dismissalTombstones.removeAll { $0.incidentKey == incident.key }
        dismissalTombstones.append(IncidentDismissalTombstone(
            incidentKey: incident.key,
            alertDeduplicationKey: incident.alert.deduplicationKey,
            dismissedAt: Date()
        ))
    }

    private func boundInMemory() {
        let sorted = incidents.sorted(by: Self.retentionPrecedes)
        var retained: [SecurityIncident] = []
        var perRule: [String: Int] = [:]
        for incident in sorted {
            let rule = Self.primaryRuleID(for: incident)
            guard perRule[rule, default: 0] < Self.maximumIncidentsPerRule,
                  retained.count < Self.maximumPersistedIncidents else {
                evictedIncidentCount += 1
                continue
            }
            retained.append(incident)
            perRule[rule, default: 0] += 1
        }
        incidents = retained
        dismissalTombstones = Array(
            dismissalTombstones
                .sorted { $0.dismissedAt > $1.dismissedAt }
                .prefix(Self.maximumDismissalTombstones)
        )
        for identityKey in Set(learnedReviewEntries.map(\.identityKey)) {
            enforceLearnedEntryCap(for: identityKey)
        }
    }

    private static func primaryRuleID(for incident: SecurityIncident) -> String {
        incident.evidence.first?.ruleID?.lowercased()
            ?? incident.alert.contributingSignals.first.map { EvidenceRulePolicy.ruleID(for: $0).lowercased() }
            ?? "unknown"
    }

    private static func retentionPrecedes(_ lhs: SecurityIncident, _ rhs: SecurityIncident) -> Bool {
        let lhsUnresolved = lhs.state != .resolved && lhs.state != .allowed
        let rhsUnresolved = rhs.state != .resolved && rhs.state != .allowed
        if lhsUnresolved != rhsUnresolved { return lhsUnresolved }
        if lhs.alert.severity != rhs.alert.severity { return lhs.alert.severity > rhs.alert.severity }
        return lhs.alert.lastSeen > rhs.alert.lastSeen
    }

    private static func normalize(_ path: String) -> String {
        URL(fileURLWithPath: path).standardizedFileURL.path.lowercased()
    }

    private func normalize(_ path: String) -> String { Self.normalize(path) }
}
