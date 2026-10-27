// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation
import os

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
    case reopened
    case quarantineFailed
    case quarantined
}

enum IncidentReopenState: String, Codable, Sendable {
    case reviewed
    case resolved
    case hidden
    case allowed

    var displayName: String {
        switch self {
        case .reviewed: "reviewed"
        case .resolved: "resolved"
        case .hidden: "hidden"
        case .allowed: "Always Allow"
        }
    }
}

struct IncidentActionRecord: Codable, Sendable, Equatable {
    let action: IncidentActionKind
    let actor: EvidenceVerdictActor
    private(set) var firstTimestamp: Date
    private(set) var lastTimestamp: Date
    private(set) var count: Int
    let detail: String?

    /// Compatibility accessor for callers that previously read the single
    /// action timestamp. It now represents the most recent occurrence.
    var timestamp: Date { lastTimestamp }

    init(action: IncidentActionKind, actor: EvidenceVerdictActor, timestamp: Date, detail: String? = nil) {
        self.action = action
        self.actor = actor
        self.firstTimestamp = timestamp
        self.lastTimestamp = timestamp
        self.count = 1
        self.detail = detail
    }

    mutating func recordOccurrence(at timestamp: Date) {
        firstTimestamp = min(firstTimestamp, timestamp)
        lastTimestamp = max(lastTimestamp, timestamp)
        count += 1
    }

    private enum CodingKeys: String, CodingKey {
        case action, actor, timestamp, firstTimestamp, lastTimestamp, count, detail
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
        detail = try container.decodeIfPresent(String.self, forKey: .detail)
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(action, forKey: .action)
        try container.encode(actor, forKey: .actor)
        try container.encode(firstTimestamp, forKey: .firstTimestamp)
        try container.encode(lastTimestamp, forKey: .lastTimestamp)
        try container.encode(count, forKey: .count)
        try container.encodeIfPresent(detail, forKey: .detail)
    }
}

struct IncidentDismissalTombstone: Codable, Sendable, Equatable {
    let incidentKey: String
    let alertDeduplicationKey: String
    let dismissedAt: Date
    /// Number of occurrences covered by this dismissal. Older snapshots did
    /// not persist the count; treating them as one preserves first-write-wins
    /// while allowing later protected evidence to reopen the incident.
    let occurrenceCountAtDismissal: Int

    init(
        incidentKey: String,
        alertDeduplicationKey: String,
        dismissedAt: Date,
        occurrenceCountAtDismissal: Int = 1
    ) {
        self.incidentKey = incidentKey
        self.alertDeduplicationKey = alertDeduplicationKey
        self.dismissedAt = dismissedAt
        self.occurrenceCountAtDismissal = max(1, occurrenceCountAtDismissal)
    }

    private enum CodingKeys: String, CodingKey {
        case incidentKey, alertDeduplicationKey, dismissedAt, occurrenceCountAtDismissal
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        incidentKey = try container.decode(String.self, forKey: .incidentKey)
        alertDeduplicationKey = try container.decode(String.self, forKey: .alertDeduplicationKey)
        dismissedAt = try container.decode(Date.self, forKey: .dismissedAt)
        occurrenceCountAtDismissal = max(
            1,
            try container.decodeIfPresent(Int.self, forKey: .occurrenceCountAtDismissal) ?? 1
        )
    }
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
    var networkIngestCursor: NetworkIngestCursor?

    init(
        schemaVersion: Int = Self.currentSchemaVersion,
        incidents: [SecurityIncident],
        dismissalTombstones: [IncidentDismissalTombstone],
        expectedCooldowns: [String: TimeInterval],
        evictedIncidentCount: Int = 0,
        learnedReviewEntries: [LearnedReviewEntry] = [],
        networkIngestCursor: NetworkIngestCursor? = nil
    ) {
        self.schemaVersion = schemaVersion
        self.incidents = incidents
        self.dismissalTombstones = dismissalTombstones
        self.expectedCooldowns = expectedCooldowns
        self.evictedIncidentCount = max(0, evictedIncidentCount)
        self.learnedReviewEntries = learnedReviewEntries
        self.networkIngestCursor = networkIngestCursor
    }

    private enum CodingKeys: String, CodingKey {
        case schemaVersion, incidents, dismissalTombstones, expectedCooldowns, evictedIncidentCount
        case learnedReviewEntries, networkIngestCursor
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        schemaVersion = try container.decode(Int.self, forKey: .schemaVersion)
        incidents = try container.decode([SecurityIncident].self, forKey: .incidents)
        dismissalTombstones = try container.decode([IncidentDismissalTombstone].self, forKey: .dismissalTombstones)
        expectedCooldowns = try container.decode([String: TimeInterval].self, forKey: .expectedCooldowns)
        evictedIncidentCount = max(0, try container.decodeIfPresent(Int.self, forKey: .evictedIncidentCount) ?? 0)
        learnedReviewEntries = try container.decodeIfPresent([LearnedReviewEntry].self, forKey: .learnedReviewEntries) ?? []
        networkIngestCursor = try container.decodeIfPresent(NetworkIngestCursor.self, forKey: .networkIngestCursor)
    }
}

struct NetworkIngestCursor: Codable, Sendable, Equatable {
    let initializedAt: Date
    var deliveredEventIDs: Set<UUID>
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
    var previouslyDismissedAt: Date?
    var reopenedAfterState: IncidentReopenState?
    var reopenedAfterAt: Date?
    var lastNotifiedAt: Date?

    init(
        id: UUID = UUID(),
        key: String,
        alert: ThreatAlert,
        evidence: [Evidence],
        state: IncidentState = .new,
        actions: [IncidentActionRecord] = [],
        isVisible: Bool = true,
        permanentlyDismissed: Bool = false,
        previouslyDismissedAt: Date? = nil,
        reopenedAfterState: IncidentReopenState? = nil,
        reopenedAfterAt: Date? = nil,
        lastNotifiedAt: Date? = nil
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
        self.previouslyDismissedAt = previouslyDismissedAt
        self.reopenedAfterState = reopenedAfterState
        self.reopenedAfterAt = reopenedAfterAt
        self.lastNotifiedAt = lastNotifiedAt
    }
}

enum IncidentIngestOutcome: Equatable {
    case persisted(UInt64)
    case coalesced(UInt64)
    case suppressedByPolicy(String)
    case failed

    var generation: UInt64? {
        switch self {
        case .persisted(let generation), .coalesced(let generation): generation
        case .suppressedByPolicy, .failed: nil
        }
    }
}

struct IncidentIngestResult {
    let visibleAlerts: [ThreatAlert]
    let newlyActionable: [ThreatAlert]
    let outcomes: [IncidentIngestOutcome]
}

@MainActor
final class DurableIncidentNotificationQueue {
    private var alertsByGeneration: [UInt64: [ThreatAlert]] = [:]
    var pendingGenerationCount: Int { alertsByGeneration.count }

    func stage(_ alerts: [ThreatAlert], for generation: UInt64) {
        guard generation > 0, !alerts.isEmpty else { return }
        alertsByGeneration[generation] = alerts
    }

    func confirm(generation: UInt64) -> [ThreatAlert] {
        var newestByIncidentID: [UUID: ThreatAlert] = [:]
        for key in alertsByGeneration.keys.filter({ $0 <= generation }).sorted() {
            for alert in alertsByGeneration[key] ?? [] {
                newestByIncidentID[alert.id] = alert
            }
        }
        alertsByGeneration = alertsByGeneration.filter { $0.key > generation }
        return Array(newestByIncidentID.values)
    }
}

/// The only policy and persistence boundary after deterministic correlation.
/// Trust, suppression, cooldowns and incident deduplication are deliberately
/// evaluated here once, irrespective of which monitor supplied the evidence.
@MainActor
final class IncidentStore {
    private static let logger = Logger(
        subsystem: "com.ehsanazish.nick",
        category: "IncidentStore"
    )
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

    /// Current policy configuration. Exposed read-only so callers and tests can
    /// verify that incident-history maintenance does not rewrite user policy.
    var configuredSuppressionRules: [SuppressionRule] { suppressionRules }
    private var expectedCooldowns: [String: TimeInterval]
    private var dismissalTombstones: [IncidentDismissalTombstone]
    private(set) var evictedIncidentCount = 0
    private(set) var learnedReviewEntries: [LearnedReviewEntry] = []
    private(set) var networkIngestCursor: NetworkIngestCursor?
    private var verdictLearningEnabled = false
    private let now: () -> Date
    private let identityValidator: (String, String, String) -> Bool
    private var privilegedPersistence: ((Data, UInt64) -> Void)?
    private var lastPrivilegedPayload: Data?
    private(set) var lastQueuedGeneration: UInt64 = 0
    private(set) var lastDurablyConfirmedGeneration: UInt64 = 0
    private var pendingNotificationSignalIDs: Set<UUID> = []
    private var notificationSignalIDsByGeneration: [UInt64: Set<UUID>] = [:]
    private var pendingNotificationIncidentIDs: Set<UUID> = []
    private var notificationIncidentIDsByGeneration: [UInt64: Set<UUID>] = [:]

    var hasUnconfirmedChanges: Bool {
        lastQueuedGeneration > lastDurablyConfirmedGeneration
    }

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
        persistence: @escaping (Data, UInt64) -> Void
    ) throws {
        let snapshot = try Self.decodeSnapshot(payload)
        incidents = snapshot.incidents
        dismissalTombstones = snapshot.dismissalTombstones
        expectedCooldowns = snapshot.expectedCooldowns
        evictedIncidentCount = snapshot.evictedIncidentCount
        learnedReviewEntries = snapshot.learnedReviewEntries
        networkIngestCursor = snapshot.networkIngestCursor
        migrateLegacyDismissals()
        boundInMemory()
        privilegedPersistence = persistence
        lastPrivilegedPayload = try encodedSnapshot()
    }

    func confirmDurablePersistence(generation: UInt64) {
        guard generation <= lastQueuedGeneration else { return }
        lastDurablyConfirmedGeneration = max(lastDurablyConfirmedGeneration, generation)
        for key in Array(notificationSignalIDsByGeneration.keys) where key <= generation {
            pendingNotificationSignalIDs.subtract(notificationSignalIDsByGeneration.removeValue(forKey: key) ?? [])
        }
        for key in Array(notificationIncidentIDsByGeneration.keys) where key <= generation {
            pendingNotificationIncidentIDs.subtract(notificationIncidentIDsByGeneration.removeValue(forKey: key) ?? [])
        }
    }

    /// Records a notification timestamp only after the notification center has
    /// accepted the delivery request. Suppressed, unauthorized and failed
    /// requests must not consume the recurrence window.
    @discardableResult
    func markNotificationDelivered(alertID: UUID, at timestamp: Date) -> UInt64? {
        guard let index = incidents.firstIndex(where: { $0.alert.id == alertID }) else { return nil }
        incidents[index].lastNotifiedAt = timestamp
        return persist(force: true)
    }

    @discardableResult
    func initializeNetworkIngestCursor(eventIDs: Set<UUID>) -> UInt64 {
        guard networkIngestCursor == nil else { return lastQueuedGeneration }
        networkIngestCursor = NetworkIngestCursor(
            initializedAt: now(),
            deliveredEventIDs: Self.boundedNetworkEventIDs(eventIDs)
        )
        return persist(force: true)
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
        var outcomes: [IncidentIngestOutcome] = []
        var forcePersistence = false
        var notificationSignalIDs: Set<UUID> = []
        var notificationIncidentIDs: Set<UUID> = []

        for rawCandidate in candidates {
            let networkEventIDs = Set(rawCandidate.contributingSignals.compactMap { signal in
                signal.source == .network ? signal.id : nil
            })
            if !networkEventIDs.isEmpty {
                if networkIngestCursor == nil {
                    networkIngestCursor = NetworkIngestCursor(initializedAt: now(), deliveredEventIDs: [])
                }
                networkIngestCursor?.deliveredEventIDs.formUnion(networkEventIDs)
                if let ids = networkIngestCursor?.deliveredEventIDs {
                    networkIngestCursor?.deliveredEventIDs = Self.boundedNetworkEventIDs(ids)
                }
                forcePersistence = true
            }
            let candidate = applyLearnedPriority(to: applyTrustedDowngrade(to: rawCandidate))
            guard !isSuppressed(candidate) else {
                outcomes.append(.suppressedByPolicy("suppression rule"))
                continue
            }
            guard !isCoolingDown(candidate) else {
                outcomes.append(.suppressedByPolicy("expected-activity cooldown"))
                continue
            }
            let key = Self.incidentKey(for: candidate)
            let isCaptureInactive = candidate.contributingSignals.allSatisfy {
                $0.source == .avCapture
                    && $0.metadata["reason"] == "capture_device_inactive"
            }
            if isCaptureInactive, !incidents.contains(where: { $0.key == key }) {
                Self.logger.info("capture inactive ignored because no matching incident exists")
                outcomes.append(.suppressedByPolicy("capture inactive without active incident"))
                continue
            }
            if let tombstone = matchingDismissal(for: candidate, incidentKey: key) {
                if isProtected(candidate) {
                    var reopened = candidate
                    reopened = reopened.withOccurrenceCount(
                        max(tombstone.occurrenceCountAtDismissal + 1, candidate.occurrenceCount)
                    )
                    var incident = SecurityIncident(
                        key: key,
                        alert: reopened,
                        evidence: reopened.contributingSignals.map(Evidence.init(signal:)),
                        state: .new,
                        actions: [action(.detected, actor: .automatic)],
                        previouslyDismissedAt: tombstone.dismissedAt,
                        lastNotifiedAt: nil
                    )
                    incident.isVisible = true
                    incidents.append(incident)
                    dismissalTombstones.removeAll { $0.incidentKey == tombstone.incidentKey }
                    newlyActionable.append(reopened)
                    notificationIncidentIDs.insert(reopened.id)
                    notificationSignalIDs.formUnion(reopened.contributingSignals.map(\.id))
                    outcomes.append(.persisted(0))
                    continue
                }
                outcomes.append(.suppressedByPolicy("dismissal"))
                continue
            }
            let exactIndex = incidents.firstIndex(where: { $0.key == key })
            let relatedLaunchItemIndex = exactIndex == nil
                ? incidents.firstIndex(where: {
                    Self.shouldMergeLaunchItemEvidence($0.alert, candidate)
                        || Self.shouldAttachLaunchItemRemoval($0.alert, candidate)
                })
                : nil
            if let index = exactIndex ?? relatedLaunchItemIndex {
                let prior = incidents[index]
                let mergesRelatedLaunchItemEvidence = Self.shouldMergeLaunchItemEvidence(prior.alert, candidate)
                    || Self.shouldAttachLaunchItemRemoval(prior.alert, candidate)
                let priorSignalIDs = Set(prior.alert.contributingSignals.map(\.id))
                let candidateSignalIDs = Set(candidate.contributingSignals.map(\.id))
                if !candidateSignalIDs.isEmpty, candidateSignalIDs.isSubset(of: priorSignalIDs) {
                    if hasUnconfirmedChanges {
                        outcomes.append(.coalesced(0))
                        forcePersistence = true
                        if !candidateSignalIDs.isDisjoint(with: pendingNotificationSignalIDs) {
                            newlyActionable.append(prior.alert)
                            notificationSignalIDs.formUnion(candidateSignalIDs)
                        }
                    } else {
                        outcomes.append(.suppressedByPolicy("duplicate event identifier"))
                    }
                    continue
                }
                let escalated = candidate.severity > prior.alert.severity
                let mergedAlert: ThreatAlert
                if isCaptureInactive {
                    mergedAlert = prior.alert.mergingLifecycleTransition(candidate)
                } else if mergesRelatedLaunchItemEvidence {
                    mergedAlert = prior.alert.mergingRelatedEvidence(candidate)
                } else {
                    mergedAlert = prior.alert.mergingOccurrence(candidate)
                }
                incidents[index].alert = mergedAlert
                incidents[index].evidence = mergedAlert.contributingSignals.map(Evidence.init(signal:))
                recordAutomaticRemediationAction(from: candidate, at: index)
                let learnedConfirmationCount = learningConfirmationCount(for: candidate)
                if isCaptureInactive {
                    incidents[index].state = .resolved
                    incidents[index].isVisible = true
                    recordAction(.resolved, actor: .automatic, at: index)
                }
                if candidate.contributingSignals.contains(where: { $0.metadata["remediationStatus"] == "file-gone" }) {
                    incidents[index].state = .resolved
                    incidents[index].isVisible = true
                }
                outcomes.append(.coalesced(0))
                if isProtected(candidate) {
                    let wasHidden = !prior.isVisible
                    let shouldReopen = prior.state != .new || wasHidden
                    let currentTime = now()
                    let outsideNotificationWindow = prior.lastNotifiedAt.map {
                        currentTime.timeIntervalSince($0) >= 600
                    } ?? true
                    if shouldReopen {
                        incidents[index].reopenedAfterState = prior.state == .allowed
                            ? .allowed
                            : (wasHidden ? .hidden : Self.reopenState(for: prior.state))
                        incidents[index].reopenedAfterAt = Self.lifecycleDate(for: prior)
                        incidents[index].state = .new
                        incidents[index].isVisible = true
                        recordAction(.reopened, actor: .automatic, at: index)
                    }
                    if shouldReopen || outsideNotificationWindow {
                        newlyActionable.append(incidents[index].alert)
                        notificationIncidentIDs.insert(incidents[index].alert.id)
                        notificationSignalIDs.formUnion(candidateSignalIDs)
                    } else if pendingNotificationIncidentIDs.contains(prior.alert.id) {
                        // A prior occurrence already earned a notification but
                        // its snapshot has not reached durable storage yet.
                        // Restage the newest whole-incident snapshot so a
                        // superseding write delivers the final count once.
                        newlyActionable.append(incidents[index].alert)
                        notificationIncidentIDs.insert(incidents[index].alert.id)
                    }
                } else if let learnedConfirmationCount,
                          prior.state == .allowed || prior.state == .reviewed {
                    // A learning candidate must remain reachable for its second
                    // distinct occurrence. Once active, later matches remain in
                    // history at informational priority without notifying.
                    incidents[index].state = learnedConfirmationCount >= 2 ? .reviewed : .new
                    incidents[index].isVisible = true
                    if learnedConfirmationCount >= 2 {
                        incidents[index].alert = incidents[index].alert.with(severity: .info)
                    }
                    recordAction(.reopened, actor: .automatic, at: index)
                    if learnedConfirmationCount < 2, !Self.isSilentReview(candidate) {
                        newlyActionable.append(incidents[index].alert)
                        notificationIncidentIDs.insert(incidents[index].alert.id)
                        notificationSignalIDs.formUnion(candidateSignalIDs)
                    }
                } else if escalated && !Self.isSilentReview(candidate) {
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
                if candidate.contributingSignals.contains(where: { $0.metadata["remediationStatus"] == "file-gone" }) {
                    incident.state = .resolved
                }
                incident.actions.append(action(.detected, actor: .automatic))
                if let remediation = Self.remediationAction(from: candidate, actor: .automatic, at: now()) {
                    incident.actions.append(remediation)
                }
                if isProtected(candidate) {
                    notificationSignalIDs.formUnion(candidate.contributingSignals.map(\.id))
                    notificationIncidentIDs.insert(candidate.id)
                }
                incidents.append(incident)
                outcomes.append(.persisted(0))
                if (candidate.severity != .info || Self.requiresVisibleNotification(candidate))
                    && !Self.isSilentReview(candidate) {
                    newlyActionable.append(candidate)
                }
            }
        }

        let generation = persist(force: forcePersistence)
        if generation > lastDurablyConfirmedGeneration, !notificationSignalIDs.isEmpty {
            pendingNotificationSignalIDs.formUnion(notificationSignalIDs)
            notificationSignalIDsByGeneration[generation, default: []].formUnion(notificationSignalIDs)
        }
        if generation > lastDurablyConfirmedGeneration, !notificationIncidentIDs.isEmpty {
            pendingNotificationIncidentIDs.formUnion(notificationIncidentIDs)
            notificationIncidentIDsByGeneration[generation, default: []].formUnion(notificationIncidentIDs)
        }
        outcomes = outcomes.map { outcome in
            switch outcome {
            case .persisted: .persisted(generation)
            case .coalesced: .coalesced(generation)
            case .suppressedByPolicy, .failed: outcome
            }
        }
        return IncidentIngestResult(
            visibleAlerts: visibleAlerts,
            newlyActionable: newlyActionable,
            outcomes: outcomes
        )
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
            // Resolution changes actionability, not protected-evidence
            // retention. Keep it available to both projections as history.
            incidents[index].isVisible = isProtected(incidents[index].alert)
        case .allowedOnce:
            incidents[index].state = .allowed
            incidents[index].isVisible = false
            if isEligibleForExpectedCooldown(incidents[index].alert) {
                expectedCooldowns[incidents[index].key] = Date().addingTimeInterval(86_400).timeIntervalSince1970
            }
        case .alwaysAllowed:
            incidents[index].state = .allowed
            incidents[index].isVisible = false
        case .detected, .reopened, .quarantineFailed, .quarantined:
            incidents[index].state = .new
        }
        persist()
    }

    /// Whether an authenticated review decision can contribute to local
    /// verdict learning. Callers use this to avoid installing a suppression
    /// rule that would make the required second occurrence unreachable.
    func isEligibleForVerdictLearning(_ alert: ThreatAlert) -> Bool {
        verdictLearningEnabled && learningKey(for: alert) != nil
    }

    @discardableResult
    func recordQuarantineFailure(alertID: UUID, failure: QuarantineFailure) -> UInt64 {
        guard let index = incidents.firstIndex(where: { $0.alert.id == alertID }) else { return 0 }
        let detail = "quarantine failed: \(failure.reason.rawValue) [\(failure.errorDomain):\(failure.errorCode)]"
        incidents[index].actions.append(IncidentActionRecord(
            action: .quarantineFailed,
            actor: .user,
            timestamp: now(),
            detail: detail
        ))
        incidents[index].alert = incidents[index].alert.withQuarantineFailure(failure)
        incidents[index].state = failure.reason == .fileGone ? .resolved : .new
        incidents[index].isVisible = true
        return persist()
    }

    @discardableResult
    func recordQuarantineSuccess(alertID: UUID) -> UInt64 {
        guard let index = incidents.firstIndex(where: { $0.alert.id == alertID }) else { return 0 }
        incidents[index].actions.append(IncidentActionRecord(
            action: .quarantined,
            actor: .user,
            timestamp: now(),
            detail: "quarantine succeeded"
        ))
        incidents[index].alert = incidents[index].alert.clearingQuarantineFailure()
        incidents[index].state = .resolved
        incidents[index].isVisible = true
        return persist()
    }

    /// Removes incident records only. Policy, review-learning, dismissal and
    /// cooldown state deliberately survive a history clear.
    func clearIncidentHistory() {
        incidents.removeAll()
        legacyTestDefaults?.removeObject(forKey: "nickPersistedAlerts")
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

    @discardableResult
    private func persist(force: Bool = false) -> UInt64 {
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
        guard let payload = try? encodedSnapshot() else { return lastQueuedGeneration }
        guard let privilegedPersistence else {
            lastQueuedGeneration &+= 1
            lastDurablyConfirmedGeneration = lastQueuedGeneration
            lastPrivilegedPayload = payload
            return lastQueuedGeneration
        }
        guard force || payload != lastPrivilegedPayload else { return lastQueuedGeneration }
        lastQueuedGeneration &+= 1
        lastPrivilegedPayload = payload
        privilegedPersistence(payload, lastQueuedGeneration)
        return lastQueuedGeneration
    }

    private func encodedSnapshot() throws -> Data {
        let snapshot = IncidentStoreSnapshot(
            incidents: incidents,
            dismissalTombstones: dismissalTombstones,
            expectedCooldowns: expectedCooldowns,
            evictedIncidentCount: evictedIncidentCount,
            learnedReviewEntries: learnedReviewEntries,
            networkIngestCursor: networkIngestCursor
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

    private static func boundedNetworkEventIDs(_ ids: Set<UUID>) -> Set<UUID> {
        Set(ids.sorted { $0.uuidString < $1.uuidString }.suffix(5_000))
    }

    private static func migratedIncident(_ alert: ThreatAlert) -> SecurityIncident {
        SecurityIncident(
            key: incidentKey(for: alert),
            alert: alert,
            evidence: alert.contributingSignals.map(Evidence.init(signal:)),
            actions: [migrationAction(.detected, actor: .migration)]
        )
    }

    private static func reopenState(for state: IncidentState) -> IncidentReopenState {
        switch state {
        case .resolved: .resolved
        case .reviewed: .reviewed
        case .allowed: .allowed
        case .new: .reviewed
        }
    }

    private static func lifecycleDate(for incident: SecurityIncident) -> Date {
        incident.actions.last?.lastTimestamp ?? incident.alert.lastSeen
    }

    /// Cross-source identity intentionally omits monitor source. Two monitors
    /// describing the same rule and subject update one incident.
    private static func shouldMergeLaunchItemEvidence(
        _ existing: ThreatAlert,
        _ incoming: ThreatAlert
    ) -> Bool {
        let existingKinds = launchItemEvidenceKinds(existing)
        let incomingKinds = launchItemEvidenceKinds(incoming)
        guard existingKinds.isDisjoint(with: incomingKinds),
              existingKinds.union(incomingKinds) == [.btm, .fim],
              let existingPath = launchItemPath(existing),
              let incomingPath = launchItemPath(incoming),
              normalize(existingPath) == normalize(incomingPath) else { return false }
        return abs(existing.lastSeen.timeIntervalSince(incoming.lastSeen)) <= 10
    }

    private static func shouldAttachLaunchItemRemoval(
        _ existing: ThreatAlert,
        _ incoming: ThreatAlert
    ) -> Bool {
        guard existing.contributingSignals.contains(where: {
            $0.metadata["appleEvent"] == "background-item-added"
        }), incoming.contributingSignals.contains(where: {
            $0.metadata["appleEvent"] == "background-item-removed"
        }), let existingPath = launchItemPath(existing),
           let incomingPath = launchItemPath(incoming)
        else { return false }
        return normalize(existingPath) == normalize(incomingPath)
    }

    private enum LaunchItemEvidenceKind: Hashable { case btm, fim }

    private static func launchItemEvidenceKinds(_ alert: ThreatAlert) -> Set<LaunchItemEvidenceKind> {
        Set(alert.contributingSignals.compactMap { signal in
            if signal.metadata["appleEvent"] == "background-item-added" { return .btm }
            if signal.metadata["fimStatus"] != nil || signal.source == .filesystem { return .fim }
            return nil
        })
    }

    private static func launchItemPath(_ alert: ThreatAlert) -> String? {
        for signal in alert.contributingSignals {
            let candidate = signal.metadata["persistencePath"]
                ?? signal.metadata["itemURL"]
                ?? signal.fileInfo?.path
                ?? signal.metadata["path"]
            guard let candidate else { continue }
            let path: String
            if let url = URL(string: candidate), url.isFileURL {
                path = url.path
            } else {
                path = candidate
            }
            let lowered = path.lowercased()
            if lowered.hasSuffix(".plist"),
               (lowered.contains("/launchagents/") || lowered.contains("/launchdaemons/")) {
                return path
            }
        }
        return nil
    }

    static func incidentKey(for alert: ThreatAlert) -> String {
        if let launchPath = launchItemPath(alert) {
            return "launch-item|path:\(normalize(launchPath))"
        }
        if let label = alert.contributingSignals.compactMap({ $0.metadata["launchItemLabel"] }).first {
            return "launch-item|label:\(label.lowercased())"
        }
        let captureSignals = alert.contributingSignals.filter { $0.source == .avCapture }
        if !captureSignals.isEmpty, captureSignals.count == alert.contributingSignals.count {
            let subjects = Set(captureSignals.map {
                let media = ($0.metadata["mediaType"] ?? "capture").lowercased()
                let device = normalize($0.metadata["deviceName"] ?? "device")
                return "capture-device|media:\(media)|device:\(device)"
            }).sorted()
            return subjects.joined(separator: "||")
        }
        let subjects = Set(alert.contributingSignals.map { signal -> String in
            let rule = EvidenceRulePolicy.ruleID(for: signal).lowercased()
            if signal.metadata["reason"] == "endpoint_tamper_observed",
               let operation = signal.metadata["tamperOperation"],
               let target = signal.metadata["tamperTarget"] ?? signal.fileInfo?.path,
               let process = signal.processInfo {
                let signing = EvidenceSigningIdentity(signal: signal)
                let actor = signing.teamID.flatMap { team in
                    signing.signingIdentifier.map { "signed:\(team.lowercased()):\($0.lowercased())" }
                } ?? "path:\(normalize(process.path))"
                return "\(rule)|actor:\(actor)|operation:\(operation.lowercased())|target:\(normalize(target))"
            }
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
                || ($0.source == .avCapture
                    && $0.metadata["reason"] == "capture_device_active")
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

    private static func migrationAction(_ kind: IncidentActionKind, actor: EvidenceVerdictActor) -> IncidentActionRecord {
        IncidentActionRecord(action: kind, actor: actor, timestamp: Date())
    }

    private func action(_ kind: IncidentActionKind, actor: EvidenceVerdictActor) -> IncidentActionRecord {
        IncidentActionRecord(action: kind, actor: actor, timestamp: now())
    }

    private func recordAction(_ kind: IncidentActionKind, actor: EvidenceVerdictActor, at index: Int) {
        let now = now()
        if let existing = incidents[index].actions.firstIndex(where: { $0.action == kind && $0.actor == actor }) {
            incidents[index].actions[existing].recordOccurrence(at: now)
        } else {
            incidents[index].actions.append(
                IncidentActionRecord(action: kind, actor: actor, timestamp: now)
            )
        }
    }

    private func recordAutomaticRemediationAction(from alert: ThreatAlert, at index: Int) {
        guard let remediation = Self.remediationAction(from: alert, actor: .automatic, at: now()) else { return }
        incidents[index].actions.append(remediation)
    }

    private static func remediationAction(
        from alert: ThreatAlert,
        actor: EvidenceVerdictActor,
        at timestamp: Date
    ) -> IncidentActionRecord? {
        guard let signal = alert.contributingSignals.first(where: {
            $0.metadata["remediationStatus"] != nil
        }) else { return nil }
        switch signal.metadata["remediationStatus"] {
        case "quarantine-failed", "file-gone":
            let reason = signal.metadata["remediationFailureReason"] ?? "unknown"
            let domain = signal.metadata["remediationErrorDomain"] ?? "unknown"
            let code = signal.metadata["remediationErrorCode"] ?? "unknown"
            return IncidentActionRecord(
                action: .quarantineFailed,
                actor: actor,
                timestamp: timestamp,
                detail: "quarantine failed: \(reason) [\(domain):\(code)]"
            )
        case "quarantined":
            return IncidentActionRecord(
                action: .quarantined,
                actor: actor,
                timestamp: timestamp,
                detail: "quarantine succeeded"
            )
        default:
            return nil
        }
    }

    private func isProtected(_ alert: ThreatAlert) -> Bool {
        alert.hasProtectedEvidence
    }

    private static func isSilentReview(_ alert: ThreatAlert) -> Bool {
        alert.contributingSignals.contains {
            $0.metadata["reason"] == "network_extension_scamGuardian"
        }
    }

    private func matchingDismissal(
        for alert: ThreatAlert,
        incidentKey: String
    ) -> IncidentDismissalTombstone? {
        dismissalTombstones.first { tombstone in
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
        guard verdictLearningEnabled, !isProtected(alert), !Self.isNeverDowngrade(alert),
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

    private func learningConfirmationCount(for alert: ThreatAlert) -> Int? {
        guard verdictLearningEnabled, let key = learningKey(for: alert) else { return nil }
        return learnedReviewEntries.first(where: {
            $0.expiresAt > now()
                && $0.identityKey == key.identityKey
                && $0.ruleID == key.ruleID
                && $0.contextKey == key.contextKey
        })?.confirmationCount
    }

    private func recordLearning(from incident: SecurityIncident, action: IncidentActionKind) {
        guard let key = learningKey(for: incident.alert) else { return }
        let timestamp = now()
        if let index = learnedReviewEntries.firstIndex(where: {
            $0.identityKey == key.identityKey && $0.ruleID == key.ruleID && $0.contextKey == key.contextKey
        }) {
            let confirmationID = incident.alert.contributingSignals
                .max(by: { $0.timestamp < $1.timestamp })?.id ?? incident.id
            let inserted = learnedReviewEntries[index].confirmedIncidentIDs.insert(confirmationID).inserted
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
                confirmedIncidentIDs: [incident.alert.contributingSignals
                    .max(by: { $0.timestamp < $1.timestamp })?.id ?? incident.id]
            ))
        }
        enforceLearnedEntryCap(for: key.identityKey)
    }

    private func learningKey(for alert: ThreatAlert) -> (
        teamID: String, signingIdentifier: String, identityKey: String, ruleID: String, contextKey: String
    )? {
        guard !Self.isNeverDowngrade(alert) else { return nil }
        let evidence = alert.contributingSignals.map(Evidence.init(signal:))
        guard !evidence.isEmpty,
              evidence.allSatisfy({ $0.ruleTier == .review }),
              evidence.allSatisfy({ item in
                  item.source != .avCapture
                      || item.metadata["attributionConfidence"] == "authoritative"
              }),
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
        return (
            teamID,
            signingIdentifier,
            "\(teamID.lowercased())|\(signingIdentifier.lowercased())",
            ruleID,
            "validated-identity+rule"
        )
    }

    static func isNeverDowngrade(_ alert: ThreatAlert) -> Bool {
        let protectedReasons: Set<String> = [
            "curl_pipe_shell", "wget_pipe_shell", "download_pipe_interpreter",
            "hidden_password_prompt",
            "credential_store_access", "keychain_store_transfer",
            "keychain_command_correlation", "yara_match", "exact_hash_match"
        ]
        return alert.contributingSignals.contains { signal in
            let reason = signal.metadata["reason"] ?? signal.metadata["rule"] ?? ""
            return signal.source == .yara
                || protectedReasons.contains(reason)
                || (reason == "endpoint_tamper_observed"
                    && signal.metadata["responsibleAppSigning"] != "Apple platform")
                || signal.metadata["remediationStatus"].map {
                    ["blocked", "quarantined", "quarantine-failed"].contains($0)
                } == true
        }
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
                dismissedAt: now(),
                occurrenceCountAtDismissal: 1
            ))
        }
    }

    private func recordDismissal(for incident: SecurityIncident) {
        dismissalTombstones.removeAll { $0.incidentKey == incident.key }
        dismissalTombstones.append(IncidentDismissalTombstone(
            incidentKey: incident.key,
            alertDeduplicationKey: incident.alert.deduplicationKey,
            dismissedAt: now(),
            occurrenceCountAtDismissal: incident.alert.occurrenceCount
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
