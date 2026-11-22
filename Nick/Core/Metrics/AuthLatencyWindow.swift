// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation

/// Fixed-capacity latency storage for the Endpoint Security AUTH hot path.
/// Recording is constant-time and never allocates after initialization.
final class AuthLatencyWindow: @unchecked Sendable {
    static let productionCapacity = 4096

    private let lock = NSLock()
    private var storage: [Double]
    private var writeIndex = 0
    private var retainedCount = 0
    private var maximumObservedMilliseconds: Double?

    init(capacity: Int = productionCapacity) {
        precondition(capacity > 0)
        storage = Array(repeating: 0, count: capacity)
    }

    var capacity: Int { storage.count }

    var sampleCount: Int {
        lock.withLock { retainedCount }
    }

    /// Exposed for the non-timing regression test: recording must not resize
    /// the backing store after the ring fills.
    var allocatedSlotCount: Int {
        lock.withLock { storage.count }
    }

    func record(milliseconds: Double) {
        guard milliseconds.isFinite, milliseconds >= 0 else { return }
        lock.withLock {
            storage[writeIndex] = milliseconds
            writeIndex = (writeIndex + 1) % storage.count
            retainedCount = min(retainedCount + 1, storage.count)
            maximumObservedMilliseconds = max(maximumObservedMilliseconds ?? milliseconds, milliseconds)
        }
    }

    func snapshot() -> (
        sampleCount: Int,
        p50Milliseconds: Double?,
        p99Milliseconds: Double?,
        maximumObservedMilliseconds: Double?
    ) {
        // Copy only while locked. Sorting is intentionally outside the lock so
        // AUTH callbacks never wait on percentile work.
        let samples = retainedSamples()
        let sorted = samples.sorted()
        return (
            samples.count,
            Self.percentile(0.50, in: sorted),
            Self.percentile(0.99, in: sorted),
            lock.withLock { maximumObservedMilliseconds }
        )
    }

    func retainedSamples() -> [Double] {
        lock.withLock {
            guard retainedCount > 0 else { return [] }
            if retainedCount < storage.count {
                return Array(storage.prefix(retainedCount))
            }
            return Array(storage[writeIndex...]) + Array(storage[..<writeIndex])
        }
    }

    private static func percentile(_ percentile: Double, in sortedValues: [Double]) -> Double? {
        guard !sortedValues.isEmpty else { return nil }
        let index = Int(ceil(percentile * Double(sortedValues.count))) - 1
        return sortedValues[max(0, min(index, sortedValues.count - 1))]
    }
}

/// Local response observations are not a census of kernel terminations. A
/// process killed before responding cannot increment or persist these counters.
struct AuthResponseDiagnostics: Sendable {
    private(set) var responseAttemptCount: UInt64 = 0
    private(set) var lateResponseAttemptCount: UInt64 = 0
    private(set) var responseErrorCount: UInt64 = 0
    private(set) var lastLateResponseAt: Date?
    private(set) var lastResponseErrorAt: Date?
    private(set) var lastResponseErrorCode: UInt32?
    private(set) var lastResponseErrorEvent: String?

    mutating func record(pastDeadline: Bool, errorCode: UInt32?, event: String, at date: Date) {
        responseAttemptCount &+= 1
        if pastDeadline {
            lateResponseAttemptCount &+= 1
            lastLateResponseAt = date
        }
        if let errorCode {
            responseErrorCount &+= 1
            lastResponseErrorAt = date
            lastResponseErrorCode = errorCode
            lastResponseErrorEvent = String(event.prefix(80))
        }
    }

    var healthFields: [String: Any] {
        var fields: [String: Any] = [
            "authResponseAttemptCount": responseAttemptCount,
            "lateAuthResponseAttemptCount": lateResponseAttemptCount,
            "authResponseErrorCount": responseErrorCount,
            // Compatibility alias, with its narrower meaning made explicit.
            "deadlineMissCount": lateResponseAttemptCount,
            "deadlineMissCountMeaning": "locally-observed-late-response-attempts-only",
            "deadlineObservationScope": "current-process-response-attempts-only",
            "authLatencyObservationScope": "message-mach-time-to-response-api-return; excludes-unreturned-attempts",
            "kernelDeadlineTerminationCount": NSNull(),
            "kernelDeadlineTerminationStatus": "unknown-requires-os-diagnostic"
        ]
        if let lastLateResponseAt { fields["lastLateAuthResponseAt"] = lastLateResponseAt.timeIntervalSince1970 }
        if let lastResponseErrorAt { fields["lastAuthResponseErrorAt"] = lastResponseErrorAt.timeIntervalSince1970 }
        if let lastResponseErrorCode { fields["lastAuthResponseErrorCode"] = lastResponseErrorCode }
        if let lastResponseErrorEvent { fields["lastAuthResponseErrorEvent"] = lastResponseErrorEvent }
        return fields
    }
}

/// Correlates heartbeats across process lifetimes without inferring a crash
/// cause. Only bounded, non-path diagnostic fields survive from one session.
struct ExtensionHealthSession {
    let fields: [String: Any]

    init(processID: Int32, bootSessionUUID: String, previousHealth: [String: Any]?,
         startedAt: Date = Date(), instanceID: UUID = UUID()) {
        var fields: [String: Any] = [
            "healthSchemaVersion": 2,
            "processID": processID,
            "processInstanceID": instanceID.uuidString,
            "processStartedAt": startedAt.timeIntervalSince1970,
            "bootSessionUUID": bootSessionUUID
        ]
        if let previousHealth {
            let keys = ["version", "processID", "processInstanceID", "processStartedAt", "updatedAt",
                        "bootSessionUUID", "lateAuthResponseAttemptCount", "authResponseErrorCount",
                        "deadlineMissCount", "deadlineMissCountMeaning", "deadlineObservationScope",
                        "healthSchemaVersion", "lastLateAuthResponseAt", "lastAuthResponseErrorCode",
                        "lastAuthResponseErrorEvent"]
            var previous: [String: Any] = [:]
            for key in keys {
                if let value = previousHealth[key] as? String {
                    previous[key] = String(value.prefix(160))
                } else if let value = previousHealth[key] as? NSNumber, value.doubleValue.isFinite {
                    previous[key] = value
                }
            }
            fields["previousProcessSession"] = previous
            if let previousBoot = previousHealth["bootSessionUUID"] as? String {
                fields["previousSessionTransition"] = previousBoot == bootSessionUUID
                    ? "same-boot-process-restart-cause-unknown" : "system-restart"
            } else {
                fields["previousSessionTransition"] = "unknown-legacy-health-record"
            }
        }
        self.fields = fields
    }
}

/// Local diagnostic counters only. Fixed enum slots, no paths, hashes, messages,
/// or unbounded history. Timing wraps existing work without changing verdicts.
final class CredentialAuthDiagnostics: @unchecked Sendable {
    static let shared = CredentialAuthDiagnostics()
    enum Scope: Int, CaseIterable {
        case credentialRetained, credentialWork, credentialQueueWait, credentialWatchdogDelay
        case prelaunchRetained, prelaunchWork, prelaunchQueueWait, prelaunchWatchdogDelay
        case validated, distribution, appleImage, owningApp, distributionTeam
        case staticCode, signingInformation, validity
        case responsibleIdentity, responsibleSigningInformation, responsibleValidity, responsibleAppleAnchor
    }
    enum Event: Int, CaseIterable {
        case credentialDeferred, credentialWatchdogScheduled, credentialWatchdogFired
        case credentialWatchdogWon, credentialWorkWon, credentialClaimLost
        case prelaunchDeferred, prelaunchWatchdogScheduled, prelaunchWatchdogFired
        case prelaunchWatchdogWon, prelaunchWorkWon, prelaunchClaimLost
        case validatedCacheHit, validatedCacheMiss, distributionCacheHit, distributionCacheMiss
        case signingInformationFailure, validityFailure
    }
    struct Measurement {
        var started: UInt64 = 0
        var completed: UInt64 = 0
        var inFlight: UInt64 = 0
        var peakInFlight: UInt64 = 0
        var totalNanoseconds: UInt64 = 0
        var maximumNanoseconds: UInt64 = 0
        var lastStatus: Int32 = 0
    }
    private let lock = NSLock()
    private var scopes = Array(repeating: Measurement(), count: Scope.allCases.count)
    private var events = Array(repeating: UInt64(0), count: Event.allCases.count)
    static var now: UInt64 { DispatchTime.now().uptimeNanoseconds }

    @discardableResult
    func begin(_ scope: Scope, now: UInt64 = CredentialAuthDiagnostics.now) -> UInt64 {
        lock.withLock {
            let i = scope.rawValue
            scopes[i].started += 1
            scopes[i].inFlight += 1
            scopes[i].peakInFlight = max(scopes[i].peakInFlight, scopes[i].inFlight)
        }
        return now
    }
    func end(_ scope: Scope, since: UInt64, now: UInt64 = CredentialAuthDiagnostics.now, status: Int32 = 0) {
        record(scope, nanoseconds: now >= since ? now - since : 0, status: status, completing: true)
    }
    func observe(_ scope: Scope, nanoseconds: UInt64) {
        record(scope, nanoseconds: nanoseconds, status: 0, completing: false)
    }
    private func record(_ scope: Scope, nanoseconds: UInt64, status: Int32, completing: Bool) {
        lock.withLock {
            let i = scope.rawValue
            if completing { scopes[i].inFlight = scopes[i].inFlight > 0 ? scopes[i].inFlight - 1 : 0 }
            else { scopes[i].started += 1 }
            scopes[i].completed += 1
            scopes[i].totalNanoseconds &+= nanoseconds
            scopes[i].maximumNanoseconds = max(scopes[i].maximumNanoseconds, nanoseconds)
            scopes[i].lastStatus = status
        }
    }
    func count(_ event: Event) { lock.withLock { events[event.rawValue] &+= 1 } }
    func snapshot() -> [String: Any] {
        let copy = lock.withLock { (scopes, events) }
        var timings: [String: Any] = [:]
        for scope in Scope.allCases {
            let s = copy.0[scope.rawValue]
            timings[String(describing: scope)] = [
                "started": s.started, "completed": s.completed,
                "inFlight": s.inFlight, "peakInFlight": s.peakInFlight,
                "totalMilliseconds": Double(s.totalNanoseconds) / 1e6,
                "maximumMilliseconds": Double(s.maximumNanoseconds) / 1e6,
                "lastOSStatus": s.lastStatus
            ] as [String: Any]
        }
        var counts: [String: UInt64] = [:]
        for event in Event.allCases { counts[String(describing: event)] = copy.1[event.rawValue] }
        return ["schemaVersion": 1, "mode": "observation-only", "scope": "current-process-lifetime",
                "timings": timings, "counts": counts,
                "watchdogDelayMeaning": "actual-block-entry-minus-original-scheduled-time; includes-losing-watchdogs",
                "retainedMeaning": "retained ES message lifetime; may outlive a winning watchdog",
                "statusMeaning": "last completed Security API OSStatus per stage; no path or credential data"]
    }
}

/// Admission is decided before a closure is queued. Exact target/process keys
/// prevent one credential read from hiding another target or a reused PID.
final class CredentialObservationGate: @unchecked Sendable {
    struct Key: Hashable, Sendable {
        let actorAudit: Data
        let actorHash: Data
        let actorPath: String
        let signingID: String?
        let teamID: String?
        let codeFlags: UInt32
        let responsibleAudit: Data
        let parentAudit: Data
        let path: String
        let file: FileIdentity
        let owner: UInt32
        let store: String
    }
    struct Ticket: Sendable { let key: Key; let id: UInt64; let enqueuedAt: TimeInterval }
    enum Admission { case admitted(Ticket), coalesced, pressure(report: Bool) }
    private struct Entry {
        var id: UInt64
        var admittedAt: TimeInterval
        var pending: Bool
        var began = false
        var chainKey: String?
    }
    private let lock = NSLock()
    private var entries: [Key: Entry] = [:]
    private var order: [Key?]
    private var orderIndex = 0
    private var sequence: UInt64 = 0
    private var pending = 0
    private var queued = 0
    private var active = 0
    private var peakPending = 0
    private var admitted: UInt64 = 0
    private var coalesced: UInt64 = 0
    private var dropped: UInt64 = 0
    private var lastPressure: TimeInterval?
    private let waits = AuthLatencyWindow(capacity: 256)
    let maximumPending: Int
    let maximumEntries: Int
    let window: TimeInterval
    static var now: TimeInterval { Double(DispatchTime.now().uptimeNanoseconds) / 1e9 }
    init(maximumPending: Int = 128, maximumEntries: Int = 2048, window: TimeInterval = 60) {
        precondition(maximumPending > 0 && maximumEntries >= maximumPending)
        self.maximumPending = maximumPending; self.maximumEntries = maximumEntries; self.window = window
        self.order = Array(repeating: nil, count: maximumEntries)
    }
    func chainKey(for key: Key) -> String? { lock.withLock { entries[key]?.chainKey } }
    func admit(_ key: Key, now: TimeInterval = CredentialObservationGate.now) -> Admission {
        lock.withLock {
            if let old = entries[key], old.pending || (now >= old.admittedAt && now - old.admittedAt < window) {
                coalesced &+= 1; return .coalesced
            }
            guard pending < maximumPending else {
                dropped &+= 1
                let report = lastPressure.map { now - $0 >= 60 } ?? true
                if report { lastPressure = now }
                return .pressure(report: report)
            }
            if entries[key] == nil {
                // At most maximumPending occupied slots can be skipped; no
                // dictionary filtering, sorting or growing FIFO on AUTH.
                while let candidate = order[orderIndex], entries[candidate]?.pending == true {
                    orderIndex = (orderIndex + 1) % maximumEntries
                }
                if let candidate = order[orderIndex] { entries.removeValue(forKey: candidate) }
                order[orderIndex] = key
                orderIndex = (orderIndex + 1) % maximumEntries
            }
            sequence &+= 1; admitted &+= 1; pending += 1; queued += 1; peakPending = max(peakPending, pending)
            entries[key] = Entry(id: sequence, admittedAt: now, pending: true, chainKey: entries[key]?.chainKey)
            return .admitted(Ticket(key: key, id: sequence, enqueuedAt: now))
        }
    }
    func began(_ ticket: Ticket, now: TimeInterval = CredentialObservationGate.now) {
        lock.withLock {
            guard entries[ticket.key]?.id == ticket.id, entries[ticket.key]?.began == false else { return }
            entries[ticket.key]?.began = true
            queued = max(0, queued - 1); active += 1
        }
        waits.record(milliseconds: max(0, now - ticket.enqueuedAt) * 1000)
    }
    func workEnded() { lock.withLock { active = max(0, active - 1) } }
    func setChainKey(_ value: String, ticket: Ticket) {
        lock.withLock { if entries[ticket.key]?.id == ticket.id { entries[ticket.key]?.chainKey = value } }
    }
    func finish(_ ticket: Ticket) {
        lock.withLock {
            guard entries[ticket.key]?.id == ticket.id, entries[ticket.key]?.pending == true else { return }
            if entries[ticket.key]?.began == false { queued = max(0, queued - 1) }
            entries[ticket.key]?.pending = false; pending -= 1
        }
    }
    func snapshot(now: TimeInterval = CredentialObservationGate.now) -> [String: Any] {
        var result: [String: Any] = lock.withLock {
            let oldest = entries.values.filter(\.pending).map(\.admittedAt).min()
            let oldestQueued = entries.values.filter { $0.pending && !$0.began }.map(\.admittedAt).min()
            return ["admitted": admitted, "coalescedBeforeQueue": coalesced, "pressureDrops": dropped,
                    "pendingIncludingDelayedReview": pending, "queued": queued, "active": active,
                    "delayedReview": max(0, pending - queued - active), "peakPending": peakPending,
                    "oldestQueuedAgeMilliseconds": oldestQueued.map { max(0, now - $0) * 1000 } ?? 0,
                    "retainedKeys": entries.count, "maximumPending": maximumPending, "maximumKeys": maximumEntries,
                    "oldestPendingAgeMilliseconds": oldest.map { max(0, now - $0) * 1000 } ?? 0,
                    "overloadObservedInProcess": dropped > 0,
                    "scope": "credential observation only; enforcement and keychain read tracking precede admission"]
        }
        let w = waits.snapshot()
        result["queueWaitP99Milliseconds"] = w.p99Milliseconds
        result["queueWaitMaximumMilliseconds"] = w.maximumObservedMilliseconds
        return result
    }
}

/// Bounded single-flight cache. Busy callers get no trusted identity rather
/// than waiting behind Security work. All expensive work is outside its lock.
final class BoundedAttributionCache<Key: Hashable, Value>: @unchecked Sendable {
    enum Lookup { case hit(Value?), load, busy }
    private struct Entry { let value: Value?; let expires: TimeInterval }
    private let lock = NSLock()
    private var entries: [Key: Entry] = [:]
    private var pending: Set<Key> = []
    private var hits: UInt64 = 0, misses: UInt64 = 0, busy: UInt64 = 0, evictions: UInt64 = 0
    let capacity: Int
    let maximumInFlight: Int
    let ttl: TimeInterval
    init(capacity: Int = 1024, maximumInFlight: Int = 32, ttl: TimeInterval = 5) {
        precondition(capacity > 0 && maximumInFlight > 0)
        self.capacity = capacity; self.maximumInFlight = maximumInFlight; self.ttl = ttl
    }
    func lookupOrReserve(_ key: Key, now: TimeInterval) -> Lookup {
        lock.withLock {
            if let e = entries[key], now < e.expires { hits &+= 1; return .hit(e.value) }
            entries.removeValue(forKey: key)
            guard !pending.contains(key), pending.count < maximumInFlight else { busy &+= 1; return .busy }
            pending.insert(key); misses &+= 1; return .load
        }
    }
    func complete(_ key: Key, value: Value?, cache: Bool = true, now: TimeInterval) {
        lock.withLock {
            guard pending.remove(key) != nil, cache else { return }
            if entries.count >= capacity, let oldest = entries.min(by: { $0.value.expires < $1.value.expires })?.key {
                entries.removeValue(forKey: oldest); evictions &+= 1
            }
            entries[key] = Entry(value: value, expires: now + ttl)
        }
    }
    func snapshot() -> [String: Any] {
        lock.withLock { ["hits": hits, "misses": misses, "singleFlightBusy": busy,
                        "entries": entries.count, "inFlight": pending.count, "evictions": evictions,
                        "capacity": capacity, "maximumInFlight": maximumInFlight, "ttlSeconds": ttl] }
    }
}
