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
