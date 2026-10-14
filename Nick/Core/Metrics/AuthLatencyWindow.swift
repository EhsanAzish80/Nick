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
        }
    }

    func snapshot() -> (
        sampleCount: Int,
        p50Milliseconds: Double?,
        p99Milliseconds: Double?
    ) {
        // Copy only while locked. Sorting is intentionally outside the lock so
        // AUTH callbacks never wait on percentile work.
        let samples = retainedSamples()
        let sorted = samples.sorted()
        return (
            samples.count,
            Self.percentile(0.50, in: sorted),
            Self.percentile(0.99, in: sorted)
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
