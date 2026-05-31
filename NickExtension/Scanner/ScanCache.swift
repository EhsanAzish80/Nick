// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation

// MARK: - ScanCache

/// Thread-safe, TTL-based in-memory cache for file scan results.
///
/// The cache prevents redundant SHA-256 computation and signature DB lookups
/// for files that have already been scanned recently. Entries expire after
/// `defaultTTL` seconds and are evicted lazily on lookup or proactively when
/// the cache exceeds `maxEntries`.
///
/// All methods are safe to call from any thread or queue.
final class ScanCache {

    // MARK: - Types

    /// A single cached scan result.
    struct Entry {
        let hash: String
        let isThreat: Bool
        let threatName: String?
        let threatFamily: String?
        let expiry: Date
    }

    // MARK: - Configuration

    /// Default TTL for cache entries (5 minutes).
    static let defaultTTL: TimeInterval = 300

    /// Maximum number of entries before an expired-entry eviction pass is run.
    static let maxEntries = 10_000

    // MARK: - Private

    private var store: [String: Entry] = [:]
    private let lock = NSLock()

    // MARK: - Public API

    /// Returns a valid (non-expired) entry for `path`, or `nil` if absent / stale.
    func lookup(path: String) -> Entry? {
        lock.lock()
        defer { lock.unlock() }

        guard let entry = store[path] else { return nil }
        guard entry.expiry > Date() else {
            store.removeValue(forKey: path)
            return nil
        }
        return entry
    }

    /// Stores a scan result for `path` with the given TTL (defaults to `defaultTTL`).
    func store(
        path: String,
        hash: String,
        isThreat: Bool,
        threatName: String? = nil,
        threatFamily: String? = nil,
        ttl: TimeInterval = defaultTTL
    ) {
        let entry = Entry(
            hash: hash,
            isThreat: isThreat,
            threatName: threatName,
            threatFamily: threatFamily,
            expiry: Date().addingTimeInterval(ttl)
        )

        lock.lock()
        store[path] = entry

        if store.count > Self.maxEntries {
            evictExpired()
        }
        lock.unlock()
    }

    /// Removes the entry for `path`, forcing a fresh scan on next access.
    func invalidate(path: String) {
        lock.withLock { store.removeValue(forKey: path) }
    }

    /// Removes all entries from the cache.
    func invalidateAll() {
        lock.withLock { store.removeAll() }
    }

    // MARK: - Private Helpers

    /// Caller must hold `lock`.
    private func evictExpired() {
        let now = Date()
        store = store.filter { $0.value.expiry > now }
    }
}
