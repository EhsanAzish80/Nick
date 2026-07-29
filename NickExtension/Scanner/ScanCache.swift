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
        /// Only exact, high-confidence evidence may be used by an AUTH event
        /// to deny access. A YARA/behavioural match remains reportable but must
        /// never silently break the app that produced or opened the file.
        let mayBlock: Bool
        let threatName: String?
        let threatFamily: String?
        let expiry: Date
    }

    // MARK: - Configuration

    /// Default TTL for cache entries (5 minutes).
    static let defaultTTL: TimeInterval = 300

    /// Hard maximum number of retained entries.
    static let maxEntries = 10_000

    // MARK: - Private

    private var store: [String: Entry] = [:]
    private var oneTimeAllowances: Set<String> = []
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

    /// Consumes an explicit user approval for the next authorization involving
    /// this path. Consuming it prevents an accidental permanent bypass.
    func consumeOneTimeAllowance(path: String) -> Bool {
        lock.withLock {
            oneTimeAllowances.remove(path) != nil
        }
    }

    /// Allows the next authorization and clears any stale deny verdict now,
    /// rather than waiting for the normal cache TTL.
    func allowOnce(path: String) {
        lock.withLock {
            oneTimeAllowances.insert(path)
            store.removeValue(forKey: path)
        }
    }

    /// Promotes the current cached finding to an explicit user-selected block.
    /// Returns false when no reviewed finding exists for the path.
    func blockReviewedFinding(path: String) -> Bool {
        lock.withLock {
            guard let entry = store[path], entry.isThreat else { return false }
            store[path] = Entry(
                hash: entry.hash,
                isThreat: true,
                mayBlock: true,
                threatName: entry.threatName,
                threatFamily: entry.threatFamily,
                expiry: entry.expiry
            )
            oneTimeAllowances.remove(path)
            return true
        }
    }

    /// Stores a scan result for `path` with the given TTL (defaults to `defaultTTL`).
    func store(
        path: String,
        hash: String,
        isThreat: Bool,
        mayBlock: Bool = false,
        threatName: String? = nil,
        threatFamily: String? = nil,
        ttl: TimeInterval = defaultTTL
    ) {
        let entry = Entry(
            hash: hash,
            isThreat: isThreat,
            mayBlock: mayBlock,
            threatName: threatName,
            threatFamily: threatFamily,
            expiry: Date().addingTimeInterval(ttl)
        )

        lock.lock()
        store[path] = entry

        if store.count > Self.maxEntries {
            evictExpired()
            if store.count > Self.maxEntries,
               let oldest = store.min(by: { $0.value.expiry < $1.value.expiry })?.key {
                store.removeValue(forKey: oldest)
            }
        }
        lock.unlock()
    }

    /// Removes the entry for `path`, forcing a fresh scan on next access.
    func invalidate(path: String) {
        lock.withLock { _ = store.removeValue(forKey: path) }
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
