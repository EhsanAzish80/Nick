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
        /// Monotonic store sequence used by eviction bookkeeping.
        var sequence: UInt64 = 0
        /// Content identity at scan time. `nil` only for legacy callers.
        let identity: FileIdentity?
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
    /// Insertion log for O(1) amortised oldest-first eviction. Each store
    /// appends `(path, sequence)`; a log record is live only while the stored
    /// entry still carries that sequence, so re-stores and invalidations never
    /// require searching the log.
    private var insertionLog: [(path: String, sequence: UInt64)] = []
    private var insertionHead = 0
    private var nextSequence: UInt64 = 0
    /// Explicit approvals are bound to the file that was reviewed, not merely
    /// to a reusable pathname. Replacing or modifying the file invalidates the
    /// approval on the next authorization attempt.
    private var oneTimeAllowances: [String: OneTimeFileAllowance] = [:]
    private let lock = NSLock()

    // MARK: - Public API

    /// Returns a valid (non-expired) entry for `path`, or `nil` if absent /
    /// stale / describing different content.
    ///
    /// - Parameter identity: The file's current identity. When supplied, an
    ///   entry recorded for a different inode, size, or modification time is
    ///   discarded — the file changed after it was scanned.
    func lookup(path: String, identity: FileIdentity? = nil) -> Entry? {
        lock.lock()
        defer { lock.unlock() }

        guard let entry = store[path] else { return nil }
        guard entry.expiry > Date() else {
            store.removeValue(forKey: path)
            return nil
        }
        if let identity, let recorded = entry.identity, identity != recorded {
            store.removeValue(forKey: path)
            return nil
        }
        return entry
    }

    /// Consumes an explicit user approval for the next authorization involving
    /// this path. Consuming it prevents an accidental permanent bypass.
    func consumeOneTimeAllowance(path: String, identity: FileIdentity) -> Bool {
        lock.withLock {
            guard let allowance = oneTimeAllowances.removeValue(forKey: path) else {
                return false
            }
            return allowance.permits(identity)
        }
    }

    /// Allows the next authorization and clears any stale deny verdict now,
    /// rather than waiting for the normal cache TTL.
    @discardableResult
    func allowOnce(
        reviewedPath: String,
        authorizationPath: String,
        currentIdentity: FileIdentity
    ) -> Bool {
        lock.withLock {
            guard let entry = store[reviewedPath] ?? store[authorizationPath],
                  entry.isThreat,
                  ReviewedFileAllowancePolicy.permits(
                    reviewed: entry.identity,
                    current: currentIdentity
                  ) else {
                oneTimeAllowances.removeValue(forKey: reviewedPath)
                oneTimeAllowances.removeValue(forKey: authorizationPath)
                return false
            }
            oneTimeAllowances[authorizationPath] = OneTimeFileAllowance(identity: currentIdentity)
            store.removeValue(forKey: reviewedPath)
            store.removeValue(forKey: authorizationPath)
            return true
        }
    }

    /// Promotes the current cached finding to an explicit user-selected block.
    /// Returns false when no reviewed finding exists for the path.
    func blockReviewedFinding(path: String) -> Bool {
        lock.withLock {
            guard let entry = store[path], entry.isThreat else { return false }
            store[path] = Entry(
                sequence: entry.sequence,
                identity: entry.identity,
                hash: entry.hash,
                isThreat: true,
                mayBlock: true,
                threatName: entry.threatName,
                threatFamily: entry.threatFamily,
                expiry: entry.expiry
            )
            oneTimeAllowances.removeValue(forKey: path)
            return true
        }
    }

    /// Stores a scan result for `path` with the given TTL (defaults to `defaultTTL`).
    func store(
        path: String,
        identity: FileIdentity? = nil,
        hash: String,
        isThreat: Bool,
        mayBlock: Bool = false,
        threatName: String? = nil,
        threatFamily: String? = nil,
        ttl: TimeInterval = defaultTTL
    ) {
        var entry = Entry(
            identity: identity,
            hash: hash,
            isThreat: isThreat,
            mayBlock: mayBlock,
            threatName: threatName,
            threatFamily: threatFamily,
            expiry: Date().addingTimeInterval(ttl)
        )

        lock.lock()
        defer { lock.unlock() }
        nextSequence &+= 1
        entry.sequence = nextSequence
        store[path] = entry
        insertionLog.append((path, nextSequence))

        // Evict the oldest live insertions first.
        while store.count > Self.maxEntries, insertionHead < insertionLog.count {
            let record = insertionLog[insertionHead]
            insertionHead += 1
            if store[record.path]?.sequence == record.sequence {
                store.removeValue(forKey: record.path)
            }
        }

        // Keep the log proportional to the live cache under churn
        // (the same path re-scanned many times, or frequent invalidation).
        if insertionLog.count - insertionHead > 2 * Self.maxEntries || insertionHead > Self.maxEntries {
            insertionLog = insertionLog[insertionHead...].filter {
                store[$0.path]?.sequence == $0.sequence
            }
            insertionHead = 0
        }
    }

    /// Removes the entry for `path`, forcing a fresh scan on next access.
    func invalidate(path: String) {
        lock.withLock { _ = store.removeValue(forKey: path) }
    }

    /// Removes all entries from the cache.
    func invalidateAll() {
        lock.withLock {
            store.removeAll()
            insertionLog.removeAll()
            insertionHead = 0
        }
    }
}
