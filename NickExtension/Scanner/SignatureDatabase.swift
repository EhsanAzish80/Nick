// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation
import SQLite3
import os

// MARK: - SignatureDatabase

/// SQLite-backed store for known-malware SHA-256 hashes.
///
/// The database lives at a path writable by the extension (root-owned):
/// `/Library/Application Support/com.ehsanazish.nick/signatures.db`
///
/// **Schema:**
/// ```sql
/// CREATE TABLE signatures (
///     hash      TEXT PRIMARY KEY,   -- lowercase hex SHA-256
///     name      TEXT NOT NULL,      -- e.g. "Trojan.Mac.Genieo"
///     family    TEXT NOT NULL,      -- e.g. "Trojan"
///     severity  TEXT NOT NULL,      -- "low" | "medium" | "high" | "critical"
///     added_at  TEXT NOT NULL       -- ISO-8601
/// )
/// ```
///
/// Phase 6 (cloud intel) pushes updates via XPC; the extension calls
/// `upsert(hash:name:family:severity:)` to merge new signatures without
/// rebuilding the table.
///
/// All public methods are safe to call from any thread. An internal `NSLock`
/// serialises concurrent reads and writes.
final class SignatureDatabase {

    // MARK: - Types

    struct ThreatMatch {
        let hash: String
        let name: String
        let family: String
        let severity: String   // raw string — maps to ESEvent severity at the caller
    }

    // MARK: - Constants

    static let dbDirectory = "/Library/Application Support/com.ehsanazish.nick"
    static let dbPath      = "\(dbDirectory)/signatures.db"

    // MARK: - Private

    private static let logger = Logger(
        subsystem: "com.ehsanazish.nick.NickExtension",
        category: "SignatureDatabase"
    )

    private var db: OpaquePointer?
    private let lock = NSLock()

    // MARK: - Init

    /// Opens (or creates) the signatures database.
    ///
    /// - Parameter path: Path to the SQLite file. Defaults to `SignatureDatabase.dbPath`.
    init(path: String = SignatureDatabase.dbPath) {
        ensureDirectory(at: SignatureDatabase.dbDirectory)

        if sqlite3_open(path, &db) != SQLITE_OK {
            let msg = db.map { String(cString: sqlite3_errmsg($0)) } ?? "unknown error"
            Self.logger.critical("Failed to open signature database at \(path): \(msg)")
            return
        }

        applyPragmas()
        createTableIfNeeded()
        Self.logger.info("Signature database ready at \(path)")
    }

    deinit {
        sqlite3_close(db)
    }

    // MARK: - Public API

    /// Looks up `hash` (lowercase SHA-256 hex) in the database.
    ///
    /// - Returns: `ThreatMatch` if the hash is known malware; `nil` otherwise.
    /// - Complexity: O(1) — indexed by primary key.
    func lookup(hash: String) -> ThreatMatch? {
        lock.lock()
        defer { lock.unlock() }

        guard let db else { return nil }

        let sql = "SELECT hash, name, family, severity FROM signatures WHERE hash = ? LIMIT 1;"
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else { return nil }
        defer { sqlite3_finalize(stmt) }

        sqlite3_bind_text(stmt, 1, hash, -1, nil)
        guard sqlite3_step(stmt) == SQLITE_ROW else { return nil }

        return ThreatMatch(
            hash:     columnText(stmt, 0),
            name:     columnText(stmt, 1),
            family:   columnText(stmt, 2),
            severity: columnText(stmt, 3)
        )
    }

    /// Inserts or replaces a signature entry.
    ///
    /// Thread-safe. Used by Phase 6 cloud intel XPC handler.
    func upsert(hash: String, name: String, family: String, severity: String) {
        lock.lock()
        defer { lock.unlock() }

        guard let db else { return }

        let sql = """
            INSERT OR REPLACE INTO signatures (hash, name, family, severity, added_at)
            VALUES (?, ?, ?, ?, ?);
        """
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else { return }
        defer { sqlite3_finalize(stmt) }

        let now = ISO8601DateFormatter().string(from: Date())
        sqlite3_bind_text(stmt, 1, hash,     -1, nil)
        sqlite3_bind_text(stmt, 2, name,     -1, nil)
        sqlite3_bind_text(stmt, 3, family,   -1, nil)
        sqlite3_bind_text(stmt, 4, severity, -1, nil)
        sqlite3_bind_text(stmt, 5, now,      -1, nil)

        if sqlite3_step(stmt) != SQLITE_DONE {
            let msg = String(cString: sqlite3_errmsg(db))
            Self.logger.error("upsert failed for hash \(hash): \(msg)")
        }
    }

    /// Bulk-inserts signatures from an array. Uses a single transaction for speed.
    func bulkUpsert(_ entries: [(hash: String, name: String, family: String, severity: String)]) {
        lock.lock()
        defer { lock.unlock() }

        guard let db else { return }

        sqlite3_exec(db, "BEGIN;", nil, nil, nil)

        let sql = """
            INSERT OR REPLACE INTO signatures (hash, name, family, severity, added_at)
            VALUES (?, ?, ?, ?, ?);
        """
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            sqlite3_exec(db, "ROLLBACK;", nil, nil, nil)
            return
        }
        defer { sqlite3_finalize(stmt) }

        let now = ISO8601DateFormatter().string(from: Date())
        for entry in entries {
            sqlite3_bind_text(stmt, 1, entry.hash,     -1, nil)
            sqlite3_bind_text(stmt, 2, entry.name,     -1, nil)
            sqlite3_bind_text(stmt, 3, entry.family,   -1, nil)
            sqlite3_bind_text(stmt, 4, entry.severity, -1, nil)
            sqlite3_bind_text(stmt, 5, now,            -1, nil)
            sqlite3_step(stmt)
            sqlite3_reset(stmt)
        }

        sqlite3_exec(db, "COMMIT;", nil, nil, nil)
        Self.logger.info("Bulk-inserted \(entries.count) signature(s)")
    }

    /// Returns the total number of signatures in the database.
    var count: Int {
        lock.lock()
        defer { lock.unlock() }

        guard let db else { return 0 }
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM signatures;", -1, &stmt, nil) == SQLITE_OK else { return 0 }
        defer { sqlite3_finalize(stmt) }

        return sqlite3_step(stmt) == SQLITE_ROW ? Int(sqlite3_column_int64(stmt, 0)) : 0
    }

    // MARK: - Private Helpers

    private func applyPragmas() {
        guard let db else { return }
        // WAL mode for concurrent reads; normal sync for performance (data loss on crash is tolerable here)
        sqlite3_exec(db, "PRAGMA journal_mode=WAL;",       nil, nil, nil)
        sqlite3_exec(db, "PRAGMA synchronous=NORMAL;",     nil, nil, nil)
        sqlite3_exec(db, "PRAGMA cache_size=-8000;",       nil, nil, nil) // ~8 MB page cache
        sqlite3_exec(db, "PRAGMA temp_store=MEMORY;",      nil, nil, nil)
    }

    private func createTableIfNeeded() {
        guard let db else { return }
        let sql = """
            CREATE TABLE IF NOT EXISTS signatures (
                hash      TEXT PRIMARY KEY,
                name      TEXT NOT NULL,
                family    TEXT NOT NULL,
                severity  TEXT NOT NULL,
                added_at  TEXT NOT NULL
            );
        """
        sqlite3_exec(db, sql, nil, nil, nil)
    }

    private func ensureDirectory(at path: String) {
        var isDir: ObjCBool = false
        if !FileManager.default.fileExists(atPath: path, isDirectory: &isDir) || !isDir.boolValue {
            try? FileManager.default.createDirectory(
                atPath: path,
                withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o755]
            )
        }
    }

    private func columnText(_ stmt: OpaquePointer?, _ index: Int32) -> String {
        guard let stmt, let ptr = sqlite3_column_text(stmt, index) else { return "" }
        return String(cString: ptr)
    }
}
