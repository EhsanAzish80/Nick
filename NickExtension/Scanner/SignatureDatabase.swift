// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation
import SQLite3
import os


/// `SQLITE_TRANSIENT`: SQLite copies the bound text immediately. Passing `nil`
/// (`SQLITE_STATIC`) told SQLite to keep using a pointer that Swift only
/// guarantees for the duration of the bind call — temporaries such as a
/// formatted date string were already freed when the statement ran.
nonisolated(unsafe) private let sqliteTransient = unsafeBitCast(-1, to: sqlite3_destructor_type.self)

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
/// A versioned catalog bundled in the signed extension seeds fresh installs.
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
    private(set) var bundledCatalogEntryCount = 0
    private(set) var bundledCatalogRetrievedAt: String?

    // MARK: - Init

    /// Opens (or creates) the signatures database.
    ///
    /// - Parameter path: Path to the SQLite file. Defaults to `SignatureDatabase.dbPath`.
    init(
        path: String = SignatureDatabase.dbPath,
        bundledCatalogURL: URL? = Bundle.main.url(
            forResource: "known-threat-hashes",
            withExtension: "json"
        )
    ) {
        ensureDirectory(at: URL(fileURLWithPath: path).deletingLastPathComponent().path)

        if sqlite3_open(path, &db) != SQLITE_OK {
            let msg = db.map { String(cString: sqlite3_errmsg($0)) } ?? "unknown error"
            Self.logger.critical("Failed to open signature database at \(path): \(msg)")
            return
        }

        applyPragmas()
        createTableIfNeeded()
        createMetadataTableIfNeeded()
        loadBundledCatalog(from: bundledCatalogURL)
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

        sqlite3_bind_text(stmt, 1, hash, -1, sqliteTransient)
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
    /// Thread-safe primitive retained for local catalog maintenance.
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
        sqlite3_bind_text(stmt, 1, hash,     -1, sqliteTransient)
        sqlite3_bind_text(stmt, 2, name,     -1, sqliteTransient)
        sqlite3_bind_text(stmt, 3, family,   -1, sqliteTransient)
        sqlite3_bind_text(stmt, 4, severity, -1, sqliteTransient)
        sqlite3_bind_text(stmt, 5, now,      -1, sqliteTransient)

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
            sqlite3_bind_text(stmt, 1, entry.hash,     -1, sqliteTransient)
            sqlite3_bind_text(stmt, 2, entry.name,     -1, sqliteTransient)
            sqlite3_bind_text(stmt, 3, entry.family,   -1, sqliteTransient)
            sqlite3_bind_text(stmt, 4, entry.severity, -1, sqliteTransient)
            sqlite3_bind_text(stmt, 5, now,            -1, sqliteTransient)
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

    private func createMetadataTableIfNeeded() {
        guard let db else { return }
        sqlite3_exec(
            db,
            "CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);",
            nil,
            nil,
            nil
        )
    }

    private func loadBundledCatalog(from url: URL?) {
        guard let db, let url else { return }
        let catalog: BundledHashCatalog
        let validEntries: [BundledHashCatalog.Entry]
        do {
            let data = try Data(contentsOf: url)
            catalog = try JSONDecoder().decode(BundledHashCatalog.self, from: data)
            validEntries = try catalog.validatedEntries()
        } catch {
            Self.logger.error("Rejected invalid bundled signature catalog: \(error.localizedDescription)")
            return
        }

        bundledCatalogEntryCount = validEntries.count
        bundledCatalogRetrievedAt = catalog.retrievedAt
        guard catalog.version > metadataInteger(for: "bundled_catalog_version") else { return }

        let databaseEntries = validEntries.map {
            ($0.hash, $0.name, $0.family, $0.severity)
        }
        guard !databaseEntries.isEmpty else {
            Self.logger.error("Bundled signature catalog contained no valid entries")
            return
        }

        bulkUpsert(databaseEntries)
        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(
            db,
            "INSERT OR REPLACE INTO metadata (key, value) VALUES ('bundled_catalog_version', ?);",
            -1,
            &statement,
            nil
        ) == SQLITE_OK else { return }
        defer { sqlite3_finalize(statement) }
        sqlite3_bind_text(statement, 1, String(catalog.version), -1, sqliteTransient)
        if sqlite3_step(statement) == SQLITE_DONE {
            Self.logger.info(
                "Loaded bundled signature catalog version \(catalog.version) with \(databaseEntries.count) entries"
            )
        }
    }

    private func metadataInteger(for key: String) -> Int {
        guard let db else { return 0 }
        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(
            db,
            "SELECT value FROM metadata WHERE key = ? LIMIT 1;",
            -1,
            &statement,
            nil
        ) == SQLITE_OK else { return 0 }
        defer { sqlite3_finalize(statement) }
        sqlite3_bind_text(statement, 1, key, -1, sqliteTransient)
        guard sqlite3_step(statement) == SQLITE_ROW else { return 0 }
        return Int(columnText(statement, 0)) ?? 0
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
