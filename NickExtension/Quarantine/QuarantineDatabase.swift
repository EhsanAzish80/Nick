// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation
import SQLite3
import os

// MARK: - QuarantineDatabase

/// SQLite-backed persistence for `QuarantineRecord` objects.
///
/// Schema lives in `/Library/Application Support/com.ehsanazish.nick/quarantine.db`.
/// All public methods are thread-safe — concurrent access is serialised via `NSLock`.
final class QuarantineDatabase {

    // MARK: - Private

    private static let logger = Logger(
        subsystem: "com.ehsanazish.nick.NickExtension",
        category: "QuarantineDB"
    )

    private var db: OpaquePointer?
    private let lock = NSLock()
    private let iso  = ISO8601DateFormatter()

    // MARK: - Init

    init(dbPath: String) {
        let flags = SQLITE_OPEN_CREATE | SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX
        guard sqlite3_open_v2(dbPath, &db, flags, nil) == SQLITE_OK else {
            Self.logger.error("Failed to open quarantine DB at \(dbPath)")
            return
        }
        sqlite3_exec(db, "PRAGMA journal_mode=WAL;", nil, nil, nil)
        createTable()
    }

    deinit { sqlite3_close(db) }

    // MARK: - Schema

    private func createTable() {
        let sql = """
            CREATE TABLE IF NOT EXISTS quarantine (
                id               TEXT PRIMARY KEY,
                original_path    TEXT NOT NULL,
                quarantined_path TEXT NOT NULL,
                hash             TEXT NOT NULL,
                threat_name      TEXT NOT NULL,
                severity         TEXT NOT NULL,
                quarantined_at   TEXT NOT NULL,
                process_path     TEXT NOT NULL,
                pid              INTEGER NOT NULL
            );
        """
        sqlite3_exec(db, sql, nil, nil, nil)
    }

    // MARK: - CRUD

    func insert(record: QuarantineRecord) {
        lock.lock(); defer { lock.unlock() }

        let sql = """
            INSERT OR REPLACE INTO quarantine
            (id, original_path, quarantined_path, hash, threat_name,
             severity, quarantined_at, process_path, pid)
            VALUES (?,?,?,?,?,?,?,?,?)
        """
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else { return }
        defer { sqlite3_finalize(stmt) }

        sqlite3_bind_text(stmt, 1, record.id.uuidString,             -1, nil)
        sqlite3_bind_text(stmt, 2, record.originalPath,              -1, nil)
        sqlite3_bind_text(stmt, 3, record.quarantinedPath,           -1, nil)
        sqlite3_bind_text(stmt, 4, record.hash,                      -1, nil)
        sqlite3_bind_text(stmt, 5, record.threatName,                -1, nil)
        sqlite3_bind_text(stmt, 6, record.severity,                  -1, nil)
        sqlite3_bind_text(stmt, 7, iso.string(from: record.quarantinedAt), -1, nil)
        sqlite3_bind_text(stmt, 8, record.processPath,               -1, nil)
        sqlite3_bind_int (stmt, 9, record.pid)
        sqlite3_step(stmt)
    }

    func get(id: UUID) -> QuarantineRecord? {
        lock.lock(); defer { lock.unlock() }

        let sql = "SELECT * FROM quarantine WHERE id = ? LIMIT 1"
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else { return nil }
        defer { sqlite3_finalize(stmt) }

        sqlite3_bind_text(stmt, 1, id.uuidString, -1, nil)
        guard sqlite3_step(stmt) == SQLITE_ROW else { return nil }
        return decodeRow(stmt)
    }

    func listAll() -> [QuarantineRecord] {
        lock.lock(); defer { lock.unlock() }

        let sql = "SELECT * FROM quarantine ORDER BY quarantined_at DESC"
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else { return [] }
        defer { sqlite3_finalize(stmt) }

        var records: [QuarantineRecord] = []
        while sqlite3_step(stmt) == SQLITE_ROW {
            if let r = decodeRow(stmt) { records.append(r) }
        }
        return records
    }

    func delete(id: UUID) {
        lock.lock(); defer { lock.unlock() }

        let sql = "DELETE FROM quarantine WHERE id = ?"
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else { return }
        defer { sqlite3_finalize(stmt) }

        sqlite3_bind_text(stmt, 1, id.uuidString, -1, nil)
        sqlite3_step(stmt)
    }

    // MARK: - Private

    private func decodeRow(_ stmt: OpaquePointer?) -> QuarantineRecord? {
        guard let s = stmt,
              let col0 = sqlite3_column_text(s, 0),
              let id   = UUID(uuidString: String(cString: col0))
        else { return nil }

        return QuarantineRecord(
            id:               id,
            originalPath:     String(cString: sqlite3_column_text(s, 1)),
            quarantinedPath:  String(cString: sqlite3_column_text(s, 2)),
            hash:             String(cString: sqlite3_column_text(s, 3)),
            threatName:       String(cString: sqlite3_column_text(s, 4)),
            severity:         String(cString: sqlite3_column_text(s, 5)),
            quarantinedAt:    iso.date(from: String(cString: sqlite3_column_text(s, 6))) ?? Date(),
            processPath:      String(cString: sqlite3_column_text(s, 7)),
            pid:              sqlite3_column_int(s, 8)
        )
    }
}
