// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation
import os

// MARK: - QuarantineManager

/// Moves detected threat files into a locked vault, records metadata in a
/// SQLite database, and provides restore / permanent-delete operations.
///
/// **Vault:** `/Library/Application Support/com.ehsanazish.nick/Quarantine/`
///
/// Each quarantined file is:
/// - Renamed to `<sha256>-<record-id>.quarantine` (prevents accidental execution)
/// - Chmod'd to `0o000` (no read/write/execute for anyone)
/// - All extended attributes stripped via `removexattr(2)`
/// - A companion `<sha256>-<record-id>.meta.json` written in the same directory
/// - Persisted in `QuarantineDatabase` for display and restore operations
final class QuarantineManager {

    // MARK: - Private

    private static let logger = Logger(
        subsystem: "com.ehsanazish.nick.NickExtension",
        category: "QuarantineManager"
    )

    private let vaultPath: String
    private let database:  QuarantineDatabase

    // MARK: - Init

    /// - Parameter supportDir: The `com.ehsanazish.nick` app-support directory.
    ///   Both the vault subfolder and the SQLite DB are created here.
    init(supportDir: String) {
        vaultPath = (supportDir as NSString).appendingPathComponent("Quarantine")
        let dbPath = (supportDir as NSString).appendingPathComponent("quarantine.db")

        database = QuarantineDatabase(dbPath: dbPath)

        // Ensure vault directory exists (root-owned, 0700)
        try? FileManager.default.createDirectory(
            atPath: vaultPath,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
    }

    // MARK: - Public API

    /// Moves `filePath` to the vault and records a `QuarantineRecord`.
    ///
    /// - Returns: The `QuarantineRecord` on success; `nil` if the file could
    ///   not be moved. A failed quarantine never deletes the original file.
    @discardableResult
    func quarantine(
        filePath:    String,
        hash:        String,
        threatName:  String,
        severity:    String,
        processPath: String,
        pid:         Int32
    ) -> QuarantineRecord? {
        let fm = FileManager.default
        let normalizedHash = hash.lowercased()
        guard normalizedHash.count == 64,
              normalizedHash.allSatisfy({ character in character.isHexDigit }) else {
            Self.logger.error("Quarantine refused because the SHA-256 hash is invalid")
            return nil
        }
        guard fm.fileExists(atPath: filePath) else {
            Self.logger.warning("Quarantine skipped — file no longer exists: \(filePath)")
            return nil
        }

        let recordID = UUID()
        let vaultName = "\(normalizedHash)-\(recordID.uuidString)"
        let quarantinedPath = (vaultPath as NSString).appendingPathComponent("\(vaultName).quarantine")
        let metaPath = (vaultPath as NSString).appendingPathComponent("\(vaultName).meta.json")

        let record = QuarantineRecord(
            id:               recordID,
            originalPath:     filePath,
            quarantinedPath:  quarantinedPath,
            hash:             normalizedHash,
            threatName:       threatName,
            severity:         severity,
            quarantinedAt:    Date(),
            processPath:      processPath,
            pid:              pid
        )

        do {
            // Every record receives a unique vault path, so identical files never
            // overwrite earlier evidence or share a stale database reference.
            try fm.moveItem(atPath: filePath, toPath: quarantinedPath)

            // Strip attributes while the owner can still access the file, then
            // lock the vault copy against reading, writing, and execution.
            stripXattrs(path: quarantinedPath)
            try fm.setAttributes([.posixPermissions: 0o000], ofItemAtPath: quarantinedPath)

            // Write companion metadata (allows restore even if DB is lost)
            let metaData = try JSONEncoder().encode(record)
            try metaData.write(to: URL(fileURLWithPath: metaPath), options: .atomic)

            database.insert(record: record)

            Self.logger.info("Quarantined '\(filePath)' → .\(vaultName).quarantine. (threat: \(threatName))")
            return record

        } catch {
            Self.logger.error("Quarantine failed for '\(filePath)': \(error.localizedDescription)")
            // Quarantine is fail-safe: if the move succeeded but a later vault step
            // failed, put the original back whenever possible. Never delete it.
            if fm.fileExists(atPath: quarantinedPath), !fm.fileExists(atPath: filePath) {
                try? fm.setAttributes([.posixPermissions: 0o600], ofItemAtPath: quarantinedPath)
                try? fm.moveItem(atPath: quarantinedPath, toPath: filePath)
            }
            try? fm.removeItem(atPath: metaPath)
            return nil
        }
    }

    /// Restores a quarantined file to its original path.
    ///
    /// - Returns: `true` on success.
    func restore(id: UUID) -> Bool {
        guard let record = database.get(id: id) else { return false }
        let fm = FileManager.default
        let vaultRoot = URL(fileURLWithPath: vaultPath).standardizedFileURL.path + "/"
        let source = URL(fileURLWithPath: record.quarantinedPath).standardizedFileURL.path
        let destination = URL(fileURLWithPath: record.originalPath).standardizedFileURL.path

        guard source.hasPrefix(vaultRoot),
              fm.fileExists(atPath: source),
              destination.hasPrefix("/"),
              !destination.hasPrefix("/System/"),
              !destination.hasPrefix("/usr/"),
              !fm.fileExists(atPath: destination) else {
            Self.logger.error("Restore refused because the source or destination is unsafe")
            return false
        }

        do {
            // Re-enable read/write so the file can be moved
            try fm.setAttributes([.posixPermissions: 0o600], ofItemAtPath: source)
            try fm.createDirectory(
                at: URL(fileURLWithPath: destination).deletingLastPathComponent(),
                withIntermediateDirectories: true
            )
            try fm.moveItem(atPath: source, toPath: destination)

            // Restored threats remain marked as downloaded/untrusted so
            // Gatekeeper and supporting apps can warn before opening them.
            let quarantineValue = "0081;\(Int(Date().timeIntervalSince1970));Nick;"
            quarantineValue.withCString { value in
                _ = setxattr(
                    destination,
                    "com.apple.quarantine",
                    value,
                    strlen(value),
                    0,
                    XATTR_NOFOLLOW
                )
            }

            let metaPath = metadataPath(for: record)
            try? fm.removeItem(atPath: metaPath)

            database.delete(id: id)
            Self.logger.info("Restored '\(record.originalPath)'")
            return true
        } catch {
            if fm.fileExists(atPath: source) {
                try? fm.setAttributes([.posixPermissions: 0o000], ofItemAtPath: source)
            }
            Self.logger.error("Restore failed: \(error.localizedDescription)")
            return false
        }
    }

    /// Permanently deletes a quarantined file from the vault.
    ///
    /// - Returns: `true` on success.
    func deletePermanently(id: UUID) -> Bool {
        guard let record = database.get(id: id) else { return false }
        let fm = FileManager.default

        do {
            if fm.fileExists(atPath: record.quarantinedPath) {
                // Need at least owner-write to delete. Missing vault files are
                // treated as already deleted and their stale record is cleared.
                try fm.setAttributes([.posixPermissions: 0o600], ofItemAtPath: record.quarantinedPath)
                try fm.removeItem(atPath: record.quarantinedPath)
            }

            removeRecordMetadata(record)
            Self.logger.info("Permanently deleted quarantine entry \(id)")
            return true
        } catch {
            Self.logger.error("Permanent delete failed: \(error.localizedDescription)")
            return false
        }
    }

    /// Returns all quarantined records, newest first. Entries whose vault file
    /// no longer exists are reconciled out of the database so the UI never offers
    /// restore or delete actions that cannot succeed.
    func listQuarantined() -> [QuarantineRecord] {
        let fm = FileManager.default
        return database.listAll().filter { record in
            guard fm.fileExists(atPath: record.quarantinedPath) else {
                removeRecordMetadata(record)
                return false
            }
            return true
        }
    }

    private func removeRecordMetadata(_ record: QuarantineRecord) {
        let metaPath = metadataPath(for: record)
        try? FileManager.default.removeItem(atPath: metaPath)
        database.delete(id: record.id)
    }

    // MARK: - Private Helpers

    private func metadataPath(for record: QuarantineRecord) -> String {
        URL(fileURLWithPath: record.quarantinedPath)
            .deletingPathExtension()
            .appendingPathExtension("meta.json")
            .path
    }

    /// Strips every extended attribute from the file at `path` using BSD `removexattr(2)`.
    private func stripXattrs(path: String) {
        // First pass: measure the total name-list size
        let size = listxattr(path, nil, 0, XATTR_NOFOLLOW)
        guard size > 0 else { return }

        var buffer = [CChar](repeating: 0, count: size)
        guard listxattr(path, &buffer, size, XATTR_NOFOLLOW) > 0 else { return }

        // The list is a sequence of NUL-terminated C strings
        var offset = 0
        while offset < size {
            let namePtr = buffer.withUnsafeBufferPointer { $0.baseAddress! + offset }
            let name    = String(cString: namePtr)
            removexattr(path, name, XATTR_NOFOLLOW)
            offset += name.utf8.count + 1
        }
    }
}
