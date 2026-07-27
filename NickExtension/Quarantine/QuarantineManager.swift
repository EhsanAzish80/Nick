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
/// - Renamed to `<sha256>.quarantine` (prevents accidental execution)
/// - Chmod'd to `0o000` (no read/write/execute for anyone)
/// - All extended attributes stripped via `removexattr(2)`
/// - A companion `<sha256>.meta.json` written in the same directory
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
    ///   not be moved (it is then deleted as a safety fallback).
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
        guard fm.fileExists(atPath: filePath) else {
            Self.logger.warning("Quarantine skipped — file no longer exists: \(filePath)")
            return nil
        }

        let quarantinedPath = (vaultPath as NSString).appendingPathComponent("\(hash).quarantine")
        let metaPath        = (vaultPath as NSString).appendingPathComponent("\(hash).meta.json")

        let record = QuarantineRecord(
            id:               UUID(),
            originalPath:     filePath,
            quarantinedPath:  quarantinedPath,
            hash:             hash,
            threatName:       threatName,
            severity:         severity,
            quarantinedAt:    Date(),
            processPath:      processPath,
            pid:              pid
        )

        do {
            // Replace any previously quarantined copy with the same hash
            if fm.fileExists(atPath: quarantinedPath) {
                try fm.removeItem(atPath: quarantinedPath)
            }

            try fm.moveItem(atPath: filePath, toPath: quarantinedPath)

            // Lock down the quarantined file completely
            try fm.setAttributes([.posixPermissions: 0o000], ofItemAtPath: quarantinedPath)

            // Strip all extended attributes (e.g. com.apple.quarantine, custom xattrs)
            stripXattrs(path: quarantinedPath)

            // Write companion metadata (allows restore even if DB is lost)
            let metaData = try JSONEncoder().encode(record)
            try metaData.write(to: URL(fileURLWithPath: metaPath), options: .atomic)

            database.insert(record: record)

            Self.logger.info("Quarantined '\(filePath)' → '\(hash).quarantine' (threat: \(threatName))")
            return record

        } catch {
            Self.logger.error("Quarantine failed for '\(filePath)': \(error.localizedDescription)")
            // Last resort: delete the threat if it couldn't be quarantined
            try? fm.removeItem(atPath: filePath)
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

            let metaPath = (vaultPath as NSString).appendingPathComponent("\(record.hash).meta.json")
            try? fm.removeItem(atPath: metaPath)

            database.delete(id: id)
            Self.logger.info("Restored '\(record.originalPath)'")
            return true
        } catch {
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
            // Need at least owner-write to delete
            try fm.setAttributes([.posixPermissions: 0o600], ofItemAtPath: record.quarantinedPath)
            try fm.removeItem(atPath: record.quarantinedPath)

            let metaPath = (vaultPath as NSString).appendingPathComponent("\(record.hash).meta.json")
            try? fm.removeItem(atPath: metaPath)

            database.delete(id: id)
            Self.logger.info("Permanently deleted quarantine entry \(id)")
            return true
        } catch {
            Self.logger.error("Permanent delete failed: \(error.localizedDescription)")
            return false
        }
    }

    /// Returns all quarantined records, newest first.
    func listQuarantined() -> [QuarantineRecord] {
        database.listAll()
    }

    // MARK: - Private Helpers

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
