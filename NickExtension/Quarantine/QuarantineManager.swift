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

        var originalStat = stat()
        guard lstat(filePath, &originalStat) == 0,
              originalStat.st_mode & S_IFMT == S_IFREG else {
            Self.logger.warning("Quarantine refused because the selected item is not a regular file")
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
            pid:              pid,
            originalOwnerID:  originalStat.st_uid,
            originalGroupID:  originalStat.st_gid,
            originalPermissions: UInt16(originalStat.st_mode & 0o7777)
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
              URL(fileURLWithPath: source).deletingLastPathComponent().path
                == URL(fileURLWithPath: vaultPath).standardizedFileURL.path,
              destination.hasPrefix("/"),
              !destination.hasPrefix("/System/"),
              !destination.hasPrefix("/usr/"),
              !fm.fileExists(atPath: destination) else {
            Self.logger.error("Restore refused because the source or destination is unsafe")
            return false
        }

        let sourceName = URL(fileURLWithPath: source).lastPathComponent
        let destinationName = URL(fileURLWithPath: destination).lastPathComponent
        let vaultFD = open(vaultPath, O_RDONLY | O_DIRECTORY | O_NOFOLLOW)
        guard vaultFD >= 0 else { return false }
        defer { close(vaultFD) }

        let sourceFD = openat(vaultFD, sourceName, O_RDONLY | O_NOFOLLOW)
        guard sourceFD >= 0 else { return false }
        var sourceStat = stat()
        let sourceIsRegular = fstat(sourceFD, &sourceStat) == 0
            && sourceStat.st_mode & S_IFMT == S_IFREG
        close(sourceFD)
        guard sourceIsRegular,
              let destinationParentFD = openSafeDestinationParent(for: destination) else {
            Self.logger.error("Restore refused because a path component is not a real directory")
            return false
        }
        defer { close(destinationParentFD) }

        var existingDestination = stat()
        guard fstatat(
            destinationParentFD,
            destinationName,
            &existingDestination,
            AT_SYMLINK_NOFOLLOW
        ) != 0,
              errno == ENOENT else {
            Self.logger.error("Restore refused because the destination already exists")
            return false
        }

        var movedToDestination = false
        do {
            guard renameat(vaultFD, sourceName, destinationParentFD, destinationName) == 0 else {
                throw CocoaError(.fileWriteUnknown)
            }
            movedToDestination = true

            // A move preserves ownership, including for legacy records. New
            // records additionally persist the original IDs so restoration is
            // explicit. Legacy records use the vault file's retained owner/group
            // and a conservative non-executable 0600 mode.
            let ownerID = record.originalOwnerID ?? sourceStat.st_uid
            let groupID = record.originalGroupID ?? sourceStat.st_gid
            let restoredFD = openat(
                destinationParentFD,
                destinationName,
                O_RDONLY | O_NOFOLLOW
            )
            guard restoredFD >= 0 else { throw CocoaError(.fileReadNoPermission) }
            defer { close(restoredFD) }
            guard fchown(restoredFD, ownerID, groupID) == 0 else {
                throw CocoaError(.fileWriteUnknown)
            }
            let restoredMode = mode_t(record.originalPermissions ?? 0o600)
            guard fchmod(restoredFD, restoredMode) == 0 else {
                throw CocoaError(.fileWriteUnknown)
            }

            // Restored threats remain marked as downloaded/untrusted so
            // Gatekeeper and supporting apps can warn before opening them.
            let quarantineValue = "0081;\(Int(Date().timeIntervalSince1970));Nick;"
            let xattrResult = quarantineValue.withCString { value in
                fsetxattr(
                    restoredFD,
                    "com.apple.quarantine",
                    value,
                    strlen(value),
                    0,
                    0
                )
            }
            guard xattrResult == 0 else { throw CocoaError(.fileWriteUnknown) }

            let metaPath = metadataPath(for: record)
            try? fm.removeItem(atPath: metaPath)

            database.delete(id: id)
            Self.logger.info("Restored '\(record.originalPath)'")
            return true
        } catch {
            if movedToDestination {
                _ = renameat(destinationParentFD, destinationName, vaultFD, sourceName)
                let restoredVaultFD = openat(vaultFD, sourceName, O_RDONLY | O_NOFOLLOW)
                if restoredVaultFD >= 0 {
                    _ = fchmod(restoredVaultFD, 0o000)
                    close(restoredVaultFD)
                }
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

    /// Creates missing destination folders one component at a time and refuses
    /// any existing symbolic link. This prevents a restore path from being
    /// redirected outside the location recorded when the file was quarantined.
    private func openSafeDestinationParent(for destination: String) -> Int32? {
        let parent = URL(fileURLWithPath: destination).deletingLastPathComponent().path
        let components = URL(fileURLWithPath: parent).pathComponents
        var directoryFD = open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW)
        guard directoryFD >= 0 else { return nil }

        for component in components where component != "/" {
            var childFD = openat(
                directoryFD,
                component,
                O_RDONLY | O_DIRECTORY | O_NOFOLLOW
            )
            if childFD < 0, errno == ENOENT {
                guard mkdirat(directoryFD, component, 0o755) == 0 else {
                    close(directoryFD)
                    return nil
                }
                childFD = openat(
                    directoryFD,
                    component,
                    O_RDONLY | O_DIRECTORY | O_NOFOLLOW
                )
            }
            guard childFD >= 0 else {
                close(directoryFD)
                return nil
            }
            close(directoryFD)
            directoryFD = childFD
        }
        return directoryFD
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
