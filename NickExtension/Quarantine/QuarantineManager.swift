// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import CryptoKit
import Foundation
import os

struct QuarantineVolumeInfo: Equatable {
    let isReadOnly: Bool
    let name: String?
}

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

    /// Raised when the path was replaced after review but before the move.
    /// The extension turns this into a durable high-severity incident.
    var onReviewedFileSwap: ((String) -> Void)?

    // MARK: - Private

    private static let logger = Logger(
        subsystem: "com.ehsanazish.nick.NickExtension",
        category: "QuarantineManager"
    )

    private let vaultPath: String
    private let database:  QuarantineDatabase
    private let volumeInfo: (String) -> QuarantineVolumeInfo?
    private let moveItem: (String, String) throws -> Void
    private let afterMove: (String) throws -> Void

    // MARK: - Init

    /// - Parameter supportDir: The `com.ehsanazish.nick` app-support directory.
    ///   Both the vault subfolder and the SQLite DB are created here.
    init(
        supportDir: String,
        volumeInfo: @escaping (String) -> QuarantineVolumeInfo? = QuarantineManager.volumeInfo,
        moveItem: @escaping (String, String) throws -> Void = { source, destination in
            try FileManager.default.moveItem(atPath: source, toPath: destination)
        },
        afterMove: @escaping (String) throws -> Void = { _ in
            // Production quarantine needs no post-move hook; tests inject one
            // to exercise failures after the filesystem move succeeds.
        }
    ) {
        vaultPath = (supportDir as NSString).appendingPathComponent("Quarantine")
        let dbPath = (supportDir as NSString).appendingPathComponent("quarantine.db")

        database = QuarantineDatabase(dbPath: dbPath)
        self.volumeInfo = volumeInfo
        self.moveItem = moveItem
        self.afterMove = afterMove

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
    /// - Returns: The record on success or a typed failure preserving the
    ///   underlying errno/NSError evidence. A failed quarantine never deletes
    ///   the original file.
    @discardableResult
    func quarantine(
        filePath:    String,
        hash:        String,
        threatName:  String,
        severity:    String,
        processPath: String,
        pid:         Int32
    ) -> Result<QuarantineRecord, QuarantineFailure> {
        let fm = FileManager.default
        let normalizedHash = hash.lowercased()
        guard normalizedHash.count == 64,
              normalizedHash.allSatisfy({ character in character.isHexDigit }) else {
            Self.logger.error("Quarantine refused because the SHA-256 hash is invalid")
            return .failure(failure(.other, code: Int(EINVAL), path: filePath))
        }
        guard let canonicalOriginalPath = canonicalOriginalPath(for: filePath),
              fm.fileExists(atPath: canonicalOriginalPath) else {
            Self.logger.warning("Quarantine skipped — file no longer exists: \(filePath)")
            return .failure(failure(.fileGone, code: Int(ENOENT), path: filePath))
        }
        if let sourceVolume = volumeInfo(canonicalOriginalPath), sourceVolume.isReadOnly {
            Self.logger.notice("Quarantine refused before move because the source volume is read-only")
            return .failure(QuarantineFailure(
                reason: .readOnlyVolume,
                errorDomain: NSPOSIXErrorDomain,
                errorCode: Int(EROFS),
                volumeName: sourceVolume.name
            ))
        }

        let sourceFD = open(canonicalOriginalPath, O_RDONLY | O_NOFOLLOW)
        guard sourceFD >= 0 else {
            Self.logger.warning("Quarantine refused because the selected item could not be opened safely")
            return .failure(failureForCurrentErrno(path: canonicalOriginalPath))
        }
        defer { close(sourceFD) }

        var originalStat = stat()
        guard fstat(sourceFD, &originalStat) == 0 else {
            Self.logger.warning("Quarantine refused because the opened file could not be inspected")
            return .failure(failureForCurrentErrno(path: canonicalOriginalPath))
        }
        guard originalStat.st_mode & S_IFMT == S_IFREG else {
            Self.logger.warning("Quarantine refused because the reviewed path is no longer a regular file")
            return .failure(failure(.fileChanged, code: Int(EINVAL), path: canonicalOriginalPath))
        }
        guard let openedHash = sha256(fileDescriptor: sourceFD) else {
            Self.logger.warning("Quarantine refused because the reviewed file could not be hashed")
            return .failure(failureForCurrentErrno(path: canonicalOriginalPath))
        }
        let reviewedIdentity = FileIdentity(stat: originalStat)
        var pathStat = stat()
        guard lstat(canonicalOriginalPath, &pathStat) == 0 else {
            Self.logger.warning("Quarantine refused because the reviewed path could not be inspected")
            return .failure(failureForCurrentErrno(path: canonicalOriginalPath))
        }
        guard QuarantineMovePolicy.matchesReviewedFile(
                  reviewedIdentity: reviewedIdentity,
                  reviewedHash: normalizedHash,
                  currentIdentity: FileIdentity(stat: pathStat),
                  currentHash: openedHash
              ) else {
            Self.logger.warning("Quarantine refused because the file changed after review")
            return .failure(failure(.fileChanged, code: Int(ESTALE), path: canonicalOriginalPath))
        }

        let recordID = UUID()
        let vaultName = "\(normalizedHash)-\(recordID.uuidString)"
        let quarantinedPath = (vaultPath as NSString).appendingPathComponent("\(vaultName).quarantine")
        let metaPath = (vaultPath as NSString).appendingPathComponent("\(vaultName).meta.json")

        let record = QuarantineRecord(
            id:               recordID,
            originalPath:     canonicalOriginalPath,
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
            try moveItem(canonicalOriginalPath, quarantinedPath)

            // The path can be replaced between scan and move. Bind the move to
            // the file opened above, then verify its identity at the vault
            // destination before accepting it as quarantined. Re-hashing the
            // still-open source descriptor would only hash the reviewed inode
            // again and cannot establish what the pathname move selected.
            var quarantinedStat = stat()
            guard lstat(quarantinedPath, &quarantinedStat) == 0,
                  reviewedIdentity == FileIdentity(stat: quarantinedStat) else {
                onReviewedFileSwap?(canonicalOriginalPath)
                throw CocoaError(.fileWriteFileExists)
            }
            try afterMove(quarantinedPath)

            // Strip attributes while the owner can still access the file, then
            // lock the vault copy against reading, writing, and execution.
            stripXattrs(path: quarantinedPath)
            try fm.setAttributes([.posixPermissions: 0o000], ofItemAtPath: quarantinedPath)

            // Write companion metadata (allows restore even if DB is lost)
            let metaData = try JSONEncoder().encode(record)
            try metaData.write(to: URL(fileURLWithPath: metaPath), options: .atomic)

            database.insert(record: record)

            Self.logger.info("Quarantined '\(filePath)' → .\(vaultName).quarantine. (threat: \(threatName))")
            return .success(record)

        } catch {
            let typedFailure = failure(from: error, path: canonicalOriginalPath)
            Self.logger.error("Quarantine failed for '\(filePath)': \(error.localizedDescription, privacy: .public) [\(typedFailure.errorDomain, privacy: .public):\(typedFailure.errorCode)]")
            // Quarantine is fail-safe: if the move succeeded but a later vault step
            // failed, put the original back whenever possible. Never delete it.
            if fm.fileExists(atPath: quarantinedPath) {
                var currentOriginalStat = stat()
                if lstat(canonicalOriginalPath, &currentOriginalStat) == 0,
                   reviewedIdentity.device == Int64(currentOriginalStat.st_dev),
                   reviewedIdentity.inode == UInt64(currentOriginalStat.st_ino) {
                    do {
                        try fm.removeItem(atPath: quarantinedPath)
                        Self.logger.notice("Removed incomplete vault copy after quarantine failure")
                    } catch {
                        Self.logger.error("Could not remove incomplete vault copy: \(error.localizedDescription, privacy: .public)")
                    }
                } else if fm.fileExists(atPath: canonicalOriginalPath) {
                    let incompleteRecord = QuarantineRecord(
                        id: record.id,
                        originalPath: record.originalPath,
                        quarantinedPath: record.quarantinedPath,
                        hash: record.hash,
                        threatName: record.threatName,
                        severity: record.severity,
                        quarantinedAt: record.quarantinedAt,
                        processPath: record.processPath,
                        pid: record.pid,
                        originalOwnerID: record.originalOwnerID,
                        originalGroupID: record.originalGroupID,
                        originalPermissions: record.originalPermissions,
                        isIncomplete: true
                    )
                    stripXattrs(path: quarantinedPath)
                    do {
                        try fm.setAttributes([.posixPermissions: 0o000], ofItemAtPath: quarantinedPath)
                        let metaData = try JSONEncoder().encode(incompleteRecord)
                        try metaData.write(to: URL(fileURLWithPath: metaPath), options: .atomic)
                        database.insert(record: incompleteRecord)
                        Self.logger.error("Preserved incomplete quarantine record \(record.id, privacy: .public) because the original path now identifies a different file")
                    } catch {
                        Self.logger.error("Could not persist incomplete quarantine record \(record.id, privacy: .public): \(error.localizedDescription, privacy: .public)")
                    }
                } else {
                    try? fm.setAttributes([.posixPermissions: 0o600], ofItemAtPath: quarantinedPath)
                    try? fm.moveItem(atPath: quarantinedPath, toPath: canonicalOriginalPath)
                }
            }
            if database.get(id: record.id) == nil {
                try? fm.removeItem(atPath: metaPath)
            }
            return .failure(typedFailure)
        }
    }

    private func failureForCurrentErrno(path: String) -> QuarantineFailure {
        failure(reason(forPOSIXCode: errno), code: Int(errno), path: path)
    }

    private func failure(from error: Error, path: String) -> QuarantineFailure {
        let nsError = error as NSError
        let errors = errorChain(nsError)
        if let posix = errors.first(where: { $0.domain == NSPOSIXErrorDomain }) {
            return failure(reason(forPOSIXCode: Int32(posix.code)), domain: posix.domain, code: posix.code, path: path)
        }
        let reason: QuarantineFailureReason
        switch CocoaError.Code(rawValue: nsError.code) {
        case .fileWriteVolumeReadOnly: reason = .readOnlyVolume
        case .fileNoSuchFile: reason = .fileGone
        case .fileWriteNoPermission, .fileReadNoPermission: reason = .permissionDenied
        case .fileLocking, .fileWriteInapplicableStringEncoding: reason = .inUse
        default: reason = .other
        }
        return failure(reason, domain: nsError.domain, code: nsError.code, path: path)
    }

    private func errorChain(_ error: NSError) -> [NSError] {
        var result = [error]
        var current = error
        while let underlying = current.userInfo[NSUnderlyingErrorKey] as? NSError {
            result.append(underlying)
            current = underlying
        }
        return result
    }

    private func reason(forPOSIXCode code: Int32) -> QuarantineFailureReason {
        switch code {
        case EROFS: .readOnlyVolume
        case EPERM, EACCES: .permissionDenied
        case ENOENT: .fileGone
        case EBUSY, ETXTBSY: .inUse
        default: .other
        }
    }

    private func failure(
        _ reason: QuarantineFailureReason,
        domain: String = NSPOSIXErrorDomain,
        code: Int,
        path: String
    ) -> QuarantineFailure {
        let values = try? URL(fileURLWithPath: path).resourceValues(forKeys: [.volumeNameKey])
        return QuarantineFailure(
            reason: reason,
            errorDomain: domain,
            errorCode: code,
            volumeName: values?.volumeName
        )
    }

    private static func volumeInfo(path: String) -> QuarantineVolumeInfo? {
        var fileSystem = statfs()
        guard statfs(path, &fileSystem) == 0 else { return nil }
        let values = try? URL(fileURLWithPath: path).resourceValues(forKeys: [.volumeNameKey])
        return QuarantineVolumeInfo(
            isReadOnly: fileSystem.f_flags & UInt32(MNT_RDONLY) != 0,
            name: values?.volumeName
        )
    }

    private func sha256(fileDescriptor: Int32) -> String? {
        guard lseek(fileDescriptor, 0, SEEK_SET) >= 0 else { return nil }
        defer { _ = lseek(fileDescriptor, 0, SEEK_SET) }
        var hasher = SHA256()
        var buffer = [UInt8](repeating: 0, count: 1_024 * 1_024)
        while true {
            let count = read(fileDescriptor, &buffer, buffer.count)
            if count == 0 { break }
            guard count > 0 else { return nil }
            hasher.update(data: Data(buffer[0..<count]))
        }
        return hasher.finalize().map { String(format: "%02x", $0) }.joined()
    }

    /// Restores a quarantined file to its original path.
    ///
    /// - Returns: `true` on success.
    func restore(id: UUID) -> Bool {
        guard let record = database.get(id: id) else { return false }
        let fm = FileManager.default
        let vaultRoot = URL(fileURLWithPath: vaultPath).standardizedFileURL.path + "/"
        let source = URL(fileURLWithPath: record.quarantinedPath).standardizedFileURL.path
        let destination = QuarantineRestorePolicy.canonicalPathForLegacyRecord(
            record.originalPath
        )

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
        let ownerID = record.originalOwnerID ?? sourceStat.st_uid
        let groupID = record.originalGroupID ?? sourceStat.st_gid
        guard sourceIsRegular,
              let destinationParentFD = openSafeDestinationParent(
                  for: destination,
                  ownerID: ownerID,
                  groupID: groupID
              ) else {
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
            // Never restore setuid or setgid. Sticky and ordinary permission
            // bits are retained; legacy records use a non-executable fallback.
            let restoredMode = mode_t(
                QuarantineRestorePolicy.restoredPermissions(record.originalPermissions)
            )
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

    /// Resolves the existing parent while leaving the final file component
    /// untouched. This stores `/private/tmp`, `/private/var`, and `/private/etc`
    /// rather than their public symlink aliases on macOS.
    private func canonicalOriginalPath(for path: String) -> String? {
        let standardized = URL(fileURLWithPath: path).standardizedFileURL
        let parent = standardized.deletingLastPathComponent().path
        guard let resolvedParent = realpath(parent, nil) else { return nil }
        defer { free(resolvedParent) }
        return URL(fileURLWithPath: String(cString: resolvedParent))
            .appendingPathComponent(standardized.lastPathComponent)
            .path
    }

    /// Creates missing destination folders one component at a time and refuses
    /// any existing symbolic link. This prevents a restore path from being
    /// redirected outside the location recorded when the file was quarantined.
    private func openSafeDestinationParent(
        for destination: String,
        ownerID: uid_t,
        groupID: gid_t
    ) -> Int32? {
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
            let openError = errno
            if childFD < 0, openError == ENOENT {
                guard mkdirat(directoryFD, component, 0o755) == 0 else {
                    close(directoryFD)
                    return nil
                }
                childFD = openat(
                    directoryFD,
                    component,
                    O_RDONLY | O_DIRECTORY | O_NOFOLLOW
                )
                var createdDirectoryStat = stat()
                let ownershipMatches = childFD >= 0
                    && fstat(childFD, &createdDirectoryStat) == 0
                    && createdDirectoryStat.st_uid == ownerID
                    && createdDirectoryStat.st_gid == groupID
                let requestedOwner = createdDirectoryStat.st_uid == ownerID
                    ? uid_t.max
                    : ownerID
                let requestedGroup = createdDirectoryStat.st_gid == groupID
                    ? gid_t.max
                    : groupID
                let ownershipReady = ownershipMatches
                    || (childFD >= 0 && fchown(childFD, requestedOwner, requestedGroup) == 0)
                guard childFD >= 0,
                      ownershipReady else {
                    if childFD >= 0 { close(childFD) }
                    _ = unlinkat(directoryFD, component, AT_REMOVEDIR)
                    close(directoryFD)
                    return nil
                }
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
