// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation

/// Root-owned, file-backed storage used by the Endpoint Security extension.
/// The payload is opaque here so the privileged process does not duplicate the
/// app's incident model. All access is serialized and revisions prevent an
/// older asynchronous app write from replacing newer evidence.
final class PrivilegedIncidentFileStore: @unchecked Sendable {
    enum StoreError: Error {
        case invalidRecord
        case payloadTooLarge
        case unsafeStoragePath
    }

    static let maximumPayloadBytes = 16 * 1_024 * 1_024

    private let fileURL: URL
    private let directoryURL: URL
    private let queue = DispatchQueue(label: "com.ehsanazish.nick.incident-store")
    private let fileManager: FileManager

    init(
        fileURL: URL = URL(
            fileURLWithPath: "/Library/Application Support/com.ehsanazish.nick/state/incidents.json"
        ),
        fileManager: FileManager = .default
    ) {
        self.fileURL = fileURL
        self.directoryURL = fileURL.deletingLastPathComponent()
        self.fileManager = fileManager
    }

    func load() -> Data {
        queue.sync {
            guard let record = try? loadRecord() else { return Data() }
            return (try? JSONEncoder().encode(record)) ?? Data()
        }
    }

    func migrate(payload: Data) -> (accepted: Bool, record: Data) {
        queue.sync {
            do {
                try validate(payload: payload)
                if let existing = try loadRecord() {
                    return (true, (try? JSONEncoder().encode(existing)) ?? Data())
                }
                let record = PrivilegedIncidentStoreRecord(revision: 1, payload: payload)
                try write(record)
                return (true, try JSONEncoder().encode(record))
            } catch {
                let current = (try? loadRecord()).flatMap { try? JSONEncoder().encode($0) }
                return (false, current ?? Data())
            }
        }
    }

    func replace(payload: Data, expectedRevision: UInt64) -> (accepted: Bool, record: Data) {
        queue.sync {
            do {
                try validate(payload: payload)
                guard let existing = try loadRecord(), existing.revision == expectedRevision else {
                    let current = (try? loadRecord()).flatMap { try? JSONEncoder().encode($0) }
                    return (false, current ?? Data())
                }
                if existing.payload == payload {
                    return (true, try JSONEncoder().encode(existing))
                }
                let record = PrivilegedIncidentStoreRecord(
                    revision: existing.revision &+ 1,
                    payload: payload
                )
                try write(record)
                return (true, try JSONEncoder().encode(record))
            } catch {
                return (false, Data())
            }
        }
    }

    private func validate(payload: Data) throws {
        guard payload.count <= Self.maximumPayloadBytes else { throw StoreError.payloadTooLarge }
        guard (try? JSONSerialization.jsonObject(with: payload)) != nil else {
            throw StoreError.invalidRecord
        }
    }

    private func loadRecord() throws -> PrivilegedIncidentStoreRecord? {
        guard fileManager.fileExists(atPath: fileURL.path) else { return nil }
        let values = try fileURL.resourceValues(forKeys: [.isSymbolicLinkKey, .isRegularFileKey])
        guard values.isSymbolicLink != true, values.isRegularFile == true else {
            throw StoreError.unsafeStoragePath
        }
        let data = try Data(contentsOf: fileURL, options: .mappedIfSafe)
        let record = try JSONDecoder().decode(PrivilegedIncidentStoreRecord.self, from: data)
        guard record.schemaVersion == PrivilegedIncidentStoreRecord.currentSchemaVersion else {
            throw StoreError.invalidRecord
        }
        try validate(payload: record.payload)
        return record
    }

    private func write(_ record: PrivilegedIncidentStoreRecord) throws {
        try prepareDirectory()
        let encoded = try JSONEncoder().encode(record)
        try encoded.write(to: fileURL, options: [.atomic])
        try fileManager.setAttributes([.posixPermissions: 0o600], ofItemAtPath: fileURL.path)
    }

    private func prepareDirectory() throws {
        let supportURL = directoryURL.deletingLastPathComponent()
        if fileManager.fileExists(atPath: supportURL.path) {
            let values = try supportURL.resourceValues(forKeys: [.isSymbolicLinkKey, .isDirectoryKey])
            guard values.isSymbolicLink != true, values.isDirectory == true else {
                throw StoreError.unsafeStoragePath
            }
        } else {
            try fileManager.createDirectory(at: supportURL, withIntermediateDirectories: true)
        }
        try fileManager.setAttributes([.posixPermissions: 0o755], ofItemAtPath: supportURL.path)
        if fileManager.fileExists(atPath: directoryURL.path) {
            let values = try directoryURL.resourceValues(forKeys: [.isSymbolicLinkKey, .isDirectoryKey])
            guard values.isSymbolicLink != true, values.isDirectory == true else {
                throw StoreError.unsafeStoragePath
            }
        } else {
            try fileManager.createDirectory(at: directoryURL, withIntermediateDirectories: false)
        }
        try fileManager.setAttributes([.posixPermissions: 0o700], ofItemAtPath: directoryURL.path)
    }
}
