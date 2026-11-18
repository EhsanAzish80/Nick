// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation
import os

enum ExtensionDiskWriteBudget {
    static let dailyTargetBytes: UInt64 = 50 * 1_024 * 1_024

    static func projectedDailyBytes(
        healthRecordBytes: Int,
        heartbeatInterval: TimeInterval,
        incidentSnapshotBytes: Int,
        incidentWritesPerDay: Int,
        endpointJournalBytesPerDay: Int,
        endpointCompactionBytesPerDay: Int
    ) -> UInt64 {
        let heartbeatWrites = Int(86_400 / max(heartbeatInterval, 1))
        let total = max(0, healthRecordBytes) * heartbeatWrites
            + max(0, incidentSnapshotBytes) * max(0, incidentWritesPerDay)
            + max(0, endpointJournalBytesPerDay)
            + max(0, endpointCompactionBytesPerDay)
        return UInt64(total)
    }
}

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
    private let writeObserver: ((String, Int) -> Void)?

    init(
        fileURL: URL = URL(
            fileURLWithPath: "/Library/Application Support/com.ehsanazish.nick/state/incidents.json"
        ),
        fileManager: FileManager = .default,
        writeObserver: ((String, Int) -> Void)? = nil
    ) {
        self.fileURL = fileURL
        self.directoryURL = fileURL.deletingLastPathComponent()
        self.fileManager = fileManager
        self.writeObserver = writeObserver
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
        writeObserver?(
            fileURL.lastPathComponent == "incidents.json" ? "incident-store" : "settings-store",
            encoded.count
        )
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

/// Small durable ring buffer for denied and threat-enriched ES events. Routine
/// writes stay live-only so database journals cannot create continuous disk I/O.
final class EndpointEventStore: @unchecked Sendable {
    private static let logger = Logger(subsystem: "com.ehsanazish.nick", category: "EndpointEventStore")
    private let writeObserver: ((String, Int) -> Void)?
    private let url: URL
    private let journalURL: URL
    private let queue = DispatchQueue(
        label: "com.ehsanazish.nick.NickExtension.persisted-events",
        qos: .utility
    )
    private let maximumCount = 250
    private let maximumJournalBytes: Int
    private var cachedEvents: [PersistedExtensionFinding]?
    private var journalTailChecked = false
    private struct Acknowledgement: Codable { let acknowledgedFindingIDs: Set<UUID> }

    init(path: String, legacyPath: String, maximumJournalBytes: Int = 1_024 * 1_024,
         writeObserver: ((String, Int) -> Void)? = nil) {
        self.maximumJournalBytes = maximumJournalBytes
        self.writeObserver = writeObserver
        url = URL(fileURLWithPath: path)
        journalURL = URL(fileURLWithPath: path + ".journal")
        let directory = url.deletingLastPathComponent()
        let fileManager = FileManager.default
        do {
            try fileManager.createDirectory(
                at: directory,
                withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o700]
            )
            try fileManager.setAttributes(
                [.posixPermissions: 0o700],
                ofItemAtPath: directory.path
            )

            let legacyURL = URL(fileURLWithPath: legacyPath)
            if !fileManager.fileExists(atPath: url.path),
               fileManager.fileExists(atPath: legacyURL.path) {
                try fileManager.moveItem(at: legacyURL, to: url)
            } else if fileManager.fileExists(atPath: url.path),
                      fileManager.fileExists(atPath: legacyURL.path) {
                // A prior interrupted migration may leave both files behind.
                // The protected file is authoritative; remove the stale public
                // copy so old path-bearing events do not remain readable.
                try fileManager.removeItem(at: legacyURL)
            }
            if fileManager.fileExists(atPath: url.path) {
                try fileManager.setAttributes(
                    [.posixPermissions: 0o600],
                    ofItemAtPath: url.path
                )
            }
        } catch {
            Self.logger.error(
                "Could not prepare protected event storage: \(error.localizedDescription, privacy: .public)"
            )
        }
    }

    func appendIfImportant(_ finding: PersistedExtensionFinding) {
        guard let event = try? JSONDecoder().decode(ESEvent.self, from: finding.payload),
              event.decision == .deny || event.threatName != nil else { return }
        append(finding)
    }

    func append(_ finding: PersistedExtensionFinding) {
        queue.async {
            self.appendOnQueue(finding, synchronize: false)
        }
    }

    func appendSynchronously(_ finding: PersistedExtensionFinding) {
        queue.sync { appendOnQueue(finding, synchronize: true) }
    }

    private func appendOnQueue(_ finding: PersistedExtensionFinding, synchronize: Bool) {
        var events = eventsOnQueue()
        guard !events.contains(where: { $0.id == finding.id }) else { return }
        events.append(finding)
        if events.count > maximumCount {
            events.removeFirst(events.count - maximumCount)
        }
        do {
            try prepareDirectory()
            var encoded = try JSONEncoder().encode(finding)
            encoded.append(0x0A)
            if !FileManager.default.fileExists(atPath: journalURL.path) {
                FileManager.default.createFile(atPath: journalURL.path, contents: nil, attributes: [.posixPermissions: 0o600])
            }
            let handle = try FileHandle(forWritingTo: journalURL)
            defer { try? handle.close() }
            try repairIncompleteJournalTail(handle)
            try handle.seekToEnd()
            try handle.write(contentsOf: encoded)
            if synchronize { try handle.synchronize() }
            cachedEvents = events
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: journalURL.path)
            writeObserver?("endpoint-event-journal", encoded.count)
            // URL resource values cache file size across appends. Use the
            // writer's actual offset so the journal really remains bounded.
            let journalBytes = try handle.offset()
            if journalBytes >= maximumJournalBytes {
                try compactOnQueue(events)
            }
        } catch {
            journalTailChecked = false
            Self.logger.error(
                "Could not persist important event: \(error.localizedDescription, privacy: .public)"
            )
        }
    }

    func snapshot() -> Data {
        queue.sync {
            (try? JSONEncoder().encode(eventsOnQueue())) ?? Data("[]".utf8)
        }
    }

    func removeThreats(eventIDs: Set<UUID>) {
        guard !eventIDs.isEmpty else { return }
        queue.async {
            let events = self.eventsOnQueue()
            let removed = Set(events.compactMap { finding -> UUID? in
                guard finding.kind == .threat,
                      let event = try? JSONDecoder().decode(ESEvent.self, from: finding.payload),
                      eventIDs.contains(event.id) else { return nil }
                return finding.id
            })
            // Replay and duplicate acknowledgements are common; no disk I/O.
            guard !removed.isEmpty else { return }
            do {
                try self.prepareDirectory()
                var encoded = try JSONEncoder().encode(Acknowledgement(acknowledgedFindingIDs: removed))
                encoded.append(0x0A)
                if !FileManager.default.fileExists(atPath: self.journalURL.path) {
                    FileManager.default.createFile(atPath: self.journalURL.path, contents: nil,
                                                  attributes: [.posixPermissions: 0o600])
                }
                let handle = try FileHandle(forWritingTo: self.journalURL)
                defer { try? handle.close() }
                try self.repairIncompleteJournalTail(handle)
                try handle.seekToEnd()
                try handle.write(contentsOf: encoded)
                try handle.synchronize()
                self.writeObserver?("endpoint-event-journal", encoded.count)
                let retained = events.filter { !removed.contains($0.id) }
                self.cachedEvents = retained
                let bytes = try handle.offset()
                if bytes >= self.maximumJournalBytes { try self.compactOnQueue(retained) }
            } catch {
                self.journalTailChecked = false
                Self.logger.error("Could not acknowledge persisted threats: \(error.localizedDescription, privacy: .public)")
            }
        }
    }

    private func load() -> [PersistedExtensionFinding] {
        var findings: [PersistedExtensionFinding] = []
        if let data = try? Data(contentsOf: url) {
            if let decoded = try? JSONDecoder().decode([PersistedExtensionFinding].self, from: data) {
                findings = decoded
            } else {
                // One-time migration from the 4.6.3 ESEvent-only journal.
                let oldEvents = (try? JSONDecoder().decode([ESEvent].self, from: data)) ?? []
                findings = oldEvents.compactMap { event in
                    guard let payload = try? JSONEncoder().encode(event) else { return nil }
                    return PersistedExtensionFinding(
                        id: event.id,
                        kind: .endpointEvent,
                        timestamp: event.timestamp,
                        payload: payload
                    )
                }
            }
        }
        if let journal = try? String(contentsOf: journalURL, encoding: .utf8) {
            let decoder = JSONDecoder()
            for line in journal.split(separator: "\n") {
                guard let data = line.data(using: .utf8) else { continue }
                if let ack = try? decoder.decode(Acknowledgement.self, from: data) {
                    findings.removeAll { ack.acknowledgedFindingIDs.contains($0.id) }
                    continue
                }
                guard let finding = try? decoder.decode(PersistedExtensionFinding.self, from: data) else { continue }
                if let index = findings.firstIndex(where: { $0.id == finding.id }) {
                    findings[index] = finding
                } else {
                    findings.append(finding)
                }
            }
        }
        return Array(findings.suffix(maximumCount))
    }

    private func eventsOnQueue() -> [PersistedExtensionFinding] {
        if let cachedEvents { return cachedEvents }
        let loaded = load()
        cachedEvents = loaded
        return loaded
    }

    private func repairIncompleteJournalTail(_ handle: FileHandle) throws {
        // A crash can leave a partial final JSON line. Keep completed evidence,
        // discard only the uncommitted tail before appending another record.
        guard !journalTailChecked else { return }
        guard let data = try? Data(contentsOf: journalURL), let last = data.last, last != 0x0A else {
            journalTailChecked = true
            return
        }
        let end = data.lastIndex(of: 0x0A).map { $0 + 1 } ?? 0
        if (try? JSONSerialization.jsonObject(with: Data(data.suffix(from: end)))) != nil {
            try handle.seekToEnd()
            try handle.write(contentsOf: Data([0x0A]))
        } else {
            try handle.truncate(atOffset: UInt64(end))
        }
        journalTailChecked = true
    }

    private func prepareDirectory() throws {
        try FileManager.default.createDirectory(
            at: url.deletingLastPathComponent(),
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
    }

    private func compactOnQueue(_ events: [PersistedExtensionFinding]) throws {
        try prepareDirectory()
        let encoded = try JSONEncoder().encode(events)
        try encoded.write(to: url, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
        let checkpoint = try FileHandle(forWritingTo: url)
        try checkpoint.synchronize()
        try checkpoint.close()
        try Data().write(to: journalURL, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: journalURL.path)
        writeObserver?("endpoint-event-compaction", encoded.count)
    }
}
