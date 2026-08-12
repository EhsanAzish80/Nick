import Foundation
import Observation

@MainActor
@Observable
final class RuntimeComparisonStore {
    enum StorageError: LocalizedError, Equatable {
        case snapshotTooLarge

        var errorDescription: String? {
            "The snapshot exceeds Nick's 25 MB storage limit. Shorten the observation window and try again."
        }
    }

    enum ImportError: LocalizedError, Equatable {
        case fileTooLarge
        case unsupportedSchema(Int)
        case differentDevice
        case missingEvidence
        case invalidFile

        var errorDescription: String? {
            switch self {
            case .fileTooLarge:
                "The comparison is larger than Nick's 50 MB import limit."
            case .unsupportedSchema(let version):
                "This comparison uses unsupported schema version \(version)."
            case .differentDevice:
                "This comparison was captured on a different Mac. Nick 4.1 supports same-Mac comparisons only."
            case .missingEvidence:
                "The imported comparison does not contain a baseline or follow-up snapshot."
            case .invalidFile:
                "The selected file is not a valid Nick Runtime Comparison JSON file."
            }
        }
    }

    private(set) var comparisons: [RuntimeComparison] = []
    private(set) var lastError: String?

    private let directory: URL
    private let maximumCount: Int
    private static let maximumImportBytes = 50 * 1_024 * 1_024
    private static let maximumSnapshotBytes = 25 * 1_024 * 1_024

    init(directory: URL? = nil, maximumCount: Int = 20) {
        self.directory = directory ?? Self.defaultDirectory
        self.maximumCount = min(20, max(1, maximumCount))
        load()
    }

    @discardableResult
    func create(label: String, scenario: RuntimeScenario) -> UUID {
        let now = Date()
        let comparison = RuntimeComparison(
            id: UUID(), label: label.trimmingCharacters(in: .whitespacesAndNewlines),
            scenario: scenario, createdAt: now, updatedAt: now,
            state: .awaitingBaseline, baseline: nil, followUp: nil, findings: []
        )
        comparisons.insert(comparison, at: 0)
        persist()
        return comparison.id
    }

    func setBaseline(_ snapshot: RuntimeSnapshot, for id: UUID) throws {
        try Self.validateStorageSize(snapshot)
        update(id) { value in
            value.baseline = snapshot
            value.state = .awaitingFollowUp
            value.findings = []
        }
    }

    func setFollowUp(_ snapshot: RuntimeSnapshot, for id: UUID) throws {
        try Self.validateStorageSize(snapshot)
        update(id) { value in
            value.followUp = snapshot
            if let baseline = value.baseline {
                value.findings = RuntimeSnapshotComparator.compare(baseline: baseline, followUp: snapshot)
            }
            value.state = .completed
        }
    }

    func rename(_ id: UUID, to label: String) {
        update(id) { $0.label = label.trimmingCharacters(in: .whitespacesAndNewlines) }
    }

    func delete(_ id: UUID) {
        comparisons.removeAll { $0.id == id }
        try? FileManager.default.removeItem(at: fileURL(for: id))
    }

    func comparison(_ id: UUID) -> RuntimeComparison? {
        comparisons.first { $0.id == id }
    }

    @discardableResult
    func importComparison(from url: URL, expectedDeviceToken: String = RuntimeDeviceIdentity.token) throws -> UUID {
        let resourceValues = try url.resourceValues(forKeys: [.fileSizeKey])
        if let size = resourceValues.fileSize, size > Self.maximumImportBytes {
            throw ImportError.fileTooLarge
        }
        let data = try Data(contentsOf: url, options: [.mappedIfSafe])
        return try importComparison(data: data, expectedDeviceToken: expectedDeviceToken)
    }

    @discardableResult
    func importComparison(data: Data, expectedDeviceToken: String) throws -> UUID {
        guard data.count <= Self.maximumImportBytes else { throw ImportError.fileTooLarge }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        guard var imported = try? decoder.decode(RuntimeComparison.self, from: data) else {
            throw ImportError.invalidFile
        }
        let snapshots = [imported.baseline, imported.followUp].compactMap { $0 }
        guard !snapshots.isEmpty else { throw ImportError.missingEvidence }
        try snapshots.forEach(Self.validateStorageSize)
        if let unsupported = snapshots.map(\.schemaVersion).first(where: { $0 > RuntimeSnapshot.currentSchemaVersion }) {
            throw ImportError.unsupportedSchema(unsupported)
        }
        guard snapshots.allSatisfy({ $0.deviceToken == expectedDeviceToken }) else {
            throw ImportError.differentDevice
        }

        let now = Date()
        imported = RuntimeComparison(
            id: UUID(), label: imported.label, scenario: imported.scenario,
            createdAt: imported.createdAt, updatedAt: now, state: imported.state,
            baseline: imported.baseline, followUp: imported.followUp,
            findings: imported.findings
        )
        if let baseline = imported.baseline, let followUp = imported.followUp {
            imported.findings = RuntimeSnapshotComparator.compare(baseline: baseline, followUp: followUp)
            imported.state = .completed
        } else if imported.baseline != nil {
            imported.state = .awaitingFollowUp
            imported.findings = []
        } else {
            imported.state = .awaitingBaseline
            imported.findings = []
        }
        comparisons.insert(imported, at: 0)
        persist()
        return imported.id
    }

    private func update(_ id: UUID, mutation: (inout RuntimeComparison) -> Void) {
        guard let index = comparisons.firstIndex(where: { $0.id == id }) else { return }
        mutation(&comparisons[index])
        comparisons[index].updatedAt = Date()
        comparisons.sort { $0.updatedAt > $1.updatedAt }
        persist()
    }

    private func load() {
        do {
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
            let urls = try FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil)
                .filter { $0.pathExtension == "json" }
            let decoder = JSONDecoder()
            comparisons = try urls.compactMap { url in
                let value = try decoder.decode(RuntimeComparison.self, from: Data(contentsOf: url))
                guard value.baseline?.schemaVersion ?? RuntimeSnapshot.currentSchemaVersion <= RuntimeSnapshot.currentSchemaVersion,
                      value.followUp?.schemaVersion ?? RuntimeSnapshot.currentSchemaVersion <= RuntimeSnapshot.currentSchemaVersion else { return nil }
                return value
            }.sorted { $0.updatedAt > $1.updatedAt }
        } catch { lastError = error.localizedDescription }
    }

    private func persist() {
        do {
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            for comparison in comparisons.prefix(maximumCount) {
                try encoder.encode(comparison).write(to: fileURL(for: comparison.id), options: .atomic)
            }
            for comparison in comparisons.dropFirst(maximumCount) {
                try? FileManager.default.removeItem(at: fileURL(for: comparison.id))
            }
            if comparisons.count > maximumCount { comparisons = Array(comparisons.prefix(maximumCount)) }
            lastError = nil
        } catch { lastError = error.localizedDescription }
    }

    private func fileURL(for id: UUID) -> URL { directory.appendingPathComponent(id.uuidString).appendingPathExtension("json") }

    private static func validateStorageSize(_ snapshot: RuntimeSnapshot) throws {
        if try JSONEncoder().encode(snapshot).count > maximumSnapshotBytes {
            throw StorageError.snapshotTooLarge
        }
    }

    private static var defaultDirectory: URL {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
        return base.appendingPathComponent("com.ehsanazish.nick/RuntimeComparisons", isDirectory: true)
    }
}
