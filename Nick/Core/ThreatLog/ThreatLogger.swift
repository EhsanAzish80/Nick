// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation
import SwiftData
import os

// MARK: - ThreatLogger

/// Persists `ThreatAlert` events as `ThreatLogEntry` records via SwiftData.
///
/// `ThreatLogger` is the forensic write-ahead log for Nick. Every alert raised by
/// `ThreatCorrelator` should be logged here before being shown to the user, so
/// investigators can reconstruct event timelines after the fact.
///
/// All operations that modify persistent state are async and isolated to the
/// actor executor of the underlying SwiftData `ModelContext`.
///
/// Default retention policy: 90 days. Call `pruneOlderThan(days:)` on app launch.
///
/// - Note: Inject a custom `ModelContainer` in tests to use an in-memory store.
final class ThreatLogger: Sendable {

    // MARK: - Private

    private let container: ModelContainer
    private static let logger = Logger(subsystem: "com.ehsanazish.nick", category: "ThreatLogger")

    // MARK: - Init

    /// Creates a `ThreatLogger` backed by the provided SwiftData container.
    ///
    /// - Parameter container: The `ModelContainer` for `ThreatLogEntry`.
    ///   Use `ModelContainer(for: ThreatLogEntry.self)` for production,
    ///   or an in-memory container for tests.
    init(container: ModelContainer) {
        self.container = container
    }

    // MARK: - Public API

    /// Persists a `ThreatAlert` as a `ThreatLogEntry`.
    ///
    /// If an entry with the same `alert.id` already exists, it is replaced with
    /// the new data (idempotent for replay scenarios).
    ///
    /// - Parameters:
    ///   - alert: The alert to log.
    ///   - explanation: Natural-language explanation from `AlertExplainer`, if available.
    func log(alert: ThreatAlert, explanation: String?) async {
        await withContext { context in
            // Deduplicate: remove existing entry with the same alert ID
            let alertID = alert.id
            let fetchDescriptor = FetchDescriptor<ThreatLogEntry>(
                predicate: #Predicate { $0.id == alertID }
            )
            if let existing = try? context.fetch(fetchDescriptor).first {
                context.delete(existing)
            }

            let entry = ThreatLogEntry(from: alert, explanation: explanation)
            context.insert(entry)
            Self.saveContext(context)
            Self.logger.info("Logged alert: \(alert.title) score=\(alert.score)")
        }
    }

    /// Marks a log entry as reviewed and resolved.
    ///
    /// - Parameters:
    ///   - entryID: The `id` of the `ThreatLogEntry` to update.
    ///   - note: Optional resolution note from the user.
    func markResolved(entryID: UUID, note: String?) async {
        await withContext { context in
            let fetchDescriptor = FetchDescriptor<ThreatLogEntry>(
                predicate: #Predicate { $0.id == entryID }
            )
            guard let entry = try? context.fetch(fetchDescriptor).first else {
                Self.logger.warning("markResolved: entry \(entryID) not found")
                return
            }
            entry.resolved = true
            entry.resolvedNote = note
            Self.saveContext(context)
        }
    }

    /// Fetches log entries matching optional filters.
    ///
    /// All filter parameters are optional; omitting them returns all entries.
    ///
    /// - Parameters:
    ///   - severity: Filter to a specific severity level, or `nil` for all.
    ///   - dateRange: Restrict results to a date range, or `nil` for all dates.
    ///   - resolved: `true` for resolved only, `false` for unresolved only, `nil` for both.
    /// - Returns: Matching entries sorted newest-first.
    func query(
        severity: SignalSeverity?,
        dateRange: ClosedRange<Date>?,
        resolved: Bool?
    ) async -> [ThreatLogEntry] {
        let context = ModelContext(container)
        let descriptor = FetchDescriptor<ThreatLogEntry>(
            sortBy: [SortDescriptor(\.timestamp, order: .reverse)]
        )
        let entries = (try? context.fetch(descriptor)) ?? []
        return entries.filter { entry in
            if let sev = severity, entry.severity != sev.displayName.lowercased() { return false }
            if let range = dateRange, !range.contains(entry.timestamp) { return false }
            if let res = resolved, entry.resolved != res { return false }
            return true
        }
    }

    /// Exports entries as JSON data.
    ///
    /// - Parameter entries: The entries to encode.
    /// - Returns: Encoded JSON bytes.
    /// - Throws: `ThreatLoggerError.exportFailed` if encoding fails.
    func exportJSON(entries: [ThreatLogEntry]) throws -> Data {
        let exportable = entries.map { ExportableThreatLogEntry(from: $0) }
        do {
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            encoder.dateEncodingStrategy = .iso8601
            return try encoder.encode(exportable)
        } catch {
            throw ThreatLoggerError.exportFailed(error)
        }
    }

    /// Exports entries as CSV data.
    ///
    /// - Parameter entries: The entries to encode.
    /// - Returns: UTF-8 CSV bytes with a header row.
    /// - Throws: `ThreatLoggerError.exportFailed` if encoding fails.
    func exportCSV(entries: [ThreatLogEntry]) throws -> Data {
        var rows: [String] = [ExportableThreatLogEntry.csvHeader]
        for entry in entries {
            rows.append(ExportableThreatLogEntry(from: entry).csvRow)
        }
        let csv = rows.joined(separator: "\n")
        guard let data = csv.data(using: .utf8) else {
            throw ThreatLoggerError.exportFailed(nil)
        }
        return data
    }

    /// Deletes all entries older than the given number of days.
    ///
    /// - Parameter days: Entries older than this many days are deleted. Default 90.
    func pruneOlderThan(days: Int = 90) async {
        await withContext { context in
            let cutoff = Date(timeIntervalSinceNow: -Double(days) * 86_400)
            let descriptor = FetchDescriptor<ThreatLogEntry>(
                predicate: #Predicate { $0.timestamp < cutoff }
            )
            let old = (try? context.fetch(descriptor)) ?? []
            for entry in old {
                context.delete(entry)
            }
            if !old.isEmpty {
                Self.saveContext(context)
                Self.logger.info("Pruned \(old.count) entries older than \(days) days")
            }
        }
    }

    // MARK: - Private Helpers

    private func withContext(_ body: (ModelContext) -> Void) async {
        let context = ModelContext(container)
        body(context)
    }

    private static func saveContext(_ context: ModelContext) {
        do {
            try context.save()
        } catch {
            logger.error("ModelContext save failed: \(error.localizedDescription)")
        }
    }
}

// MARK: - ThreatLoggerError

/// Errors thrown by `ThreatLogger`.
enum ThreatLoggerError: LocalizedError {

    /// Export serialisation failed.
    case exportFailed(Error?)

    var errorDescription: String? {
        switch self {
        case .exportFailed(let underlying):
            let detail = underlying?.localizedDescription ?? "unknown encoding error"
            return "Export failed: \(detail)"
        }
    }
}

// MARK: - ExportableThreatLogEntry

/// A `Codable` DTO used for JSON/CSV export, decoupled from `@Model`.
private struct ExportableThreatLogEntry: Codable {

    let id: String
    let timestamp: Date
    let alertTitle: String
    let alertDescription: String
    let explanation: String
    let score: Double
    let severity: String
    let signalSummaries: [String]
    let processName: String
    let processPath: String
    let remoteAddress: String
    let remotePort: String
    let filePath: String
    let resolved: Bool
    let resolvedNote: String

    init(from entry: ThreatLogEntry) {
        id              = entry.id.uuidString
        timestamp       = entry.timestamp
        alertTitle      = entry.alertTitle
        alertDescription = entry.alertDescription
        explanation     = entry.explanation ?? ""
        score           = entry.score
        severity        = entry.severity
        signalSummaries = entry.contributingSignalSummaries
        processName     = entry.processName ?? ""
        processPath     = entry.processPath ?? ""
        remoteAddress   = entry.remoteAddress ?? ""
        remotePort      = entry.remotePort.map { String($0) } ?? ""
        filePath        = entry.filePath ?? ""
        resolved        = entry.resolved
        resolvedNote    = entry.resolvedNote ?? ""
    }

    static let csvHeader = [
        "id", "timestamp", "alertTitle", "score", "severity",
        "processName", "processPath", "remoteAddress", "remotePort",
        "filePath", "resolved", "resolvedNote"
    ].joined(separator: ",")

    var csvRow: String {
        let iso = ISO8601DateFormatter().string(from: timestamp)
        return [
            csvEscaped(id),
            csvEscaped(iso),
            csvEscaped(alertTitle),
            String(format: "%.4f", score),
            csvEscaped(severity),
            csvEscaped(processName),
            csvEscaped(processPath),
            csvEscaped(remoteAddress),
            csvEscaped(remotePort),
            csvEscaped(filePath),
            resolved ? "true" : "false",
            csvEscaped(resolvedNote)
        ].joined(separator: ",")
    }

    private func csvEscaped(_ value: String) -> String {
        guard value.contains(",") || value.contains("\"") || value.contains("\n") else {
            return value
        }
        return "\"" + value.replacingOccurrences(of: "\"", with: "\"\"") + "\""
    }
}
