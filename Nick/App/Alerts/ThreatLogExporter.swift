// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation
import AppKit
import SwiftData
import os

// MARK: - ThreatLogExporter

/// Handles file export of `ThreatLogEntry` records via `NSSavePanel`.
///
/// Presents the system save panel and writes JSON or CSV data to the chosen
/// URL. All I/O runs on a background task; the completion handler is called
/// on the main actor.
///
/// - Note: This type is separate from `ThreatLogger` to keep persistence and
///   UI/export concerns decoupled.
final class ThreatLogExporter {

    // MARK: - Types

    /// The supported export formats.
    enum ExportFormat {
        case json
        case csv
    }

    // MARK: - Private

    private static let logger = Logger(subsystem: "com.ehsanazish.nick", category: "ThreatLogExporter")

    // MARK: - Init

    /// Creates a new instance. No configuration required.
    init() {}

    // MARK: - Public API

    /// Presents a save panel, then writes the exported data.
    ///
    /// - Parameters:
    ///   - entries: The log entries to export.
    ///   - format: The output format (`.json` or `.csv`).
    ///   - completion: Called on the main actor with `.success` or `.failure`.
    @MainActor
    func export(
        entries: [ThreatLogEntry],
        format: ExportFormat,
        completion: @MainActor @escaping (Result<Void, Error>) -> Void
    ) {
        let panel = NSSavePanel()
        panel.title = "Export Threat Log"
        panel.nameFieldStringValue = exportFilename(format: format)
        panel.allowedContentTypes = format == .json ? [.json] : [.commaSeparatedText]
        panel.canCreateDirectories = true

        guard panel.runModal() == .OK, let url = panel.url else {
            return
        }

        // Capture what we need before leaving the main actor
        let exporter = self
        Task { @MainActor in
            do {
                let data = try exporter.buildExportData(entries: entries, format: format)
                try data.write(to: url, options: .atomic)
                Self.logger.info("Exported \(entries.count) entries to \(url.path)")
                completion(.success(()))
            } catch {
                Self.logger.error("Export failed: \(error.localizedDescription)")
                completion(.failure(error))
            }
        }
    }

    // MARK: - Internal Helpers (accessible in tests)

    /// Builds the raw export data without saving to disk.
    ///
    /// - Parameters:
    ///   - entries: The log entries to encode.
    ///   - format: The encoding format.
    /// - Returns: Encoded data.
    /// - Throws: `ThreatLoggerError.exportFailed` on encoding failure.
    func buildExportData(entries: [ThreatLogEntry], format: ExportFormat) throws -> Data {
        let threatLogger = ThreatLogger(container: try ThreatLogExporter.makeInMemoryContainer())
        switch format {
        case .json: return try threatLogger.exportJSON(entries: entries)
        case .csv:  return try threatLogger.exportCSV(entries: entries)
        }
    }

    // MARK: - Private

    private func exportFilename(format: ExportFormat) -> String {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd"
        let date = formatter.string(from: Date())
        return "nick-threat-log-\(date).\(format == .json ? "json" : "csv")"
    }

    /// Creates a throw-away in-memory container for building the export helper.
    ///
    /// - Throws: `ThreatLoggerError.exportFailed` if SwiftData cannot initialise an in-memory store.
    private static func makeInMemoryContainer() throws -> ModelContainer {
        let config = ModelConfiguration(isStoredInMemoryOnly: true)
        do {
            return try ModelContainer(for: ThreatLogEntry.self, configurations: config)
        } catch {
            Self.logger.error("Failed to create in-memory export container: \(error)")
            throw error
        }
    }
}
