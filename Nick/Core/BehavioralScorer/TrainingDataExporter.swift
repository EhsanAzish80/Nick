// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation
import os

// MARK: - ThreatLabel

/// Ground-truth threat classification used to label training examples.
///
/// Applied by a security analyst (or the synthetic data generator) to mark
/// each `FeatureVector` for supervised learning.
enum ThreatLabel: String, Codable, Sendable, CaseIterable {
    /// Normal activity — Homebrew installs, Xcode builds, browser downloads.
    case benign     = "benign"
    /// Activity that warrants investigation but may be legitimate.
    case suspicious = "suspicious"
    /// Confirmed or near-certain malicious activity.
    case malicious  = "malicious"
}

// MARK: - LabeledFeatureVector

/// A training example consisting of a feature vector and its ground-truth label.
///
/// These are produced either by `TrainingDataExporter` from live Nick telemetry
/// with analyst-applied labels, or synthetically via `generate_training_data.py`.
struct LabeledFeatureVector: Codable, Sendable {

    /// The 40-dimensional feature input.
    let features: FeatureVector

    /// The ground-truth classification for this sample.
    let label: ThreatLabel

    /// Optional human-readable note explaining why this label was assigned.
    let note: String?

    init(features: FeatureVector, label: ThreatLabel, note: String? = nil) {
        self.features = features
        self.label    = label
        self.note     = note
    }
}

// MARK: - TrainingDataExporterError

/// Errors thrown by `TrainingDataExporter`.
enum TrainingDataExporterError: LocalizedError {
    /// The destination URL could not be written to.
    case writeFailure(url: URL, underlying: Error)
    /// The vectors array is empty — nothing to export.
    case emptyDataSet

    var errorDescription: String? {
        switch self {
        case .writeFailure(let url, let error):
            return "Failed to write training data to \(url.lastPathComponent): \(error.localizedDescription)"
        case .emptyDataSet:
            return "No labeled vectors to export."
        }
    }
}

// MARK: - TrainingDataExporter

/// Serialises labeled training examples to CSV for the Python ML training pipeline.
///
/// The exported CSV uses the column names from `FeatureVector.featureNames` plus a
/// `label` column and an optional `note` column. The Python `train_model.py` script
/// consumes this format directly with `pandas.read_csv`.
///
/// - Note: This class produces training artefacts and is not part of the
///         real-time detection pipeline.
final class TrainingDataExporter {

    // MARK: - Private

    private static let logger = Logger(subsystem: "com.ehsanazish.nick", category: "TrainingDataExporter")

    // MARK: - Init

    init() {}

    // MARK: - Public API

    /// Exports labeled feature vectors to a CSV file at the given URL.
    ///
    /// The file is created or overwritten atomically. Each row contains all 40
    /// feature values (comma-separated) followed by the `label` string and an
    /// optional `note` field. The header row uses `FeatureVector.featureNames`.
    ///
    /// - Parameters:
    ///   - vectors: The labeled training examples to export. Must not be empty.
    ///   - url: Destination file URL. The parent directory must already exist.
    ///
    /// - Throws: `TrainingDataExporterError.emptyDataSet` if `vectors` is empty.
    ///           `TrainingDataExporterError.writeFailure` if the file cannot be written.
    func export(vectors: [LabeledFeatureVector], to url: URL) throws {
        guard !vectors.isEmpty else {
            throw TrainingDataExporterError.emptyDataSet
        }

        let csvData = buildCSV(from: vectors)

        do {
            try csvData.write(to: url, atomically: true, encoding: .utf8)
            Self.logger.info("Exported \(vectors.count) training examples to \(url.lastPathComponent)")
        } catch {
            throw TrainingDataExporterError.writeFailure(url: url, underlying: error)
        }
    }

    // MARK: - Internal Helpers

    /// Builds the full CSV string from labeled vectors.
    ///
    /// Separated for testability — callers can inspect the CSV string without writing to disk.
    func buildCSV(from vectors: [LabeledFeatureVector]) -> String {
        var rows: [String] = []

        // Header row
        let header = (FeatureVector.featureNames + ["label", "note"]).joined(separator: ",")
        rows.append(header)

        // Data rows
        for labeled in vectors {
            let featureValues = labeled.features.asArray.map { String($0) }
            let label = labeled.label.rawValue
            let note  = csvEscaped(labeled.note ?? "")
            let row   = (featureValues + [label, note]).joined(separator: ",")
            rows.append(row)
        }

        return rows.joined(separator: "\n") + "\n"
    }

    // MARK: - Private Implementation

    /// Escapes a field value for safe CSV embedding.
    ///
    /// Fields containing commas, double-quotes, or newlines are wrapped in double-quotes.
    /// Existing double-quotes are doubled per RFC 4180.
    private func csvEscaped(_ field: String) -> String {
        guard field.contains(",") || field.contains("\"") || field.contains("\n") else {
            return field
        }
        let escaped = field.replacingOccurrences(of: "\"", with: "\"\"")
        return "\"\(escaped)\""
    }
}
