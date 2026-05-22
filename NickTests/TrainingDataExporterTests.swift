// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import XCTest
@testable import Nick

// MARK: - TrainingDataExporterTests

/// Unit tests for `TrainingDataExporter`.
///
/// Verifies CSV structure, header correctness, RFC 4180 escaping,
/// round-trip parsability, and error handling.
final class TrainingDataExporterTests: XCTestCase {

    private var exporter: TrainingDataExporter!

    override func setUp() {
        super.setUp()
        exporter = TrainingDataExporter()
    }

    // MARK: - CSV structure

    func test_exportCSV_hasCorrectHeader() throws {
        let csv = exporter.buildCSV(from: [makeLabeled(.benign)])
        let lines = csv.components(separatedBy: "\n")
        let header = lines[0]
        let expectedHeader = (FeatureVector.featureNames + ["label", "note"]).joined(separator: ",")
        XCTAssertEqual(header, expectedHeader)
    }

    func test_exportCSV_has40FeatureColumns() throws {
        let csv = exporter.buildCSV(from: [makeLabeled(.malicious)])
        let lines = csv.components(separatedBy: "\n").filter { !$0.isEmpty }
        XCTAssertEqual(lines.count, 2, "Should have header + 1 data row")

        let dataRow = lines[1].components(separatedBy: ",")
        // 40 features + label + note = 42 columns
        XCTAssertEqual(dataRow.count, 42)
    }

    func test_exportCSV_correctLabel() {
        for label in ThreatLabel.allCases {
            let csv = exporter.buildCSV(from: [makeLabeled(label)])
            XCTAssertTrue(csv.contains(label.rawValue), "CSV must contain label '\(label.rawValue)'")
        }
    }

    func test_exportCSV_multipleRows() {
        let vectors = [makeLabeled(.benign), makeLabeled(.suspicious), makeLabeled(.malicious)]
        let csv = exporter.buildCSV(from: vectors)
        let lines = csv.components(separatedBy: "\n").filter { !$0.isEmpty }
        XCTAssertEqual(lines.count, 4, "Header + 3 data rows")
    }

    // MARK: - Parsability

    func test_csvIsParsable() {
        let vectors = (0..<10).map { i -> LabeledFeatureVector in
            var fv = FeatureVector()
            fv.processIsUnsigned = Double(i % 2)
            fv.yaraMatchCount = Double(i)
            return LabeledFeatureVector(features: fv, label: i % 2 == 0 ? .benign : .malicious)
        }
        let csv = exporter.buildCSV(from: vectors)
        let lines = csv.components(separatedBy: "\n").filter { !$0.isEmpty }
        // All data rows should parse to 42 comma-separated values
        for line in lines.dropFirst() {
            let cols = parseCSVRow(line)
            XCTAssertEqual(cols.count, 42, "Each row must have 42 columns. Got: \(cols.count)")
        }
    }

    // MARK: - File write / read round-trip

    func test_exportToFile_roundTrip() throws {
        let tmpURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("nick_test_\(UUID()).csv")
        defer { try? FileManager.default.removeItem(at: tmpURL) }

        var fv = FeatureVector()
        fv.processIsUnsigned = 1
        fv.yaraMatchCount    = 3
        fv.yaraMaxSeverity   = 4
        let labeled = LabeledFeatureVector(features: fv, label: .malicious, note: "test round-trip")

        try exporter.export(vectors: [labeled], to: tmpURL)

        let content = try String(contentsOf: tmpURL, encoding: .utf8)
        XCTAssertTrue(content.contains("malicious"))
        XCTAssertTrue(content.contains("test round-trip"))
        XCTAssertTrue(content.hasPrefix("process_is_unsigned"))
    }

    // MARK: - Error cases

    func test_emptyVectors_throwsEmptyDataSetError() {
        let tmpURL = FileManager.default.temporaryDirectory.appendingPathComponent("empty.csv")
        XCTAssertThrowsError(try exporter.export(vectors: [], to: tmpURL)) { error in
            guard case TrainingDataExporterError.emptyDataSet = error else {
                XCTFail("Expected emptyDataSet error, got \(error)")
                return
            }
        }
    }

    func test_invalidURL_throwsWriteFailure() {
        let badURL = URL(fileURLWithPath: "/nonexistent/directory/file.csv")
        let labeled = makeLabeled(.benign)
        XCTAssertThrowsError(try exporter.export(vectors: [labeled], to: badURL)) { error in
            guard case TrainingDataExporterError.writeFailure = error else {
                XCTFail("Expected writeFailure error, got \(error)")
                return
            }
        }
    }

    // MARK: - RFC 4180 CSV escaping

    func test_noteWithComma_isProperlyEscaped() {
        let labeled = LabeledFeatureVector(
            features: FeatureVector(),
            label: .suspicious,
            note: "process, suspicious"
        )
        let csv = exporter.buildCSV(from: [labeled])
        XCTAssertTrue(csv.contains("\"process, suspicious\""), "Comma in note must be quoted")
    }

    func test_noteWithQuote_isProperlyEscaped() {
        let labeled = LabeledFeatureVector(
            features: FeatureVector(),
            label: .malicious,
            note: "says \"hello\""
        )
        let csv = exporter.buildCSV(from: [labeled])
        XCTAssertTrue(csv.contains("\"says \"\"hello\"\"\""), "Quotes in note must be doubled")
    }

    // MARK: - Helpers

    private func makeLabeled(_ label: ThreatLabel) -> LabeledFeatureVector {
        LabeledFeatureVector(features: FeatureVector(), label: label)
    }

    /// Minimal RFC 4180-aware CSV row parser for test assertions.
    private func parseCSVRow(_ row: String) -> [String] {
        var fields: [String] = []
        var current = ""
        var inQuotes = false
        var idx = row.startIndex

        while idx < row.endIndex {
            let ch = row[idx]
            if inQuotes {
                if ch == "\"" {
                    let next = row.index(after: idx)
                    if next < row.endIndex && row[next] == "\"" {
                        current.append("\"")
                        idx = row.index(after: next)
                        continue
                    } else {
                        inQuotes = false
                    }
                } else {
                    current.append(ch)
                }
            } else {
                if ch == "\"" {
                    inQuotes = true
                } else if ch == "," {
                    fields.append(current)
                    current = ""
                } else {
                    current.append(ch)
                }
            }
            idx = row.index(after: idx)
        }
        fields.append(current)
        return fields
    }
}
