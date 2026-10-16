// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import XCTest
@testable import Nick

final class SignalTelemetryTests: XCTestCase {
    func testTelemetryIsDisabledUnlessExplicitlyEnabled() {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
            .appendingPathComponent("telemetry.jsonl")
        let telemetry = SignalTelemetry(
            storageURL: url,
            maximumStorageBytes: 128,
            isEnabled: { false }
        )

        telemetry.record(signals: [], verdict: .falsePositive)

        XCTAssertFalse(FileManager.default.fileExists(atPath: url.path))
        XCTAssertNil(telemetry.exportData())
    }

    func testTelemetryCapKeepsOnlyCompleteNewestRecords() {
        let records = Data("first\nsecond\nthird\n".utf8)

        let capped = SignalTelemetry.cappedJSONL(records, maximumBytes: 14)

        XCTAssertEqual(String(decoding: capped, as: UTF8.self), "second\nthird\n")
        XCTAssertLessThanOrEqual(capped.count, 14)
    }
}
