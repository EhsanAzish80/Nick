// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import XCTest
@testable import Nick

final class AuthLatencyWindowTests: XCTestCase {
    func testTenThousandRecordingsRetainExactlyTheNewest4096() {
        let window = AuthLatencyWindow()

        for value in 0..<10_000 {
            window.record(milliseconds: Double(value))
        }

        XCTAssertEqual(window.sampleCount, 4096)
        XCTAssertEqual(window.allocatedSlotCount, 4096)
        XCTAssertEqual(window.retainedSamples(), (5904..<10_000).map(Double.init))
    }

    func testPercentilesUseNearestRankOnKnownDistribution() {
        let window = AuthLatencyWindow()
        for value in 5904..<10_000 {
            window.record(milliseconds: Double(value))
        }

        let snapshot = window.snapshot()

        XCTAssertEqual(snapshot.sampleCount, 4096)
        XCTAssertEqual(snapshot.p50Milliseconds, 7951)
        XCTAssertEqual(snapshot.p99Milliseconds, 9959)
    }

    func testAppendStorageCostDoesNotGrowAfterRingIsFull() {
        let window = AuthLatencyWindow()
        for value in 0..<4096 {
            window.record(milliseconds: Double(value))
        }
        let allocatedWhenFull = window.allocatedSlotCount

        for value in 4096..<100_000 {
            window.record(milliseconds: Double(value))
        }

        XCTAssertEqual(allocatedWhenFull, 4096)
        XCTAssertEqual(window.allocatedSlotCount, allocatedWhenFull)
        XCTAssertEqual(window.sampleCount, 4096)
    }
}
