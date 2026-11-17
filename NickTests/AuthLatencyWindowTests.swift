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

    func testRareCompletedOutlierSurvivesPercentileWindowRotation() {
        let window = AuthLatencyWindow(capacity: 4)
        window.record(milliseconds: 900)
        for _ in 0..<10 { window.record(milliseconds: 0.2) }
        XCTAssertEqual(window.snapshot().p99Milliseconds, 0.2)
        XCTAssertEqual(window.snapshot().maximumObservedMilliseconds, 900)
        XCTAssertEqual(window.sampleCount, 4)
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

final class AuthResponseDiagnosticsTests: XCTestCase {
    func testResponseErrorDoesNotInventDeadlineMiss() throws {
        var counters = AuthResponseDiagnostics()
        counters.record(pastDeadline: false, errorCode: 3, event: "auth_open", at: Date(timeIntervalSince1970: 10))
        XCTAssertEqual(counters.responseErrorCount, 1)
        XCTAssertEqual(counters.lateResponseAttemptCount, 0)
        XCTAssertEqual(counters.lastResponseErrorCode, 3)
        XCTAssertEqual(counters.lastResponseErrorEvent, "auth_open")
        XCTAssertTrue(counters.healthFields["kernelDeadlineTerminationCount"] is NSNull)
        _ = try JSONSerialization.data(withJSONObject: counters.healthFields)
    }

    func testLateFailedAttemptCountsOnceInEachIndependentCategory() {
        var counters = AuthResponseDiagnostics()
        let now = Date(timeIntervalSince1970: 10)
        counters.record(pastDeadline: true, errorCode: 2, event: "auth_exec", at: now)
        counters.record(pastDeadline: false, errorCode: nil, event: "auth_open", at: now)
        XCTAssertEqual(counters.responseAttemptCount, 2)
        XCTAssertEqual(counters.lateResponseAttemptCount, 1)
        XCTAssertEqual(counters.responseErrorCount, 1)
        XCTAssertEqual(counters.lastLateResponseAt, now)
    }

    func testNewProcessCountersDoNotErasePreviousSessionEvidenceOrClaimNoKernelKills() throws {
        var previousCounters = AuthResponseDiagnostics()
        previousCounters.record(pastDeadline: true, errorCode: nil, event: "auth_open", at: Date())
        var previous = previousCounters.healthFields
        previous["processID"] = 10
        previous["bootSessionUUID"] = "boot-a"
        previous["privatePath"] = "/Users/private/secret"
        let session = ExtensionHealthSession(processID: 20, bootSessionUUID: "boot-a", previousHealth: previous)
        let preserved = try XCTUnwrap(session.fields["previousProcessSession"] as? [String: Any])
        XCTAssertEqual(preserved["lateAuthResponseAttemptCount"] as? UInt64, 1)
        XCTAssertNil(preserved["privatePath"])
        XCTAssertEqual(session.fields["previousSessionTransition"] as? String, "same-boot-process-restart-cause-unknown")
        let fresh = AuthResponseDiagnostics()
        XCTAssertEqual(fresh.lateResponseAttemptCount, 0)
        XCTAssertTrue(fresh.healthFields["kernelDeadlineTerminationCount"] is NSNull)
        _ = try JSONSerialization.data(withJSONObject: session.fields)
    }

    func testRebootAndLegacyHeartbeatDoNotBecomeConfirmedDeadlineTerminations() {
        let reboot = ExtensionHealthSession(processID: 2, bootSessionUUID: "new", previousHealth: ["bootSessionUUID": "old"])
        XCTAssertEqual(reboot.fields["previousSessionTransition"] as? String, "system-restart")
        let legacy = ExtensionHealthSession(processID: 2, bootSessionUUID: "new", previousHealth: ["deadlineMissCount": 0])
        XCTAssertEqual(legacy.fields["previousSessionTransition"] as? String, "unknown-legacy-health-record")
    }
}
