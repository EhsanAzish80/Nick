import XCTest
@testable import Nick

final class SlowAuthResponseDiagnosticsTests: XCTestCase {
    func testSeparatesKernelQueueHandlerAndResponseAPITime() throws {
        let d = SlowAuthResponseDiagnostics(nanosecondsPerTick: 1_000_000)
        let context = PendingAuthDiagnostics.ResponseContext(callbackMachTime: 400, phaseBeforeResponse: .workerClaimed)
        d.record(event: 42, result: 0, allowed: false, message: 0, context: context,
                 apiStart: 600, returned: 700, deadline: 1000)
        let r = try first(d)
        XCTAssertEqual(r["eventType"] as? UInt32, 42)
        XCTAssertEqual(r["allowed"] as? Bool, false)
        XCTAssertEqual(r["totalMilliseconds"] as? Double, 700)
        XCTAssertEqual(r["eventToCallbackMilliseconds"] as? Double, 400)
        XCTAssertEqual(r["callbackToAPIMilliseconds"] as? Double, 200)
        XCTAssertEqual(r["responseAPIMilliseconds"] as? Double, 100)
        XCTAssertEqual(r["deadlineRemainingAtCallbackMilliseconds"] as? Double, 600)
        XCTAssertEqual(r["deadlineRemainingAtResponseMilliseconds"] as? Double, 300)
        XCTAssertEqual(r["phaseBeforeResponse"] as? String, "workerClaimed")
        XCTAssertTrue(JSONSerialization.isValidJSONObject(d.snapshot()))
    }

    func testMissingOrInvalidCallbackDoesNotInventZeroQueueDelay() throws {
        for context in [nil, PendingAuthDiagnostics.ResponseContext(callbackMachTime: 999, phaseBeforeResponse: .callback)] {
            let d = SlowAuthResponseDiagnostics(nanosecondsPerTick: 1_000_000)
            d.record(event: 1, result: 0, allowed: true, message: 0, context: context,
                     apiStart: 150, returned: 200, deadline: 300)
            let r = try first(d)
            XCTAssertTrue(r["eventToCallbackMilliseconds"] is NSNull)
            XCTAssertTrue(r["callbackToAPIMilliseconds"] is NSNull)
            XCTAssertEqual(r["responseAPIMilliseconds"] as? Double, 50)
        }
    }

    func testBoundedRingReportsEvictionAndPreservesMaximum() throws {
        let d = SlowAuthResponseDiagnostics(capacity: 2, nanosecondsPerTick: 1_000_000)
        for duration in [UInt64(600), 200, 300] {
            d.record(event: 1, result: 0, allowed: true, message: 0, context: nil,
                     apiStart: duration - 1, returned: duration, deadline: 1000)
        }
        let s = d.snapshot()
        let rows = try XCTUnwrap(s["records"] as? [[String: Any]])
        XCTAssertEqual(rows.compactMap { $0["totalMilliseconds"] as? Double }, [200, 300])
        XCTAssertEqual(s["overwritten"] as? UInt64, 1)
        XCTAssertEqual((s["maximumObserved"] as? [String: Any])?["totalMilliseconds"] as? Double, 600)
    }

    func testFastSuccessfulRepliesDoNotEnterOutlierHistory() throws {
        let d = SlowAuthResponseDiagnostics(nanosecondsPerTick: 1_000_000)
        for _ in 0..<10_000 {
            d.record(event: 1, result: 0, allowed: true, message: 0, context: nil,
                     apiStart: 9, returned: 10, deadline: 100)
        }
        XCTAssertEqual((d.snapshot()["records"] as? [[String: Any]])?.count, 0)
        XCTAssertTrue(d.snapshot()["maximumObserved"] is NSNull)
        XCTAssertEqual(d.capacity, 16)
    }

    func testFailedOrLateFastRepliesAreRecordedWithSignedDeadlineMargin() throws {
        let d = SlowAuthResponseDiagnostics(nanosecondsPerTick: 1_000_000)
        d.record(event: 1, result: 7, allowed: false, message: 0, context: nil,
                 apiStart: 9, returned: 10, deadline: 100)
        d.record(event: 2, result: 0, allowed: true, message: 0, context: nil,
                 apiStart: 19, returned: 20, deadline: 15)
        let rows = try XCTUnwrap(d.snapshot()["records"] as? [[String: Any]])
        XCTAssertEqual(rows.count, 2)
        XCTAssertEqual(rows[0]["responseResult"] as? UInt32, 7)
        XCTAssertEqual(rows[1]["pastDeadline"] as? Bool, true)
        XCTAssertEqual(rows[1]["deadlineRemainingAtResponseMilliseconds"] as? Double, -5)
    }

    func testPendingContextCapturesCallbackAndPhaseBeforeResponseBookkeeping() throws {
        let d = PendingAuthDiagnostics(), key = PendingAuthDiagnostics.Key(address: 1, machTime: 100)
        d.received(key, event: 42, deadline: 300, callbackMachTime: 120)
        d.phase(key, .watchdogClaimed)
        let c = try XCTUnwrap(d.responseStarted(key))
        XCTAssertEqual(c.callbackMachTime, 120)
        XCTAssertEqual(c.phaseBeforeResponse, .watchdogClaimed)
        XCTAssertEqual((d.snapshot(now: 130)["phaseCounts"] as? [String: Int])?["responseAPI"], 1)
        d.responseReturned(key, accepted: true)
        XCTAssertEqual(d.snapshot(now: 140)["pending"] as? Int, 0)
        XCTAssertNil(d.responseStarted(key))
    }

    private func first(_ d: SlowAuthResponseDiagnostics) throws -> [String: Any] {
        try XCTUnwrap((d.snapshot()["records"] as? [[String: Any]])?.first)
    }
}
