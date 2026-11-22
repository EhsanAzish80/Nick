import XCTest
@testable import Nick

final class FullCallbackTimingDiagnosticsTests: XCTestCase {
    func testIncludesPostReplyWorkAndPreviousCallbackOverlap() throws {
        let d = FullCallbackTimingDiagnostics(nanosecondsPerTick: 1_000_000)
        d.begin(event: 9, auth: true, message: 0, entry: 10)
        d.responseReturned(callbackEntry: 10, returned: 20)
        d.finish(entry: 10, end: 210)
        d.begin(event: 1, auth: true, message: 100, entry: 220)
        d.finish(entry: 220, end: 221)
        let rows = try records(d), r = try XCTUnwrap(rows.last)
        XCTAssertEqual(r["eventToEntryMilliseconds"] as? Double, 120)
        XCTAssertEqual(r["gapAfterPreviousBodyMilliseconds"] as? Double, 10)
        XCTAssertEqual(r["previousBodyOverlapWithEventToEntryMilliseconds"] as? Double, 110)
        let previous = try XCTUnwrap(r["previousCallback"] as? [String: Any])
        XCTAssertEqual(previous["postResponseMilliseconds"] as? Double, 190)
        XCTAssertEqual(previous["bodyMilliseconds"] as? Double, 200)
        XCTAssertTrue(JSONSerialization.isValidJSONObject(d.snapshot()))
    }
    func testNotifyCallbackAndIdleGapAreKeptSeparate() throws {
        let d = FullCallbackTimingDiagnostics(nanosecondsPerTick: 1_000_000)
        d.begin(event: 8, auth: false, message: 0, entry: 1); d.finish(entry: 1, end: 2)
        d.begin(event: 1, auth: true, message: 3, entry: 303); d.finish(entry: 303, end: 304)
        let r = try XCTUnwrap(try records(d).last)
        XCTAssertEqual(r["previousBodyOverlapWithEventToEntryMilliseconds"] as? Double, 0)
        XCTAssertEqual(r["gapAfterPreviousBodyMilliseconds"] as? Double, 301)
        XCTAssertEqual((r["previousCallback"] as? [String: Any])?["isAuth"] as? Bool, false)
    }
    func testDeferredReplyNeverAttachesToAnotherCallback() throws {
        let d = FullCallbackTimingDiagnostics(nanosecondsPerTick: 1_000_000)
        d.begin(event: 1, auth: true, message: 0, entry: 1); d.finish(entry: 1, end: 2)
        d.begin(event: 2, auth: true, message: 3, entry: 4)
        d.responseReturned(callbackEntry: 1, returned: 5)
        d.finish(entry: 4, end: 24)
        let r = try XCTUnwrap(try records(d).last)
        XCTAssertTrue((r["callback"] as? [String: Any])?["responseReturnMachTime"] is NSNull)
    }
    func testRingIsBoundedAndMaximumSurvivesEviction() throws {
        let d = FullCallbackTimingDiagnostics(capacity: 2, nanosecondsPerTick: 1_000_000)
        for (start,duration) in [(UInt64(0),UInt64(100)),(200,20),(300,30)] {
            d.begin(event: 1, auth: false, message: start, entry: start); d.finish(entry: start, end: start+duration)
        }
        XCTAssertEqual(try records(d).count, 2)
        XCTAssertEqual(d.snapshot()["overwritten"] as? UInt64, 1)
        let max = try XCTUnwrap(d.snapshot()["maximumCallback"] as? [String: Any])
        XCTAssertEqual((max["callback"] as? [String: Any])?["bodyMilliseconds"] as? Double, 100)
    }
    func testFastCallbacksDoNotFillHistoryAndClientsAreIsolated() throws {
        let a = FullCallbackTimingDiagnostics(nanosecondsPerTick: 1_000_000)
        let b = FullCallbackTimingDiagnostics(nanosecondsPerTick: 1_000_000)
        for i in 0..<10_000 {
            let start = UInt64(i*3)
            a.begin(event: 1, auth: true, message: start, entry: start); a.finish(entry: start, end: start+1)
        }
        XCTAssertEqual(try records(a).count, 0)
        XCTAssertEqual(a.snapshot()["completed"] as? UInt64, 10_000)
        XCTAssertEqual(b.snapshot()["completed"] as? UInt64, 0)
        XCTAssertTrue(b.snapshot()["maximumCallback"] is NSNull)
    }
    func testUnavailableTimebaseAndMismatchesAreExplicit() throws {
        let d = FullCallbackTimingDiagnostics(nanosecondsPerTick: 0)
        d.finish(entry: 1, end: 2)
        d.begin(event: 1, auth: true, message: 0, entry: 1); d.finish(entry: 1, end: 2)
        XCTAssertEqual(d.snapshot()["timebaseAvailable"] as? Bool, false)
        XCTAssertEqual(d.snapshot()["sequenceMismatches"] as? UInt64, 1)
        XCTAssertTrue(d.snapshot()["maximumCallback"] is NSNull)
        XCTAssertEqual(try records(d).count, 0)
    }
    private func records(_ d: FullCallbackTimingDiagnostics) throws -> [[String: Any]] {
        try XCTUnwrap(d.snapshot()["records"] as? [[String: Any]])
    }
}
