import XCTest
@testable import Nick

final class CredentialAuthDiagnosticsTests: XCTestCase {
    func testOverlappingWorkAndRetainedLifetimesAreTrackedSeparately() throws {
        let d = CredentialAuthDiagnostics()
        d.begin(.credentialRetained, now: 10)
        d.begin(.credentialWork, now: 20)
        d.begin(.credentialWork, now: 30)
        d.end(.credentialWork, since: 20, now: 120)
        let timings = try XCTUnwrap(d.snapshot()["timings"] as? [String: Any])
        let work = try XCTUnwrap(timings["credentialWork"] as? [String: Any])
        let retained = try XCTUnwrap(timings["credentialRetained"] as? [String: Any])
        XCTAssertEqual(work["inFlight"] as? UInt64, 1)
        XCTAssertEqual(work["peakInFlight"] as? UInt64, 2)
        XCTAssertEqual(retained["inFlight"] as? UInt64, 1)
    }
    func testWatchdogDelayAndSecurityStatusRemainVisibleAfterCompletion() throws {
        let d = CredentialAuthDiagnostics()
        d.observe(.credentialWatchdogDelay, nanoseconds: 3_000_000_000)
        d.begin(.validity, now: 10)
        d.end(.validity, since: 10, now: 2_000_000_010, status: -67818)
        d.count(.validityFailure)
        let snapshot = d.snapshot()
        let timings = try XCTUnwrap(snapshot["timings"] as? [String: Any])
        let delay = try XCTUnwrap(timings["credentialWatchdogDelay"] as? [String: Any])
        let validity = try XCTUnwrap(timings["validity"] as? [String: Any])
        XCTAssertEqual(delay["maximumMilliseconds"] as? Double, 3000)
        XCTAssertEqual(validity["lastOSStatus"] as? Int32, -67818)
        XCTAssertEqual(validity["inFlight"] as? UInt64, 0)
        XCTAssertNoThrow(try JSONSerialization.data(withJSONObject: snapshot))
    }
}
