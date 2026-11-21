import XCTest
@testable import Nick

final class RuntimeDiagnosticsTests: XCTestCase {
    func testActualResponseClaimHasExactlyOneWinnerUnderRace() {
        let claim = AuthResponseClaim(), lock = NSLock()
        var winners = 0
        DispatchQueue.concurrentPerform(iterations: 1000) { _ in
            if claim.claim() { lock.lock(); winners += 1; lock.unlock() }
        }
        XCTAssertEqual(winners, 1)
    }
    func testPendingSurvivesClaimAndAPIFailureUntilAcceptedReturn() throws {
        let d = PendingAuthDiagnostics(), key = PendingAuthDiagnostics.Key(address: 1, machTime: 100)
        d.received(key, event: 5, deadline: 200)
        d.phase(key, .credentialValidation); d.phase(key, .workerClaimed)
        XCTAssertEqual(d.snapshot(now: 140)["pending"] as? Int, 1)
        XCTAssertTrue(d.warnings(now: 149).isEmpty)
        d.responseStarted(key); d.responseReturned(key, accepted: false)
        let warning = try XCTUnwrap(d.warnings(now: 150).first)
        XCTAssertEqual(warning["phase"] as? String, "responseFailed")
        XCTAssertTrue(d.warnings(now: 190).isEmpty)
        d.responseStarted(key); d.responseReturned(key, accepted: true)
        XCTAssertEqual(d.snapshot(now: 200)["pending"] as? Int, 0)
        XCTAssertEqual(d.snapshot(now: 200)["duplicateAttemptsWhilePending"] as? UInt64, 1)
    }
    func testAllDeferredPhasesRemainVisibleAndWarningsAreBounded() {
        let d = PendingAuthDiagnostics()
        for (i, phase) in [PendingAuthDiagnostics.Phase.callback, .credentialValidation, .prelaunchHash, .workerClaimed, .watchdogClaimed, .responseAPI].enumerated() {
            let key = PendingAuthDiagnostics.Key(address: UInt64(i), machTime: 10)
            d.received(key, event: UInt32(i), deadline: 100); d.phase(key, phase)
        }
        XCTAssertEqual(d.warnings(now: 60, limit: 2).count, 2)
        XCTAssertEqual(d.warnings(now: 60).count, 4)
        XCTAssertEqual(d.snapshot(now: 60)["pending"] as? Int, 6)
        XCTAssertNoThrow(try JSONSerialization.data(withJSONObject: d.snapshot(now: 60)))
    }
    func testCapacityNeverEvictsUnansweredRequestAndAddressReuseIsDistinct() {
        let d = PendingAuthDiagnostics(capacity: 1)
        let first = PendingAuthDiagnostics.Key(address: 1, machTime: 10), next = PendingAuthDiagnostics.Key(address: 1, machTime: 11)
        d.received(first, event: 1, deadline: 20); d.received(next, event: 1, deadline: 20)
        XCTAssertEqual(d.snapshot(now: 12)["untrackedCapacityOverflows"] as? UInt64, 1)
        d.responseReturned(first, accepted: true); d.received(next, event: 1, deadline: 20)
        XCTAssertEqual(d.snapshot(now: 12)["pending"] as? Int, 1)
    }
    func testUSBProgressAndMemoryWorkRemainBounded() {
        let d = ScanWorkDiagnostics()
        for _ in 0..<100 { let id = d.usbStarted(); d.usbProgress(id, enumerated: 200_000, scanned: 0, finished: true) }
        XCTAssertEqual((d.snapshot()["usbRuns"] as? [[String: Any]])?.count, 32)
        d.scanStarted(); d.scanStarted(); d.hashed(bytes: 1024); d.scanEnded(); d.scanEnded()
        XCTAssertEqual(d.snapshot()["scansActive"] as? Int, 0)
        XCTAssertEqual(d.snapshot()["peakScansActive"] as? Int, 2)
        XCTAssertEqual(d.snapshot()["streamingHashBytes"] as? UInt64, 1024)
    }
    func testMountStartupRecordsPreserveUnknownPropertiesAndCorrelateUSBRun() throws {
        let d = USBMountDiagnostics(), id = try XCTUnwrap(d.received(path: "/Volumes/Synthetic-Test"))
        d.update(id, stage: "metadata-returned", fields: ["volumeIsLocal": true, "volumeIsRemovable": NSNull(), "volumeIsEjectable": true])
        d.update(id, stage: "scan-started", fields: ["usbRunID": UInt64(7)])
        d.update(id, stage: "scan-ended", finished: true, fields: ["endReason": "scanned-file-cap"])
        let record = try XCTUnwrap((d.snapshot()["mountRecords"] as? [[String: Any]])?.first)
        XCTAssertEqual(record["usbRunID"] as? UInt64, 7)
        XCTAssertTrue(record["volumeIsRemovable"] is NSNull)
        XCTAssertEqual(record["finished"] as? Bool, true)
        let json = try JSONSerialization.data(withJSONObject: d.snapshot())
        XCTAssertFalse(String(decoding: json, as: UTF8.self).contains("Synthetic-Test"))
    }
    func testMountTokensStableWithinSessionAndDifferentAcrossSessions() throws {
        let first = USBMountDiagnostics(), second = USBMountDiagnostics()
        _ = first.received(path: "/Volumes/Synthetic")
        _ = first.received(path: "/Volumes/Synthetic")
        _ = second.received(path: "/Volumes/Synthetic")
        let records = try XCTUnwrap(first.snapshot()["mountRecords"] as? [[String: Any]])
        let other = try XCTUnwrap((second.snapshot()["mountRecords"] as? [[String: Any]])?.first)
        XCTAssertEqual(records[0]["mountToken"] as? String, records[1]["mountToken"] as? String)
        XCTAssertNotEqual(records[0]["mountToken"] as? String, other["mountToken"] as? String)
    }
    func testMountDiagnosticsNeverEvictUnfinishedWorkAndCountOverflow() throws {
        let d = USBMountDiagnostics(capacity: 2)
        let first = try XCTUnwrap(d.received(path: "/Volumes/A"))
        _ = d.received(path: "/Volumes/B")
        XCTAssertNil(d.received(path: "/Volumes/C"))
        XCTAssertEqual(d.snapshot()["mountRecordOverflows"] as? UInt64, 1)
        d.update(first, stage: "rejected-metadata-error", finished: true,
                 fields: ["errorDomain": "NSCocoaErrorDomain", "errorCode": 260])
        XCTAssertNotNil(d.received(path: "/Volumes/D"))
        XCTAssertEqual((d.snapshot()["mountRecords"] as? [[String: Any]])?.count, 2)
        XCTAssertEqual(d.snapshot()["mountReceivedCount"] as? UInt64, 4)
    }
    func testMountReceiptVisibleBeforeEligibilityAndHistoryBounded() throws {
        let d = USBMountDiagnostics(), id = try XCTUnwrap(d.received(path: "/private/tmp/preparation"))
        var record = try XCTUnwrap((d.snapshot()["mountRecords"] as? [[String: Any]])?.first)
        XCTAssertEqual(record["stage"] as? String, "received")
        XCTAssertEqual(record["pathIsVolumesPrefix"] as? Bool, false)
        for _ in 0..<100 { d.update(id, stage: "metadata-requested") }
        record = try XCTUnwrap((d.snapshot()["mountRecords"] as? [[String: Any]])?.first)
        XCTAssertEqual((record["history"] as? [[String: Any]])?.count, 12)
        XCTAssertNoThrow(try JSONSerialization.data(withJSONObject: d.snapshot()))
    }
    private func report(namespace: String = "ENDPOINTSECURITY", code: Int = 2, bundle: String = "com.ehsanazish.nick.NickExtension") throws -> Data {
        let body: [String: Any] = ["incident": "B35E0200-3333-4444-8888-000000000001", "pid": 42,
            "procLaunch": "2026-11-19 10:00:00.000 +0000", "captureTime": "2026-11-19 10:10:00.000 +0000",
            "termination": ["namespace": namespace, "code": code], "bundleInfo": ["CFBundleIdentifier": bundle, "CFBundleVersion": "5110"]]
        return try JSONSerialization.data(withJSONObject: body)
    }
    func testIPSParsingAndStrictPreviousSessionCorrelation() throws {
        let body = try report(), twoObjects = Data("{\"bug_type\":\"309\"}\n".utf8) + body
        let match = try XCTUnwrap(EndpointTerminationReport.parse(twoObjects))
        var session: [String: Any] = ["processID": 42, "version": "5110", "processStartedAt": match.launch.timeIntervalSince1970 + 2, "updatedAt": match.captured.timeIntervalSince1970 - 25]
        XCTAssertTrue(EndpointTerminationReport.matchesPrevious(match, session: session))
        session["processStartedAt"] = match.launch.timeIntervalSince1970 + 1000
        XCTAssertFalse(EndpointTerminationReport.matchesPrevious(match, session: session))
        session["processStartedAt"] = match.launch.timeIntervalSince1970
        session["version"] = "5109"
        XCTAssertFalse(EndpointTerminationReport.matchesPrevious(match, session: session))
    }
    func testRejectsOtherTerminationsMalformedAndOversizeReports() throws {
        XCTAssertNil(EndpointTerminationReport.parse(try report(namespace: "SIGNAL")))
        XCTAssertNil(EndpointTerminationReport.parse(try report(code: 1)))
        XCTAssertNil(EndpointTerminationReport.parse(try report(bundle: "other.app")))
        XCTAssertNil(EndpointTerminationReport.parse(Data("not JSON".utf8)))
        XCTAssertNil(EndpointTerminationReport.parse(Data(repeating: 0, count: 8 * 1024 * 1024 + 1)))
    }
}
