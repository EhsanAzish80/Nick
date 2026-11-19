import XCTest
import Darwin
@testable import Nick

final class CredentialStormTests: XCTestCase {
    private func key(path: String = "/fixture/Cookies", actor: UInt8 = 1, inode: UInt64 = 1, uid: UInt32 = 501) -> CredentialObservationGate.Key {
        var s = stat(); s.st_ino = inode
        return .init(actorAudit: Data([actor]), actorHash: Data([2]), actorPath: "/fixture/reader", signingID: "fixture.reader", teamID: "TEAM",
            codeFlags: 1, responsibleAudit: Data([3]), parentAudit: Data([4]), path: path,
            file: Nick.FileIdentity(stat: s), owner: uid, store: "fixture")
    }
    func testSixtyThousandRepeatedReadsAdmitOneClosureBeforeQueueing() {
        let gate = CredentialObservationGate()
        var admitted = 0
        for _ in 0..<60_000 {
            if case .admitted = gate.admit(key(), now: 1) { admitted += 1 }
        }
        XCTAssertEqual(admitted, 1)
        XCTAssertEqual(gate.snapshot()["coalescedBeforeQueue"] as? UInt64, 59_999)
        XCTAssertEqual(gate.snapshot()["pendingIncludingDelayedReview"] as? Int, 1)
    }
    func testQueueMetricsSeparateWaitingActiveAndDelayedReview() {
        let gate = CredentialObservationGate()
        guard case .admitted(let ticket) = gate.admit(key(), now: 1) else { return XCTFail() }
        XCTAssertEqual(gate.snapshot(now: 2)["queued"] as? Int, 1)
        XCTAssertEqual(gate.snapshot(now: 2)["oldestQueuedAgeMilliseconds"] as? Double, 1000)
        gate.began(ticket, now: 2)
        XCTAssertEqual(gate.snapshot(now: 2)["active"] as? Int, 1)
        XCTAssertEqual(gate.snapshot(now: 2)["queued"] as? Int, 0)
        gate.workEnded()
        XCTAssertEqual(gate.snapshot(now: 3)["delayedReview"] as? Int, 1)
        gate.finish(ticket)
        XCTAssertEqual(gate.snapshot(now: 3)["pendingIncludingDelayedReview"] as? Int, 0)
    }
    func testDifferentTargetOwnerFileAndProcessAreNotCoalesced() {
        let gate = CredentialObservationGate()
        for k in [key(), key(path: "/other/Cookies"), key(actor: 2), key(inode: 2), key(uid: 502)] {
            guard case .admitted = gate.admit(k, now: 1) else { return XCTFail("Distinct evidence suppressed") }
        }
    }
    func testPressureIsSeparateFromDuplicatesAndCapacityRecovers() {
        let gate = CredentialObservationGate(maximumPending: 1, maximumEntries: 2)
        guard case .admitted(let first) = gate.admit(key(), now: 1) else { return XCTFail() }
        guard case .coalesced = gate.admit(key(), now: 2) else { return XCTFail() }
        guard case .pressure(let report) = gate.admit(key(actor: 2), now: 3) else { return XCTFail() }
        XCTAssertTrue(report)
        gate.finish(first); gate.finish(first)
        guard case .admitted = gate.admit(key(actor: 2), now: 4) else { return XCTFail("Pressure poisoned a future retry") }
        XCTAssertEqual(gate.snapshot()["pressureDrops"] as? UInt64, 1)
        XCTAssertEqual(gate.snapshot()["peakPending"] as? Int, 1)
    }
    func testCompletedKeyWindowExpiresAndRecordStorageStaysBounded() {
        let gate = CredentialObservationGate(maximumPending: 1, maximumEntries: 2, window: 10)
        for n in 0..<100 {
            guard case .admitted(let ticket) = gate.admit(key(path: "/\(n)/Cookies"), now: Double(n)) else { return XCTFail() }
            gate.finish(ticket)
        }
        XCTAssertEqual(gate.snapshot()["retainedKeys"] as? Int, 2)
        guard case .admitted = gate.admit(key(path: "/99/Cookies"), now: 111) else { return XCTFail() }
    }
    func testCoalescedReadStillRefreshesExactKeychainCopyEvidence() {
        let gate = CredentialObservationGate()
        let tracker = KeychainTransferFallbackTracker()
        let process = Nick.ProcessInstanceIdentity(pid: 40, startSeconds: 10, startMicroseconds: 1, pidVersion: 2)
        let reused = Nick.ProcessInstanceIdentity(pid: 40, startSeconds: 11, startMicroseconds: 1, pidVersion: 3)
        let path = "/fixture/Library/Keychains/login.keychain-db"
        let t = Date(timeIntervalSince1970: 1000)
        tracker.recordRead(sourcePath: path, process: process, at: t)
        guard case .admitted = gate.admit(key(path: path), now: 1) else { return XCTFail() }
        tracker.recordRead(sourcePath: path, process: process, at: t.addingTimeInterval(29))
        guard case .coalesced = gate.admit(key(path: path), now: 30) else { return XCTFail() }
        XCTAssertEqual(tracker.pendingReadForExternalClose(destinationPath: "/fixture/copy.db", process: process, at: t.addingTimeInterval(50))?.sourcePath, path)
        XCTAssertNil(tracker.pendingReadForExternalClose(destinationPath: "/fixture/copy.db", process: reused, at: t.addingTimeInterval(50)))
    }
    func testStaleTimerCannotCancelLaterReadOrDifferentSource() throws {
        let tracker = KeychainTransferFallbackTracker()
        let process = Nick.ProcessInstanceIdentity(pid: 41, startSeconds: 10, startMicroseconds: 1)
        let t = Date(timeIntervalSince1970: 1000)
        let first = try XCTUnwrap(tracker.recordRead(sourcePath: "/a/Library/Keychains/one", process: process, at: t))
        let second = try XCTUnwrap(tracker.recordRead(sourcePath: "/b/Library/Keychains/two", process: process, at: t.addingTimeInterval(1)))
        XCTAssertFalse(tracker.cancelIfMatching(process: process, pending: first))
        tracker.cancel(process: process, sourcePath: first.sourcePath)
        XCTAssertTrue(tracker.hasPendingRead(process: process, matching: second))
    }
    func testPressureDoesNotPreventIndependentCorrelationRecording() {
        let gate = CredentialObservationGate(maximumPending: 1, maximumEntries: 1)
        _ = gate.admit(key(), now: 1)
        let tracker = KeychainTransferFallbackTracker()
        let p = Nick.ProcessInstanceIdentity(pid: 42, startSeconds: 1, startMicroseconds: 1)
        tracker.recordRead(sourcePath: "/fixture/Library/Keychains/store", process: p, at: Date(timeIntervalSince1970: 1000))
        guard case .pressure = gate.admit(key(actor: 2), now: 2) else { return XCTFail() }
        XCTAssertNotNil(tracker.pendingReadForExternalClose(destinationPath: "/fixture/copy", process: p, at: Date(timeIntervalSince1970: 1001)))
    }
    func testValidatedCacheSingleFlightNegativeResultExpiryAndIdentityChange() {
        let cache = BoundedAttributionCache<String, String>(capacity: 2, maximumInFlight: 1, ttl: 5)
        guard case .load = cache.lookupOrReserve("process-v1-hash-A", now: 0) else { return XCTFail() }
        guard case .busy = cache.lookupOrReserve("process-v1-hash-A", now: 0) else { return XCTFail() }
        cache.complete("process-v1-hash-A", value: nil, now: 1)
        guard case .hit(let value) = cache.lookupOrReserve("process-v1-hash-A", now: 2) else { return XCTFail() }
        XCTAssertNil(value)
        guard case .load = cache.lookupOrReserve("process-v2-hash-A", now: 2) else { return XCTFail("PID reuse must not hit prior identity") }
        cache.complete("process-v2-hash-A", value: "new", now: 2)
        guard case .load = cache.lookupOrReserve("process-v1-hash-A", now: 7) else { return XCTFail("Expired trust reused") }
    }
    func testChangedIdentityResultIsNeverCachedAndCacheCapacityIsHardBounded() {
        let cache = BoundedAttributionCache<Int, Int>(capacity: 2)
        for n in 0..<100 {
            guard case .load = cache.lookupOrReserve(n, now: 0) else { return XCTFail() }
            cache.complete(n, value: n, now: 0)
        }
        XCTAssertEqual(cache.snapshot()["entries"] as? Int, 2)
        guard case .load = cache.lookupOrReserve(101, now: 0) else { return XCTFail() }
        cache.complete(101, value: 101, cache: false, now: 0)
        guard case .load = cache.lookupOrReserve(101, now: 0) else { return XCTFail("Changed image result cached") }
    }
}
