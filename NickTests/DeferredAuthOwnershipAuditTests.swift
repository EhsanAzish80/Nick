import XCTest
@testable import Nick

/// Regression tests use the same submission coordinator as RetainedMessage.
/// Synthetic submissions never contact or suspend the installed ES extension.
final class DeferredAuthOwnershipAuditTests: XCTestCase {
    func testWatchdogCanWinWhileWorkerIsStillComputing() {
        let reply = DeferredAuthReply(), pending = PendingAuthDiagnostics()
        let key = PendingAuthDiagnostics.Key(address: 1, machTime: 100)
        pending.received(key, event: 1, deadline: 200)
        pending.phase(key, .credentialValidation)
        let result = reply.submit(source: .watchdog, allow: true) { allow, _ in
            XCTAssertTrue(allow)
            pending.responseStarted(key); pending.responseReturned(key, accepted: true)
            return .accepted
        }
        XCTAssertTrue(result?.accepted == true)
        XCTAssertNil(reply.submit(source: .worker, allow: false) { _, _ in XCTFail("Second response"); return .accepted })
        XCTAssertEqual(pending.snapshot(now: 210)["pending"] as? Int, 0)
    }

    func testStalledPolicyWorkDoesNotReserveReplyFromWatchdog() {
        let reply = DeferredAuthReply()
        let started = DispatchSemaphore(value: 0), release = DispatchSemaphore(value: 0)
        let finished = expectation(description: "bounded policy work ends")
        DispatchQueue.global().async {
            started.signal()
            _ = release.wait(timeout: .now() + 5)
            XCTAssertNil(reply.submit(source: .worker, allow: false) { _, _ in XCTFail("Late worker response"); return .accepted })
            finished.fulfill()
        }
        defer { release.signal() }
        XCTAssertEqual(started.wait(timeout: .now() + 2), .success)
        XCTAssertTrue(reply.submit(source: .watchdog, allow: true) { _, _ in .accepted }?.accepted == true)
        release.signal(); wait(for: [finished], timeout: 6)
    }

    func testCommunicationErrorCanBeRetriedOnceWithoutChangingDeny() {
        let reply = DeferredAuthReply(), pending = PendingAuthDiagnostics()
        let key = PendingAuthDiagnostics.Key(address: 3, machTime: 100)
        pending.received(key, event: 0, deadline: 200)
        let first = reply.submit(source: .worker, allow: false) { allow, number in
            XCTAssertFalse(allow); XCTAssertEqual(number, 1)
            pending.responseStarted(key); pending.responseReturned(key, accepted: false)
            return .communicationFailure
        }
        XCTAssertFalse(first!.final); XCTAssertFalse(reply.isFinished)
        let retry = reply.submit(source: .watchdog, allow: true) { allow, number in
            XCTAssertFalse(allow, "A failed deny must never become a timeout allow")
            XCTAssertEqual(number, 2)
            pending.responseStarted(key, isRetry: true); pending.responseReturned(key, accepted: true)
            return .accepted
        }
        XCTAssertFalse(retry!.allow); XCTAssertTrue(retry!.accepted); XCTAssertTrue(reply.isFinished)
        XCTAssertEqual(pending.snapshot(now: 210)["pending"] as? Int, 0)
        XCTAssertEqual(pending.snapshot(now: 210)["retryAttempts"] as? UInt64, 1)
        XCTAssertEqual(pending.snapshot(now: 210)["duplicateAttemptsWhilePending"] as? UInt64, 0)
    }
}
