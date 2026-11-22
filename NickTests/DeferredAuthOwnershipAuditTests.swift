import XCTest
@testable import Nick

/// Characterizes the actual coordination primitives used by RetainedMessage.
/// These tests do not instantiate an ES client or run EventHandler's private
/// retained-message paths, and do not establish a cause of #122.
final class DeferredAuthOwnershipAuditTests: XCTestCase {
    func testWatchdogCanWinWhileWorkerIsStillBeforeClaim() {
        let claim = AuthResponseClaim(), pending = PendingAuthDiagnostics()
        let key = PendingAuthDiagnostics.Key(address: 1, machTime: 100)
        pending.received(key, event: 1, deadline: 200)
        pending.phase(key, .credentialValidation)
        XCTAssertTrue(claim.claim(), "Watchdog may win before worker ownership")
        pending.phase(key, .watchdogClaimed)
        pending.responseStarted(key)
        pending.responseReturned(key, accepted: true)
        XCTAssertFalse(claim.claim(), "Late worker must lose ownership")
        XCTAssertEqual(pending.snapshot(now: 210)["pending"] as? Int, 0)
    }

    func testWorkerClaimDoesNotGuaranteeReplyAndWatchdogCannotTakeOver() throws {
        let claim = AuthResponseClaim(), pending = PendingAuthDiagnostics()
        let key = PendingAuthDiagnostics.Key(address: 2, machTime: 100)
        pending.received(key, event: 1, deadline: 200)
        let claimed = DispatchSemaphore(value: 0), release = DispatchSemaphore(value: 0)
        let finished = expectation(description: "bounded worker released")
        DispatchQueue.global().async {
            if claim.claim() {
                pending.phase(key, .workerClaimed)
                claimed.signal()
                // A controlled stand-in for blocking after claim. Never touch
                // the installed extension and never leave a blocked test thread.
                _ = release.wait(timeout: .now() + 2)
            }
            finished.fulfill()
        }
        let arrived = claimed.wait(timeout: .now() + 1)
        defer { release.signal() }
        XCTAssertEqual(arrived, .success)
        XCTAssertFalse(claim.claim(), "Watchdog cannot rescue an owned request")
        let warning = try XCTUnwrap(pending.warnings(now: 201).first)
        XCTAssertEqual(warning["phase"] as? String, "workerClaimed")
        XCTAssertEqual(warning["responseAttempts"] as? Int, 0)
        XCTAssertEqual(pending.snapshot(now: 201)["pending"] as? Int, 1)
        release.signal()
        wait(for: [finished], timeout: 3)
    }

    func testRejectedResponseRemainsPendingButDoesNotReopenOwnership() throws {
        let claim = AuthResponseClaim(), pending = PendingAuthDiagnostics()
        let key = PendingAuthDiagnostics.Key(address: 3, machTime: 100)
        pending.received(key, event: 0, deadline: 200)
        XCTAssertTrue(claim.claim())
        pending.phase(key, .workerClaimed)
        pending.responseStarted(key)
        pending.responseReturned(key, accepted: false)
        XCTAssertFalse(claim.claim(), "The real one-shot claim does not reopen after API failure")
        let snapshot = pending.snapshot(now: 201)
        XCTAssertEqual(snapshot["pending"] as? Int, 1)
        XCTAssertEqual(snapshot["failedResponseReturns"] as? UInt64, 1)
        let warning = try XCTUnwrap(pending.warnings(now: 201).first)
        XCTAssertEqual(warning["phase"] as? String, "responseFailed")
        XCTAssertEqual(warning["responseAttempts"] as? Int, 1)
    }
}
