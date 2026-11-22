import XCTest
@testable import Nick

final class DeferredAuthReplyTests: XCTestCase {
    func testWorkerDecisionsAndTerminalFailuresAreNotReplacedByTimeout() {
        for allow in [false,true] {
            for accepted in [false,true] {
                let reply = DeferredAuthReply()
                let first = reply.submit(source: .worker, allow: allow) { decision, _ in
                    XCTAssertEqual(decision,allow)
                    return accepted ? .accepted : .terminalFailure
                }
                XCTAssertEqual(first?.allow,allow); XCTAssertTrue(first!.final)
                XCTAssertEqual(first?.accepted,accepted)
                XCTAssertNil(reply.submit(source: .watchdog, allow: !allow) { _, _ in XCTFail("Terminal reply retried"); return .accepted })
            }
        }
    }
    func testCommunicationRecoveryIsBoundedAndPreservesAllowToo() {
        let reply = DeferredAuthReply()
        _ = reply.submit(source: .worker, allow: true) { _, _ in .communicationFailure }
        XCTAssertNil(reply.submit(source: .worker, allow: false) { _, _ in XCTFail("Worker cannot steal recovery"); return .accepted })
        let second = reply.submit(source: .watchdog, allow: false) { allow, number in
            XCTAssertTrue(allow); XCTAssertEqual(number,2); return .communicationFailure
        }
        XCTAssertTrue(second!.final); XCTAssertFalse(second!.accepted)
        XCTAssertNil(reply.submit(source: .watchdog, allow: false) { _, _ in XCTFail("Unbounded retry"); return .accepted })
    }
    func testNoConcurrentSubmissionWhileResponseAPIIsInFlight() {
        let reply = DeferredAuthReply(), entered = DispatchSemaphore(value: 0), release = DispatchSemaphore(value: 0)
        let done = expectation(description:"response returns")
        DispatchQueue.global().async {
            _ = reply.submit(source:.worker,allow:false) { _, _ in
                entered.signal(); _ = release.wait(timeout:.now() + 5); return .accepted
            }
            done.fulfill()
        }
        defer { release.signal() }
        XCTAssertEqual(entered.wait(timeout:.now() + 2),.success)
        XCTAssertNil(reply.submit(source:.watchdog,allow:true) { _, _ in XCTFail("Concurrent API response"); return .accepted })
        release.signal(); wait(for:[done],timeout:6)
    }
}

final class AuthWatchdogSchedulerTests: XCTestCase {
    func testWatchdogRespondsWhileWorkerQueueIsBlocked() {
        let scheduler = AuthWatchdogScheduler(); defer { scheduler.stop() }
        let reply = DeferredAuthReply(), worker = DispatchQueue(label:"test.blocked.worker")
        let started = DispatchSemaphore(value:0), release = DispatchSemaphore(value:0)
        let fired = expectation(description:"independent timer responds"), done = expectation(description:"worker released")
        worker.async {
            started.signal(); _ = release.wait(timeout:.now() + 5)
            XCTAssertNil(reply.submit(source:.worker,allow:false) { _, _ in XCTFail("Late worker"); return .accepted })
            done.fulfill()
        }
        defer { release.signal() }
        XCTAssertEqual(started.wait(timeout:.now() + 2),.success)
        scheduler.schedule(at:.now() + .milliseconds(20)) {
            XCTAssertEqual(Thread.current.name,"Nick AUTH watchdog")
            XCTAssertTrue(reply.submit(source:.watchdog,allow:true) { _, _ in .accepted }?.accepted == true)
            fired.fulfill()
        }
        wait(for:[fired],timeout:2); release.signal(); wait(for:[done],timeout:6)
    }
    func testTimersRunInDeadlineOrderAndCancellationPreventsPendingWork() {
        let scheduler = AuthWatchdogScheduler(); defer { scheduler.stop() }
        let done = expectation(description:"three ordered timers"); done.expectedFulfillmentCount = 3
        let lock = NSLock(); var order:[Int] = []; let now = DispatchTime.now()
        for (value,delay) in [(3,90),(1,30),(2,60)] {
            scheduler.schedule(at:now + .milliseconds(delay)) { lock.withLock { order.append(value) }; done.fulfill() }
        }
        let token = scheduler.schedule(at:now + .milliseconds(50)) { XCTFail("Cancelled callback ran") }
        scheduler.cancel(token)
        wait(for:[done],timeout:2); XCTAssertEqual(lock.withLock { order },[1,2,3])
    }
    func testCancelReleasesCapturedStateAndPendingStorage() {
        final class Marker {}
        let scheduler = AuthWatchdogScheduler(); defer { scheduler.stop() }
        var marker:Marker? = Marker(); weak var weakMarker = marker
        let token = scheduler.schedule(at:.now() + .seconds(60)) { [held=marker!] in withExtendedLifetime(held) {} }
        marker = nil; XCTAssertNotNil(weakMarker)
        scheduler.cancel(token); XCTAssertNil(weakMarker); XCTAssertEqual(scheduler.pendingCount,0)
        for _ in 0..<1000 { scheduler.cancel(scheduler.schedule(at:.now() + .seconds(60)) {}) }
        XCTAssertEqual(scheduler.pendingCount,0)
    }
}
