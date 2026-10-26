import XCTest
@testable import Nick

final class ProcessTreeBoundsTests: XCTestCase {
    func testESCallbackHotPathUsesKernelMessageFieldsNotForeignProcessQueries() throws {
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent()
        let source = try String(
            contentsOf: root.appendingPathComponent("NickExtension/EventHandler.swift"),
            encoding: .utf8
        )
        let handle = try XCTUnwrap(source.range(of: "func handle(message:"))
        let switchStart = try XCTUnwrap(source.range(of: "switch msg.event_type", range: handle.lowerBound..<source.endIndex))
        let prefix = String(source[handle.lowerBound..<switchStart.lowerBound])

        XCTAssertFalse(prefix.contains("getpgid("))
        XCTAssertFalse(prefix.contains("ProcessInstanceIdentity.capture"))
        XCTAssertTrue(prefix.contains("process.group_id"))
        XCTAssertTrue(prefix.contains("process.start_time"))
        XCTAssertTrue(prefix.contains("audit_token_to_pidversion"))
        XCTAssertTrue(prefix.contains("process.session_id"))
    }

#if DEBUG
    func testBlockingForeignProcessResolverNeverRunsSynchronouslyOnHandlerCaller() {
        let scheduler = ESForeignProcessWorkScheduler()
        let resolverStarted = expectation(description: "resolver started off callback")
        let resolverFinished = expectation(description: "resolver finished")
        let unblock = DispatchSemaphore(value: 0)
        let resolver: @Sendable () -> Int = {
            resolverStarted.fulfill()
            _ = unblock.wait(timeout: .now() + 2)
            return 42
        }

        let start = ContinuousClock.now
        scheduler.schedule(operation: resolver) { _ in
            resolverFinished.fulfill()
        }
        XCTAssertLessThan(start.duration(to: .now), .milliseconds(50))
        wait(for: [resolverStarted], timeout: 1)
        unblock.signal()
        wait(for: [resolverFinished], timeout: 1)
    }
#endif

    func test_longArgumentSnapshotsAreBoundedAndReleasedOnExit() throws {
        let tree = ProcessTree()
        let longArguments = (0..<100).map { "arg-\($0)-" + String(repeating: "x", count: 1_024) }

        tree.recordExec(pid: 42, ppid: 1, path: "/bin/zsh", args: longArguments)

        let node = try XCTUnwrap(tree.attackChain(pid: 42).last)
        XCTAssertLessThanOrEqual(node.args.count, ProcessTree.maximumArgumentCount)
        XCTAssertLessThanOrEqual(
            node.args.reduce(0) { $0 + $1.utf8.count },
            ProcessTree.maximumArgumentBytes
        )
        XCTAssertTrue(node.args.last?.contains("<truncated>") == true)

        tree.recordExit(pid: 42, exitCode: 0)
        XCTAssertEqual(tree.retainedArgumentBytes, 0)
        XCTAssertEqual(tree.attackChain(pid: 42).last?.args, [])
    }

    func test_tenThousandLongArgExecsKeepTreeMemoryBounded() {
        let tree = ProcessTree()
        let longArguments = (0..<100).map { _ in String(repeating: "x", count: 1_024) }

        for pid in 10_000..<20_000 {
            tree.recordExec(pid: Int32(pid), ppid: 1, path: "/bin/zsh", args: longArguments)
        }

        XCTAssertEqual(tree.count, ProcessTree.maximumBenignNodeCount)
        XCTAssertLessThanOrEqual(
            tree.retainedArgumentBytes,
            ProcessTree.maximumBenignNodeCount * ProcessTree.maximumArgumentBytes
        )
        XCTAssertTrue(tree.attackChain(pid: 10_000).isEmpty)
        XCTAssertFalse(tree.attackChain(pid: 19_999).isEmpty)
    }
}
