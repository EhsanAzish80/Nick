import XCTest
@testable import Nick

final class ProcessTreeBoundsTests: XCTestCase {
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
