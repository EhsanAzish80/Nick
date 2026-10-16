import XCTest
@testable import Nick

final class RansomwareAtomicRenameTests: XCTestCase {
    func test_cmakeStyleRecentCreatesRenamedToFinalAcrossEightFoldersDoNotCount() {
        let tracker = BehaviorTracker()
        let now = Date()
        for index in 0..<8 {
            let source = "/tmp/build/dir\(index)/target.cmake.tmp"
            tracker.recordCreate(pid: 40, processGroupID: 30, processPath: "/tool", path: source, at: now)
            tracker.recordRename(
                pid: 40, processGroupID: 30, processPath: "/tool", source: source,
                destination: "/tmp/build/dir\(index)/target.cmake", at: now.addingTimeInterval(1)
            )
        }
        XCTAssertNil(tracker.extensionChangeBurst(pid: 40, window: 10))
    }

    func test_eightPreexistingFilesRenamedToLockedCountAsBurst() {
        let tracker = BehaviorTracker()
        let now = Date()
        for index in 0..<8 {
            tracker.recordRename(
                pid: 40, processGroupID: 30, processPath: "/tool",
                source: "/tmp/d\(index)/report\(index).pdf",
                destination: "/tmp/d\(index)/report\(index).pdf.locked", at: now
            )
        }
        XCTAssertEqual(tracker.extensionChangeBurst(pid: 40, window: 10)?.fileCount, 8)
    }

    func test_mixedBurstCountsOnlyEightPreexistingRenames() {
        let tracker = BehaviorTracker()
        let now = Date()
        for index in 0..<5 {
            let source = "/tmp/swap\(index).tmp"
            tracker.recordCreate(pid: 41, processGroupID: 30, processPath: "/tool", path: source, at: now)
            tracker.recordRename(
                pid: 40, processGroupID: 30, processPath: "/tool", source: source,
                destination: "/tmp/final\(index).locked", at: now.addingTimeInterval(1)
            )
        }
        for index in 0..<8 {
            tracker.recordRename(
                pid: 40, processGroupID: 30, processPath: "/tool",
                source: "/tmp/report\(index).pdf",
                destination: "/tmp/report\(index).pdf.locked", at: now.addingTimeInterval(1)
            )
        }
        XCTAssertEqual(tracker.extensionChangeBurst(pid: 40, window: 10)?.fileCount, 8)
    }
}
