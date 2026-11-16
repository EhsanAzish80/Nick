import XCTest
@testable import Nick

final class PerformanceSafetyTests: XCTestCase {
    func testCallbackPathsNormalizeLexicallyWithoutExistingFiles() {
        XCTAssertEqual(ESCallbackPath.normalize("/never-existing/a/../b//./file"), "/never-existing/b/file")
        XCTAssertEqual(ESCallbackPath.normalize("/../../"), "/")
        XCTAssertEqual(ESCallbackPath.basename("/folder/文件"), "文件")
        XCTAssertEqual(CredentialAccessPolicy.sensitiveStore(at: "/Users/test/a/../.ssh/id_ed25519"), .sshPrivateKey)
        XCTAssertNil(CredentialAccessPolicy.sensitiveStore(at: "/Users/test/.ssh/../ordinary"))
    }

    func testBackupSizedOpenBurstPreservesCredentialClassification() {
        // A bounded replay of classification work, not an installed ES benchmark.
        for index in 0..<50_000 {
            XCTAssertNil(CredentialAccessPolicy.sensitiveStore(at: "/Volumes/Backup/project/dir/asset-\(index).dat"))
        }
        XCTAssertEqual(CredentialAccessPolicy.sensitiveStore(at: "/Users/test/Library/Keychains/login.keychain-db"), .keychain)
        XCTAssertEqual(CredentialAccessPolicy.sensitiveStore(at: "/Users/test/Library/Application Support/Google/Chrome/Default/Cookies"), .browserCookies)
    }


    func test_fseventsQueueCoalescesAndReportsOverflow() {
        var queue = BoundedPathQueue(capacity: 2)
        XCTAssertTrue(queue.enqueue("/tmp/a"))
        XCTAssertTrue(queue.enqueue("/tmp/a"), "Duplicate paths must coalesce without consuming capacity")
        XCTAssertTrue(queue.enqueue("/tmp/b"))
        XCTAssertFalse(queue.enqueue("/tmp/c"), "A full queue must report overflow to the caller")
        XCTAssertEqual(queue.dequeue(), "/tmp/a")
        XCTAssertEqual(queue.dequeue(), "/tmp/b")
        XCTAssertNil(queue.dequeue())
    }

    func testRealtimeWatcherDoesNotObserveWholeHomeOrApplicationSupport() {
        let paths = FileSystemWatcher.defaultMonitoredDirectories

        XCTAssertFalse(paths.contains(NSHomeDirectory()))
        XCTAssertFalse(paths.contains { $0.hasSuffix("/Library/Application Support") })
        XCTAssertFalse(paths.contains("/private/tmp"))
        XCTAssertTrue(paths.contains { $0.hasSuffix("/Downloads") })
    }

    @MainActor
    func testBackgroundSweepHasFiveMinuteMinimum() {
        let defaults = UserDefaults.standard
        let key = "deepScanIntervalSeconds"
        let previous = defaults.object(forKey: key)
        defer {
            if let previous {
                defaults.set(previous, forKey: key)
            } else {
                defaults.removeObject(forKey: key)
            }
        }

        defaults.set(30, forKey: key)
        let engine = SecurityEngine()
        let coordinator = MonitorCoordinator(engine: engine)

        XCTAssertEqual(coordinator.deepScanInterval, 300)
    }

    @MainActor
    func testMonitorCoordinatorUsesSecurityEngineCorrelator() {
        let engine = SecurityEngine()
        let coordinator = MonitorCoordinator(engine: engine)

        XCTAssertTrue(coordinator.usesEngineCorrelator)
    }
}
