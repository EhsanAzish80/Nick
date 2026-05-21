import XCTest

final class NickIntegrationTests: XCTestCase {

    func testPersistenceWatcherInitializes() async {
        let watcher = await PersistenceWatcher()
        await watcher.start()
        let running = await watcher.isRunning
        XCTAssertTrue(running)
        await watcher.stop()
    }
}
