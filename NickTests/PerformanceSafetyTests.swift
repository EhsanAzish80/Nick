import XCTest
@testable import Nick

final class PerformanceSafetyTests: XCTestCase {

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
        let coordinator = MonitorCoordinator(
            engine: engine,
            correlator: ThreatCorrelator()
        )

        XCTAssertEqual(coordinator.deepScanInterval, 300)
    }
}
