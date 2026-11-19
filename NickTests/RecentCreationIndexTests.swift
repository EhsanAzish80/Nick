import XCTest
@testable import Nick

final class RecentCreationIndexTests: XCTestCase {
    private struct Creation: Equatable {
        let pid: Int32
        let group: Int32
        let timestamp: Date
    }
    private func date(_ seconds: Double) -> Date { Date(timeIntervalSince1970: seconds) }
    private func atomic(_ value: Creation?, pid: Int32, group: Int32, at time: Date) -> Bool {
        guard let value else { return false }
        return time.timeIntervalSince(value.timestamp) <= 10 && (value.pid == pid || value.group == group)
    }
    func testRandomizedEquivalenceToPreviousFilterAndSort() {
        // Unique timestamps permit an exact reference comparison. Equal-time
        // eviction was unspecified in the old dictionary iteration/sort.
        var heap = RecentCreationIndex<Creation>(), old: [String: Creation] = [:]
        var seed: UInt64 = 0x5110
        func random() -> UInt64 { seed = seed &* 6364136223846793005 &+ 1; return seed }
        for step in 0..<20_000 {
            let path = "/fixture/\(random() % 128)"
            let time = date(Double(random() % 180) + Double(step) / 1_000_000)
            let pid = Int32(random() % 4), group = Int32(random() % 2)
            let operation = random() % 5
            if operation < 3 {
                let value = Creation(pid: pid, group: group, timestamp: time)
                old[path] = value; heap.update(path: path, value: value, timestamp: time)
            }
            if operation < 4 {
                let cutoff = time.addingTimeInterval(-60)
                old = old.filter { $0.value.timestamp >= cutoff }
                if old.count > 64 {
                    let remove = old.sorted { $0.value.timestamp < $1.value.timestamp }.prefix(old.count - 64).map(\.key)
                    for key in remove { old.removeValue(forKey: key) }
                }
                heap.prune(before: cutoff, capacity: 64)
            }
            XCTAssertEqual(atomic(heap[path], pid: pid, group: group, at: time), atomic(old[path], pid: pid, group: group, at: time), "step \(step)")
            if operation == 3 { old.removeValue(forKey: path); heap.removeValue(forKey: path) }
            if operation == 4 {
                old = old.filter { $0.value.pid != pid }; heap.removeAll { $0.pid == pid }
            }
            XCTAssertEqual(heap.count, old.count)
            for key in 0..<128 { XCTAssertEqual(heap["/fixture/\(key)"], old["/fixture/\(key)"], "step \(step), path \(key)") }
        }
    }
    func testExpiryKeepsBoundaryAndRemovesAllOlderEntries() {
        var heap = RecentCreationIndex<Int>()
        heap.update(path: "old", value: 1, timestamp: date(9))
        heap.update(path: "boundary", value: 2, timestamp: date(10))
        heap.prune(before: date(10), capacity: 4096)
        XCTAssertNil(heap["old"]); XCTAssertEqual(heap["boundary"], 2)
    }
    func testOutOfOrderTimestampsEvictTimestampOldestNotFirstInserted() {
        var heap = RecentCreationIndex<Int>()
        for (path, time) in [("new", 30.0), ("old", 10), ("middle", 20)] { heap.update(path: path, value: Int(time), timestamp: date(time)) }
        heap.prune(before: date(0), capacity: 2)
        XCTAssertNil(heap["old"]); XCTAssertEqual(heap["new"], 30); XCTAssertEqual(heap["middle"], 20)
    }
    func testSamePathRefreshRepairsBothDirectionsWithoutStaleSlots() {
        var heap = RecentCreationIndex<Int>()
        heap.update(path: "a", value: 1, timestamp: date(1))
        heap.update(path: "b", value: 2, timestamp: date(2))
        for n in 0..<10_000 { heap.update(path: "a", value: n, timestamp: date(Double(n % 4))) }
        XCTAssertEqual(heap.count, 2)
        heap.update(path: "a", value: 100, timestamp: date(10))
        heap.prune(before: date(3), capacity: 1)
        XCTAssertEqual(heap["a"], 100); XCTAssertNil(heap["b"])
        heap.update(path: "a", value: -1, timestamp: date(0))
        heap.prune(before: date(1), capacity: 1); XCTAssertEqual(heap.count, 0)
    }
    func testEqualTimestampTieIsDeterministicAndBounded() {
        var heap = RecentCreationIndex<Int>()
        for path in ["c", "a", "b"] { heap.update(path: path, value: 1, timestamp: date(1)) }
        heap.prune(before: date(1), capacity: 2)
        XCTAssertNil(heap["a"]); XCTAssertEqual(heap.count, 2)
    }
    func testRemovingArbitraryPathsPreservesIndexAfterRebalancing() {
        var heap = RecentCreationIndex<Int>()
        for n in 0..<100 { heap.update(path: "\(n)", value: n, timestamp: date(Double(n))) }
        for n in stride(from: 99, through: 0, by: -2) { XCTAssertEqual(heap.removeValue(forKey: "\(n)"), n) }
        heap.prune(before: date(50), capacity: 100)
        for n in 0..<100 { XCTAssertEqual(heap["\(n)"], n >= 50 && n % 2 == 0 ? n : nil) }
    }
    func testActual4096CapEvictionRemovesAtomicSaveExemption() {
        let tracker = BehaviorTracker(), now = Date()
        tracker.recordCreate(pid: 10, processGroupID: 10, processPath: "/fixture", path: "/old.tmp", at: now)
        for n in 0..<4096 {
            tracker.recordCreate(pid: 10, processGroupID: 10, processPath: "/fixture", path: "/\(n).tmp", at: now.addingTimeInterval(Double(n + 1) / 10000))
        }
        XCTAssertFalse(tracker.wasRecentlyCreated(path: "/old.tmp", by: 10, processGroupID: 10, at: now.addingTimeInterval(1)))
        XCTAssertTrue(tracker.wasRecentlyCreated(path: "/4095.tmp", by: 10, processGroupID: 10, at: now.addingTimeInterval(1)))
        for n in 0..<8 {
            tracker.recordRename(pid: 10, processGroupID: 10, processPath: "/fixture", source: "/evicted-\(n).tmp", destination: "/document-\(n).txt.locked", at: now.addingTimeInterval(1))
        }
        XCTAssertNotNil(tracker.extensionChangeBurst(pid: 10))
    }
}
