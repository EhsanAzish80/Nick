import XCTest
import Darwin
@testable import Nick

/// Bounded reproduction, launched from Xcode. Synthetic files only; no real
/// credentials, backup service, external network, or installed-policy changes.
final class BackupWorkloadStressTests: XCTestCase {
    func testConcurrentBackupTrafficAndPersistenceChurnRemainBounded() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("NickBackupStress-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false,
                                                attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: root) }
        let nonce = UUID().uuidString
        try Data(nonce.utf8).write(to: root.appendingPathComponent(".nick-backup-stress-fixture"))
        let helper = Bundle.main.bundleURL.deletingLastPathComponent().appendingPathComponent("NickBackupLoadFixture")
        XCTAssertTrue(FileManager.default.isExecutableFile(atPath: helper.path), "Xcode must build the native fixture dependency")
        let process = Process()
        process.executableURL = helper
        process.arguments = [root.path, nonce]
        let output = Pipe()
        let diagnostics = Pipe()
        process.standardOutput = output
        process.standardError = diagnostics
        try process.run()
        // Only this test's child can be terminated by the bounded watchdog.
        let watchdog = DispatchWorkItem { if process.isRunning { process.terminate() } }
        DispatchQueue.global().asyncAfter(deadline: .now() + 90, execute: watchdog)
        defer { watchdog.cancel(); if process.isRunning { process.terminate(); process.waitUntilExit() } }

        let report = try await Task.detached(priority: .utility) {
            try Self.exercisePersistence(in: root)
        }.value
        await Task.detached { process.waitUntilExit() }.value
        let stdout = output.fileHandleForReading.readDataToEndOfFile()
        let stderr = diagnostics.fileHandleForReading.readDataToEndOfFile()
        let attachment = XCTAttachment(data: stdout + stderr, uniformTypeIdentifier: "public.plain-text")
        attachment.name = "Native backup workload result and phase timings"
        attachment.lifetime = .keepAlways
        add(attachment)
        let persistence = XCTAttachment(string: report)
        persistence.name = "Patched persistence byte counters and test-host RSS by phase"
        persistence.lifetime = .keepAlways
        add(persistence)
        XCTAssertEqual(process.terminationReason, .exit)
        XCTAssertEqual(process.terminationStatus, 0, String(decoding: stderr, as: UTF8.self))
        let result = try XCTUnwrap(JSONSerialization.jsonObject(with: stdout) as? [String: Any])
        XCTAssertEqual(result["reads"] as? Int, 98_304)
        XCTAssertEqual(result["files"] as? Int, 2_048)
        XCTAssertEqual(result["renames"] as? Int, 1_024)
        XCTAssertEqual(result["failures"] as? Int, 0)
    }

    func testNativeFixtureRejectsUnmarkedPublicAndWrongNonceDirectories() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("NickBackupStress-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false,
                                                attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: root) }
        let helper = Bundle.main.bundleURL.deletingLastPathComponent().appendingPathComponent("NickBackupLoadFixture")
        let nonce = UUID().uuidString
        func reject() throws {
            let child = Process()
            child.executableURL = helper
            child.arguments = [root.path, nonce]
            try child.run()
            child.waitUntilExit()
            XCTAssertEqual(child.terminationStatus, 65)
            XCTAssertFalse(FileManager.default.fileExists(atPath: root.appendingPathComponent("worker-0").path))
        }
        try reject() // No marker, even though the directory is private.
        let marker = root.appendingPathComponent(".nick-backup-stress-fixture")
        try Data(nonce.utf8).write(to: marker)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: root.path)
        try reject() // A public directory must never be used for the workload.
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: root.path)
        try Data("wrong-nonce".utf8).write(to: marker)
        try reject()
    }

    private static func exercisePersistence(in root: URL) throws -> String {
        var endpointBytes = 0
        var compactionBytes = 0
        var networkBytes = 0
        let endpointURL = root.appendingPathComponent("events/events.json")
        let endpoint = EndpointEventStore(path: endpointURL.path,
            legacyPath: root.appendingPathComponent("legacy.json").path,
            writeObserver: { writer, bytes in
                if writer == "endpoint-event-compaction" { compactionBytes += bytes }
                else { endpointBytes += bytes }
            })
        let networkURL = root.appendingPathComponent("network/events.json")
        let network = NetworkBlockEventStore(url: networkURL, writeObserver: { networkBytes += $0 })
        let throttle = NetworkObservationThrottle()
        let tracker = BehaviorTracker()
        let syntheticPath = root.appendingPathComponent("synthetic").path
        var report: [[String: Any]] = []
        var warmRSS: UInt64 = 0
        for phase in 0..<5 {
            for index in 0..<1_000 {
                try autoreleasepool {
                    let sequence = phase * 1_000 + index
                    let event = ESEvent(eventType: .authExec, processPath: syntheticPath + "/fixture", pid: 4242,
                        parentPid: 1, decision: .deny,
                        threat: .init(threatName: "Synthetic durable evidence", threatFamily: "test",
                            metadata: ["fixture": String(repeating: "x", count: 512)]))
                    endpoint.appendSynchronously(.init(kind: .threat, payload: try JSONEncoder().encode(event)))
                    endpoint.removeThreats(eventIDs: [event.id])
                    _ = endpoint.snapshot() // Complete each acknowledgement before testing restart.
                    network.append(NetworkBlockEvent(host: "host-\(sequence).invalid", appIdentifier: "fixture",
                        decision: .observed, reason: "synthetic", reasonTitle: "Synthetic network observation"))
                    _ = throttle.shouldRecord(key: "host-\(sequence)", now: Date(), interval: 300)
                    tracker.recordRename(pid: 4242, processGroupID: 4242, processPath: syntheticPath + "/fixture",
                        source: syntheticPath + "/archive-\(sequence).tar.zst.tmp",
                        destination: syntheticPath + "/archive-\(sequence).tar.zst")
                    XCTAssertNil(tracker.extensionChangeBurst(pid: 4242))
                }
            }
            let restored = EndpointEventStore(path: endpointURL.path,
                legacyPath: root.appendingPathComponent("legacy.json").path)
            XCTAssertTrue(try JSONDecoder().decode([PersistedExtensionFinding].self, from: restored.snapshot()).isEmpty)
            XCTAssertEqual(NetworkBlockEventStore.readEvents(at: networkURL).count, 500)
            XCTAssertLessThanOrEqual(throttle.retainedCount, 1_024)
            let rss = residentBytes()
            if phase == 0 { warmRSS = rss }
            report.append(["phase": phase, "testHostRSSBytes": rss,
                "endpointJournalBytesWritten": endpointBytes, "endpointCompactionBytesWritten": compactionBytes,
                "networkBytesWritten": networkBytes])
            // A coarse allocation-growth guard, not an installed-extension RSS claim.
            if warmRSS > 0, rss > warmRSS {
                XCTAssertLessThan(rss - warmRSS, 128 * 1_024 * 1_024)
            }
        }
        XCTAssertLessThan(compactionBytes, 100_000, "Acknowledgements must not rewrite the retained ring")
        XCTAssertLessThan(endpointBytes + compactionBytes, 12_000_000)
        XCTAssertLessThan(networkBytes, 2_000_000)
        XCTAssertLessThan(try Data(contentsOf: URL(fileURLWithPath: endpointURL.path + ".journal")).count, 1_024 * 1_024)
        XCTAssertLessThan(try Data(contentsOf: URL(fileURLWithPath: networkURL.path + ".journal")).count, 1_024 * 1_024)
        let data = try JSONSerialization.data(withJSONObject: report, options: [.prettyPrinted, .sortedKeys])
        return String(decoding: data, as: UTF8.self)
    }

    private static func residentBytes() -> UInt64 {
        var info = mach_task_basic_info()
        var count = mach_msg_type_number_t(MemoryLayout<mach_task_basic_info>.size / MemoryLayout<natural_t>.size)
        let result = withUnsafeMutablePointer(to: &info) {
            $0.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
                task_info(mach_task_self_, task_flavor_t(MACH_TASK_BASIC_INFO), $0, &count)
            }
        }
        return result == KERN_SUCCESS ? UInt64(info.resident_size) : 0
    }
}
