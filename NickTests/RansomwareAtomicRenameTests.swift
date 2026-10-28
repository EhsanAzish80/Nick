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

    func test_writeThenAppendLockedExtensionCountsBeforeFiftyFiles() {
        let tracker = BehaviorTracker()
        let detector = RansomwareDetector(behaviorTracker: tracker)
        let now = Date()
        var firstAlertAt: Int?
        for index in 0..<49 {
            let source = "/tmp/.document-\(index).tmp"
            let destination = "/tmp/document-\(index).txt.locked"
            tracker.recordCreate(
                pid: 70, processGroupID: 70, processPath: "/tmp/actor",
                path: source, at: now
            )
            tracker.recordRename(
                pid: 70, processGroupID: 70, processPath: "/tmp/actor",
                source: source, destination: destination,
                at: now.addingTimeInterval(1)
            )
            if detector.evaluateRename(
                pid: 70, processPath: "/tmp/actor", source: source,
                destination: destination, actorIsPlatformBinary: false
            ) != nil, firstAlertAt == nil {
                firstAlertAt = index + 1
            }
        }
        XCTAssertEqual(firstAlertAt, RansomwareDetector.extensionBurstThreshold)
        XCTAssertLessThan(try! XCTUnwrap(firstAlertAt), 50)
        XCTAssertGreaterThanOrEqual(
            detector.evaluateRename(
                pid: 70, processPath: "/tmp/actor",
                source: "/tmp/.another.tmp", destination: "/tmp/another.txt.locked",
                actorIsPlatformBinary: false
            )?.confidence ?? 0,
            0.8
        )
    }

    func test_appleSyncDaemonIdentityIsExcludedButNameAloneIsNot() {
        XCTAssertTrue(AppleSyncRenamePolicy.shouldExclude(
            isPlatformBinary: true, signingID: "com.apple.bird"
        ))
        XCTAssertFalse(AppleSyncRenamePolicy.shouldExclude(
            isPlatformBinary: false, signingID: "com.apple.bird"
        ))
        XCTAssertEqual(AppleSyncRenamePolicy.displayRole(signingID: "com.apple.bird"),
                       "iCloud Drive (bird)")
        XCTAssertTrue(AppleSyncRenamePolicy.shouldExclude(
            isPlatformBinary: true, signingID: "com.apple.mds_stores"
        ))
        XCTAssertFalse(AppleSyncRenamePolicy.shouldExclude(
            isPlatformBinary: false, signingID: "com.apple.mds_stores"
        ))
        XCTAssertEqual(AppleSyncRenamePolicy.displayRole(signingID: "com.apple.mds_stores"),
                       "Spotlight indexing (mds_stores)")
    }

    func test_routineMapAndTmpDestinationsDoNotCountAsRansomwareExtensions() {
        XCTAssertNil(RansomwareRenamePolicy.introducedExtension(
            source: "/tmp/a.old", destination: "/tmp/a.map"
        ))
        XCTAssertNil(RansomwareRenamePolicy.introducedExtension(
            source: "/tmp/a.old", destination: "/tmp/a.tmp"
        ))
    }

    func test_separatePlatformMvProcessesAggregateByResponsibleLineageAndDirectory() {
        let tracker = BehaviorTracker()
        let detector = RansomwareDetector(behaviorTracker: tracker)
        let now = Date()
        let scope = BehaviorTracker.RenameBurstScope(
            lineage: "responsible:1060",
            destinationDirectory: "/Users/test/Documents/NickScorecard"
        )
        var firstAlertAt: Int?

        for index in 0..<49 {
            let pid = Int32(10_000 + index)
            let source = "/Users/test/Documents/NickScorecard/.document-\(index).tmp"
            let destination = "/Users/test/Documents/NickScorecard/document-\(index).txt.locked"
            tracker.recordCreate(
                pid: 900, processGroupID: 700, processPath: "/bin/zsh",
                path: source, at: now
            )
            tracker.recordRename(
                pid: pid, processGroupID: 700, processPath: "/bin/mv",
                source: source, destination: destination, burstScope: scope,
                at: now.addingTimeInterval(1)
            )
            if detector.evaluateRename(
                pid: pid, processPath: "/bin/mv", source: source,
                destination: destination, burstScope: scope,
                actorIsPlatformBinary: true, actorHasTrustedSigner: true
            ) != nil, firstAlertAt == nil {
                firstAlertAt = index + 1
            }
            tracker.cleanupExited(pid: pid)
        }

        XCTAssertEqual(firstAlertAt, RansomwareDetector.extensionBurstThreshold)
        XCTAssertLessThan(try! XCTUnwrap(firstAlertAt), 50)
        XCTAssertEqual(
            tracker.extensionChangeBurst(pid: -1, burstScope: scope, window: 10)?.fileCount,
            49
        )
    }

    func test_writeThenSwapEncryptedCopiesOverPreexistingDocumentsProducesIncident() throws {
        let tracker = BehaviorTracker()
        let detector = RansomwareDetector(behaviorTracker: tracker)
        let now = Date()
        var incident: RansomwareDetector.RansomwareAlert?
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }

        for index in 0..<10 {
            let originalURL = root.appendingPathComponent("report\(index).txt")
            let temporaryURL = root.appendingPathComponent("report\(index).tmp")
            let plaintext = Data(String(repeating: "document text \(index)\n", count: 128).utf8)
            try plaintext.write(to: originalURL)
            var encrypted = Data((0..<65_536).map { _ in UInt8.random(in: .min ... .max) })
            encrypted.replaceSubrange(0..<8, with: [0x13, 0x37, 0x42, 0x99, 0x10, 0x20, 0x30, 0x40])
            try encrypted.write(to: temporaryURL)
            let original = originalURL.path
            let temporary = temporaryURL.path
            tracker.recordCreate(
                pid: 50, processGroupID: 50, processPath: "/tmp/actor",
                path: temporary, at: now
            )
            tracker.recordRename(
                pid: 50, processGroupID: 50, processPath: "/tmp/actor",
                source: temporary, destination: original,
                at: now.addingTimeInterval(1),
                replacementEvidence: .init(
                    sourceData: encrypted,
                    destinationData: plaintext,
                    destinationExisted: true
                )
            )
            try FileManager.default.removeItem(at: originalURL)
            try FileManager.default.moveItem(at: temporaryURL, to: originalURL)
            incident = detector.evaluateRename(
                pid: 50, processPath: "/tmp/actor", source: temporary,
                destination: original, actorIsPlatformBinary: false
            ) ?? incident
        }

        XCTAssertNotNil(incident)
        XCTAssertEqual(incident?.renameBurst?.fileCount, 10)
        XCTAssertEqual((try? Data(contentsOf: root.appendingPathComponent("report9.txt")))?.count,
                       65_536)
    }

    func test_cmakeReconfigureLowEntropyReplacementOfExistingFilesProducesNoIncident() throws {
        let tracker = BehaviorTracker()
        let detector = RansomwareDetector(behaviorTracker: tracker)
        let now = Date()
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }

        for index in 0..<10 {
            let directory = root.appendingPathComponent("dir\(index)", isDirectory: true)
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
            let temporaryURL = directory.appendingPathComponent("target.cmake.tmp")
            let finalURL = directory.appendingPathComponent("target.cmake")
            let oldText = Data("set(OLD_VALUE \(index))\n".utf8)
            let newText = Data("set(NEW_VALUE \(index))\n".utf8)
            try oldText.write(to: finalURL)
            try newText.write(to: temporaryURL)
            let temporary = temporaryURL.path
            let final = finalURL.path
            tracker.recordCreate(
                pid: 60, processGroupID: 60, processPath: "/tmp/tool",
                path: temporary, at: now
            )
            tracker.recordRename(
                pid: 60, processGroupID: 60, processPath: "/tmp/tool",
                source: temporary, destination: final,
                at: now.addingTimeInterval(1),
                replacementEvidence: .init(
                    sourceData: newText,
                    destinationData: oldText,
                    destinationExisted: true
                )
            )
            try FileManager.default.removeItem(at: finalURL)
            try FileManager.default.moveItem(at: temporaryURL, to: finalURL)
            XCTAssertNil(detector.evaluateRename(
                pid: 60, processPath: "/tmp/tool", source: temporary,
                destination: final, actorIsPlatformBinary: false
            ))
        }
    }
}
