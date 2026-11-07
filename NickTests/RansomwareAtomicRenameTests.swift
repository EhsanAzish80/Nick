import XCTest
import Darwin
@testable import Nick

final class RansomwareAtomicRenameTests: XCTestCase {
    func testPrefixReaderRejectsFIFOWithoutWaitingForWriter() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let fifo = root.appendingPathComponent("pipe").path
        XCTAssertEqual(mkfifo(fifo, 0o600), 0)
        let start = Date()
        XCTAssertNil(RegularFilePrefixReader.read(path: fifo, maximumBytes: 1024))
        XCTAssertLessThan(Date().timeIntervalSince(start), 1)
        let file = root.appendingPathComponent("regular")
        try Data("abcdef".utf8).write(to: file)
        XCTAssertEqual(RegularFilePrefixReader.read(path: file.path, maximumBytes: 3), Data("abc".utf8))
        let link = root.appendingPathComponent("link")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: file)
        XCTAssertNil(RegularFilePrefixReader.read(path: link.path, maximumBytes: 3))
        XCTAssertNil(RegularFilePrefixReader.read(path: root.path, maximumBytes: 3))
    }
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

    func test_multiSuffixTemporaryFinalizationsDoNotCountAsRansomware() {
        let tracker = BehaviorTracker()
        let now = Date()
        for index in 0..<8 {
            let source = "/tmp/cache/archive-\(index).tar.zst.tmp"
            tracker.recordCreate(
                pid: 40, processGroupID: 30, processPath: "/tool",
                path: source, at: now
            )
            tracker.recordRename(
                pid: 40, processGroupID: 30, processPath: "/tool",
                source: source,
                destination: "/tmp/cache/archive-\(index).tar.zst",
                at: now.addingTimeInterval(1)
            )
        }
        XCTAssertNil(tracker.extensionChangeBurst(pid: 40, window: 10))
    }

    func test_multiSuffixFinalizationsBySeparateHelpersDoNotCountAsRansomware() {
        let tracker = BehaviorTracker()
        let now = Date()
        let scope = BehaviorTracker.RenameBurstScope(
            lineage: "responsible:1060",
            destinationDirectory: "/tmp/cache"
        )

        for index in 0..<12 {
            tracker.recordCreate(
                pid: Int32(100 + index), processGroupID: Int32(100 + index),
                processPath: "/usr/bin/touch",
                path: "/tmp/cache/archive-\(index).tar.zst.tmp", at: now
            )
            tracker.recordRename(
                pid: Int32(200 + index), processGroupID: Int32(200 + index),
                processPath: "/bin/mv",
                source: "/tmp/cache/archive-\(index).tar.zst.tmp",
                destination: "/tmp/cache/archive-\(index).tar.zst",
                burstScope: scope, at: now.addingTimeInterval(1)
            )
        }

        XCTAssertNil(tracker.extensionChangeBurst(pid: -1, burstScope: scope, window: 10))
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

    func test_appleMaintenanceRenamesRequirePlatformIdentityAndBothPathsInScope() {
        for (identity, root, suffix) in [
            ("com.apple.logd", "/var/db/diagnostics/Persist/", "tracev3"),
            ("com.apple.system_installd", "/Applications/Xcode.app/Contents/Resources/", "icns"),
            ("com.apple.mds_stores", "/.Spotlight-V100/Store-V2/", "db"),
            ("com.apple.mds_stores", "/System/Volumes/Data/.Spotlight-V100/Store-V2/", "db"),
            ("com.apple.bird", "/Users/example/Library/Application Support/CloudDocs/", "map"),
            ("com.apple.bird", "/Users/example/Library/Application Support/CloudDocs/", "meta"),
            ("com.apple.fileproviderd", "/Users/example/Library/Application Support/FileProvider/", "meta"),
            ("com.apple.parsec-fbf", "/Users/example/Library/Caches/com.apple.parsec-fbf/", "processing")
        ] {
            XCTAssertTrue(AppleSyncRenamePolicy.isRoutineMaintenanceRename(
                isPlatformBinary: true, signingID: identity,
                source: root + "pending", destination: root + "file." + suffix
            ))
            XCTAssertFalse(AppleSyncRenamePolicy.isRoutineMaintenanceRename(
                isPlatformBinary: false, signingID: identity,
                source: root + "pending", destination: root + "file." + suffix
            ))
            XCTAssertFalse(AppleSyncRenamePolicy.isRoutineMaintenanceRename(
                isPlatformBinary: true, signingID: identity,
                source: "/Users/example/Documents/file", destination: root + "file." + suffix
            ))
        }
    }

    func testWhatsAppUpdaterOnlyExemptsValidatedInBundleModelResources() {
        let root = "/Applications/WhatsApp.app/Contents/"
        func matches(_ destination: String, valid: Bool = true) -> Bool {
            ScopedUpdaterRenamePolicy.matchesWhatsAppResourceRename(actorIsAppleDitto: true,
                updaterValidated: valid, updaterPath: root + "Frameworks/Sparkle.framework/Versions/B/Autoupdate",
                updaterTeamID: "57T9237FN3", source: root + "Resources/model.tmp", destination: destination)
        }
        XCTAssertTrue(matches(root + "Resources/model.mom"))
        XCTAssertFalse(matches(root + "Resources/model.mom", valid: false))
        XCTAssertFalse(matches("/Users/test/Documents/model.mom"))
        XCTAssertFalse(matches(root + "Resources/model.locked"))
    }

    func testObservedCloudDocsTransfersAreScopedToSameUserAndStagingStructure() {
        let lib = "/Users/test/Library/"
        let source = lib + "Application Support/FileProvider/EC428E58-1A69-4DFA-A6EA-AF1072C33F5A/wharf/wharf/propagate/244405655"
        let destination = lib + "Application Support/CloudDocs/session/i/f40351d.pcm"
        func routine(_ src: String, _ dst: String, platform: Bool = true) -> Bool {
            AppleSyncRenamePolicy.isRoutineMaintenanceRename(isPlatformBinary: platform,
                signingID: "com.apple.bird", source: src, destination: dst)
        }
        XCTAssertTrue(routine(source, destination))
        XCTAssertFalse(routine(source, destination, platform: false))
        XCTAssertFalse(routine(source, destination.replacingOccurrences(of: "/Users/test/", with: "/Users/other/")))
        XCTAssertFalse(routine("/Users/test/Documents/file", destination))
        XCTAssertFalse(routine(source, "/Users/test/Documents/file.pcm"))
        XCTAssertFalse(routine(source, destination + ".locked"))
        let name = "content-4285782-bi5eo-43A056B4-611F-48D4-93D5-2FB915A8E422.woff2"
        let downloadSource = lib + "Application Support/CloudDocs/session/d/" + name + "/item"
        let downloadDestination = lib + "Group Containers/group.com.apple.iCloudDrive/File Provider Storage/DownloadStage/" + name
        XCTAssertTrue(routine(downloadSource, downloadDestination))
        XCTAssertFalse(routine(downloadSource, downloadDestination + "-different"))
        XCTAssertFalse(routine(downloadSource, downloadDestination.replacingOccurrences(of: "DownloadStage", with: "Documents")))
    }

    func testGeoServicesResourceRefreshRequiresObservedContainerAndCacheScope() {
        let source = "/Users/test/Library/Containers/com.apple.geod/Data/tmp/D5F22F84-7F03-4991-BB9B-38AB4404EA3B"
        for (folder, file) in [("Resources", "globe-default-iosmac-7420@2x.styl"),
                                ("RegionalResources", "Localized_Poi_TUR_Icons-187.iconconfigpack")] {
            let destination = "/Users/test/Library/Caches/GeoServices/" + folder + "/" + file
            func routine(_ src: String, _ dst: String, platform: Bool = true) -> Bool {
                AppleSyncRenamePolicy.isRoutineMaintenanceRename(isPlatformBinary: platform,
                    signingID: "com.apple.geod", source: src, destination: dst)
            }
            XCTAssertTrue(routine(source, destination))
            XCTAssertFalse(routine(source, destination, platform: false))
            XCTAssertFalse(routine(source, destination.replacingOccurrences(of: "/Users/test/", with: "/Users/other/")))
            XCTAssertFalse(routine(source, "/Users/test/Documents/" + file))
            XCTAssertFalse(routine(source.replacingOccurrences(of: "com.apple.geod", with: "com.evil.geod"), destination))
        }
    }

    func testCodexCompressionRequiresValidatedIdentityAndExactSessionOperation() {
        let folder = "/Users/test/.codex/sessions/2026/10/29/"
        func routine(_ src: String, _ dst: String, validated: Bool = true, team: String = "2DC432GLL2") -> Bool {
            ScopedUpdaterRenamePolicy.matchesCodexSessionCompression(developerIDValidated: validated,
                teamID: team, signingID: "codex", source: src, destination: dst)
        }
        XCTAssertTrue(routine(folder + "rollout-compress-e3yOrg.tmp", folder + "rollout-session.jsonl.zst"))
        XCTAssertFalse(routine(folder + "rollout-compress-e3yOrg.tmp", folder + "rollout-session.jsonl.zst", validated: false))
        XCTAssertFalse(routine(folder + "rollout-compress-e3yOrg.tmp", folder + "rollout-session.jsonl.zst", team: "SPOOF"))
        XCTAssertFalse(routine(folder + "rollout-compress-e3yOrg.tmp", "/Users/test/Documents/rollout-session.jsonl.zst"))
        XCTAssertFalse(routine(folder + "rollout-compress-e3yOrg.tmp", folder + "rollout-session.locked"))
        XCTAssertFalse(routine(folder + "document.txt", folder + "rollout-session.jsonl.zst"))
    }

    func test_fileProviderCannotExemptUserDocumentRenames() {
        XCTAssertFalse(AppleSyncRenamePolicy.isRoutineMaintenanceRename(
            isPlatformBinary: true, signingID: "com.apple.fileproviderd",
            source: "/Users/example/Documents/report.pdf",
            destination: "/Users/example/Documents/report.pdf.locked"
        ))
    }

    func testOpenAIUpdaterRenameRequiresSameAppAndVerifiedIdentityCandidate() {
        let app = "/Applications/ChatGPT.app/Contents/"
        let helper = app + "Frameworks/Sparkle.framework/Versions/B/Autoupdate"
        func matches(team: String, destination: String) -> Bool {
            ScopedUpdaterRenamePolicy.matchesOpenAISparkleRename(
                processPath: helper, signingID: "Autoupdate", teamID: team,
                source: app + "Resources/staged", destination: destination
            )
        }
        XCTAssertTrue(matches(team: "2DC432GLL2", destination: app + "Resources/current"))
        XCTAssertFalse(matches(team: "UNRELATED", destination: app + "Resources/current"))
        XCTAssertFalse(matches(team: "2DC432GLL2", destination: "/Users/example/Documents/report.locked"))
    }

    func test_routineMapTmpAndProcessingDestinationsDoNotCountAsRansomwareExtensions() {
        XCTAssertNil(RansomwareRenamePolicy.introducedExtension(
            source: "/tmp/a.old", destination: "/tmp/a.map"
        ))
        XCTAssertNil(RansomwareRenamePolicy.introducedExtension(
            source: "/tmp/a.old", destination: "/tmp/a.tmp"
        ))
        XCTAssertNil(RansomwareRenamePolicy.introducedExtension(
            source: "/tmp/item.cache", destination: "/tmp/item.cache.processing"
        ))
    }

    func test_processingWorkflowBurstDoesNotCountButLockedBurstStillDoes() {
        let tracker = BehaviorTracker()
        let now = Date()

        for index in 0..<8 {
            tracker.recordRename(
                pid: 52, processGroupID: 52, processPath: "/system-service",
                source: "/tmp/work/item-\(index).cache",
                destination: "/tmp/work/item-\(index).cache.processing",
                at: now
            )
        }
        XCTAssertNil(tracker.extensionChangeBurst(pid: 52, window: 10))

        for index in 0..<8 {
            tracker.recordRename(
                pid: 53, processGroupID: 53, processPath: "/untrusted-actor",
                source: "/tmp/docs/report-\(index).pdf",
                destination: "/tmp/docs/report-\(index).pdf.locked",
                at: now
            )
        }
        XCTAssertEqual(tracker.extensionChangeBurst(pid: 53, window: 10)?.fileCount, 8)
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
