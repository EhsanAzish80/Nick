import XCTest
@testable import Nick

final class RansomwareNotePolicyTests: XCTestCase {
    func test_commonDeveloperFilesDoNotMatch() {
        let safeNames = [
            "README.md",
            "API_README.markdown",
            "DiskSpaceRecovery.h",
            "RansomwareDetector.swift",
            "macos_ransomware.yar",
        ]

        for filename in safeNames {
            XCTAssertFalse(
                RansomwareNotePolicy.matches(filename: filename),
                "\(filename) must not be treated as a ransom note"
            )
        }
    }

    func test_explicitDecryptionNoteMatches() {
        func decoded(_ value: String) -> String {
            String(data: Data(base64Encoded: value)!, encoding: .utf8)!
        }
        XCTAssertTrue(
            RansomwareNotePolicy.matches(filename: decoded("UkVBRE1FX0RFQ1JZUFRfRklMRVMudHh0"))
        )
        XCTAssertTrue(
            RansomwareNotePolicy.matches(filename: decoded("SE9XX1RPX0RFQ1JZUFQuaHRtbA=="))
        )
    }

    func test_containerIdentifierMatchesOwningWhatsAppBundle() {
        XCTAssertTrue(
            DeepScanner.containerIdentifier(
                "group.net.whatsapp.WhatsApp.shared",
                matchesBundleIdentifier: "net.whatsapp.WhatsApp"
            )
        )
    }

    func test_containerIdentifierRejectsUnrelatedSignedApp() {
        XCTAssertFalse(
            DeepScanner.containerIdentifier(
                "group.attacker.unrelated.shared",
                matchesBundleIdentifier: "net.whatsapp.WhatsApp"
            )
        )
    }

    func test_backupSnapshotCanaryNamesAreNotLiveRenameSources() {
        let name = ".0123456789abcdef01234567-12345678.jpg"
        let live = "/Users/test/Pictures/\(name)"
        let snapshots = [
            "/Volumes/Backup/2026-10-21-133356.previous/Macintosh HD - Data/Users/test/Pictures/\(name)",
            "/Volumes/Backup/2026-11-20-094811.inprogress/Macintosh HD - Data/Users/test/Pictures/\(name)"
        ]
        for path in snapshots {
            XCTAssertFalse(CanaryRenamePolicy.isProtectedSource(
                path: path, registeredPaths: [live], protectedDirectories: ["/Users/test/Pictures"],
                matchesManagedName: { $0 == name }
            ))
        }
        XCTAssertTrue(CanaryRenamePolicy.isProtectedSource(
            path: live, registeredPaths: [live], protectedDirectories: ["/Users/test/Pictures"],
            matchesManagedName: { $0 == name }
        ), "Moving the actual canary into any destination must still be detected")
    }

    func test_liveCanaryFallbackCoversStartupAndLegacyNamesOnlyInProtectedDirectories() {
        for name in [".0123456789abcdef01234567-12345678.docx", ".~nick_canary_test.tmp", "Nick Canary - do not modify test.docx"] {
            XCTAssertTrue(CanaryRenamePolicy.isProtectedSource(
                path: "/Users/test/Documents/\(name)", registeredPaths: [],
                protectedDirectories: ["/Users/test/Documents"], matchesManagedName: { $0 == name }
            ))
            for directory in ["/Users/other/Documents", "/Users/test/Documents/subfolder", "/tmp", "/Users/test/Documents-copy"] {
                XCTAssertFalse(CanaryRenamePolicy.isProtectedSource(
                    path: "\(directory)/\(name)", registeredPaths: [],
                    protectedDirectories: ["/Users/test/Documents"], matchesManagedName: { $0 == name }
                ))
            }
        }
    }

    func test_registeredSourcesAndNetworkHomesAreNotExcludedByVolumeNames() {
        let path = "/Volumes/Backup/actual-home/Documents/canary.docx"
        XCTAssertTrue(CanaryRenamePolicy.isProtectedSource(
            path: path, registeredPaths: [path], protectedDirectories: [], matchesManagedName: { _ in false }
        ))
        XCTAssertTrue(CanaryRenamePolicy.isProtectedSource(
            path: path, registeredPaths: [], protectedDirectories: ["/Volumes/Backup/actual-home/Documents"],
            matchesManagedName: { $0 == "canary.docx" }
        ))
        XCTAssertFalse(CanaryRenamePolicy.isProtectedSource(
            path: "Documents/canary.docx", registeredPaths: [], protectedDirectories: ["Documents"],
            matchesManagedName: { _ in true }
        ))
    }

    func test_canaryRenameScopeNormalizesPathsWithoutExpandingToSiblingDirectories() {
        let name = "canary.docx"
        let directories: Set<String> = ["/Users/test/Documents"]
        XCTAssertTrue(CanaryRenamePolicy.isProtectedSource(
            path: "/Users/test/Documents/./\(name)", registeredPaths: [], protectedDirectories: directories,
            matchesManagedName: { $0 == name }
        ))
        XCTAssertFalse(CanaryRenamePolicy.isProtectedSource(
            path: "/Users/test/Documents/../Downloads/\(name)", registeredPaths: [], protectedDirectories: directories,
            matchesManagedName: { $0 == name }
        ))
        XCTAssertFalse(CanaryRenamePolicy.isProtectedSource(
            path: "/Users/test/Documents/ordinary.docx", registeredPaths: [], protectedDirectories: directories,
            matchesManagedName: { $0 == name }
        ))
    }


    func test_canaryRenamePreservesResolvedProtectedDirectoryAliases() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let home = root.appendingPathComponent("Home")
        let physical = root.appendingPathComponent("CloudDocuments")
        try FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: physical, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let documents = home.appendingPathComponent("Documents")
        try FileManager.default.createSymbolicLink(at: documents, withDestinationURL: physical)
        let directories = CanaryRenamePolicy.directoryAliases(for: [documents])
        for directory in [documents, physical.resolvingSymlinksInPath()] {
            XCTAssertTrue(directories.contains(ESCallbackPath.normalize(directory.path)))
            XCTAssertTrue(CanaryRenamePolicy.isProtectedSource(
                path: directory.appendingPathComponent("canary.docx").path,
                registeredPaths: [], protectedDirectories: directories,
                matchesManagedName: { $0 == "canary.docx" }
            ))
        }
        XCTAssertFalse(CanaryRenamePolicy.isProtectedSource(
            path: root.appendingPathComponent("Backup/canary.docx").path,
            registeredPaths: [], protectedDirectories: directories,
            matchesManagedName: { $0 == "canary.docx" }
        ))
    }

}
