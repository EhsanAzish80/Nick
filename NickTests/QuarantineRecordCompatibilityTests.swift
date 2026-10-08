// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import XCTest
@testable import Nick

final class QuarantineRecordCompatibilityTests: XCTestCase {

    func test_decodesLegacyRecordWithoutFileMetadata() throws {
        let id = UUID()
        let json = """
        {
          "id": "\(id.uuidString)",
          "originalPath": "/Users/test/Downloads/sample",
          "quarantinedPath": "/Library/Application Support/com.ehsanazish.nick/Quarantine/sample",
          "hash": "abc",
          "threatName": "test",
          "severity": "critical",
          "quarantinedAt": 0,
          "processPath": "",
          "pid": 0
        }
        """

        let record = try JSONDecoder().decode(
            QuarantineRecord.self,
            from: Data(json.utf8)
        )

        XCTAssertEqual(record.id, id)
        XCTAssertNil(record.originalOwnerID)
        XCTAssertNil(record.originalGroupID)
        XCTAssertNil(record.originalPermissions)
    }

    func test_roundTripsOriginalFileMetadata() throws {
        let record = QuarantineRecord(
            id: UUID(),
            originalPath: "/Users/test/Downloads/sample",
            quarantinedPath: "/Library/Application Support/com.ehsanazish.nick/Quarantine/sample",
            hash: "abc",
            threatName: "test",
            severity: "critical",
            quarantinedAt: Date(timeIntervalSince1970: 1_790_000_000),
            processPath: "",
            pid: 0,
            originalOwnerID: 501,
            originalGroupID: 20,
            originalPermissions: 0o750
        )

        let decoded = try JSONDecoder().decode(
            QuarantineRecord.self,
            from: JSONEncoder().encode(record)
        )

        XCTAssertEqual(decoded.originalOwnerID, 501)
        XCTAssertEqual(decoded.originalGroupID, 20)
        XCTAssertEqual(decoded.originalPermissions, 0o750)
    }

    func test_legacyMacOSAliasesResolveBelowPrivate() {
        XCTAssertEqual(
            QuarantineRestorePolicy.canonicalPathForLegacyRecord("/tmp/sample"),
            "/private/tmp/sample"
        )
        XCTAssertEqual(
            QuarantineRestorePolicy.canonicalPathForLegacyRecord("/var/folders/sample"),
            "/private/var/folders/sample"
        )
        XCTAssertEqual(
            QuarantineRestorePolicy.canonicalPathForLegacyRecord("/etc/hosts"),
            "/private/etc/hosts"
        )
        XCTAssertEqual(
            QuarantineRestorePolicy.canonicalPathForLegacyRecord("/Users/test/sample"),
            "/Users/test/sample"
        )
    }

    func test_restoreNeverReappliesSetIDBits() {
        XCTAssertEqual(QuarantineRestorePolicy.restoredPermissions(0o6755), 0o755)
        XCTAssertEqual(QuarantineRestorePolicy.restoredPermissions(0o1755), 0o1755)
        XCTAssertEqual(QuarantineRestorePolicy.restoredPermissions(nil), 0o600)
    }

    func test_quarantineMoveRequiresReviewedIdentityAndHashBeforeAndAfterMove() throws {
        let file = FileManager.default.temporaryDirectory
            .appendingPathComponent("NickQuarantineIdentity-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: file) }
        try Data("reviewed".utf8).write(to: file)
        let reviewed = try XCTUnwrap(FileIdentity(path: file.path))

        XCTAssertTrue(QuarantineMovePolicy.matchesReviewedFile(
            reviewedIdentity: reviewed,
            reviewedHash: "reviewed-hash",
            currentIdentity: reviewed,
            currentHash: "reviewed-hash"
        ))
        XCTAssertFalse(QuarantineMovePolicy.matchesReviewedFile(
            reviewedIdentity: reviewed,
            reviewedHash: "reviewed-hash",
            currentIdentity: reviewed,
            currentHash: "replacement-hash"
        ))

        try Data("replacement".utf8).write(to: file)
        let replaced = try XCTUnwrap(FileIdentity(path: file.path))
        XCTAssertFalse(QuarantineMovePolicy.matchesReviewedFile(
            reviewedIdentity: reviewed,
            reviewedHash: "reviewed-hash",
            currentIdentity: replaced,
            currentHash: "reviewed-hash"
        ))
    }
}
