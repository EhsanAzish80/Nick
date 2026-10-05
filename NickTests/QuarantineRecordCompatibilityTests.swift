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
}
