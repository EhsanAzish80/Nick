// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import XCTest
@testable import Nick

// MARK: - PersistenceItemTests

/// Unit tests for `PersistenceItem`, `PersistenceType`, and `PersistenceScope`.
final class PersistenceItemTests: XCTestCase {

    // MARK: - PersistenceType

    func test_persistenceType_allCases_countIsExpected() {
        // Ensure no cases were accidentally added or removed
        XCTAssertEqual(PersistenceType.allCases.count, 8)
    }

    func test_persistenceType_rawValues_areStable() {
        // Raw values must not change — they are persisted to disk
        XCTAssertEqual(PersistenceType.launchDaemon.rawValue, "launchDaemon")
        XCTAssertEqual(PersistenceType.launchAgent.rawValue, "launchAgent")
        XCTAssertEqual(PersistenceType.loginItem.rawValue, "loginItem")
        XCTAssertEqual(PersistenceType.cronJob.rawValue, "cronJob")
    }

    func test_persistenceType_displayName_isNonEmpty() {
        for type in PersistenceType.allCases {
            XCTAssertFalse(type.displayName.isEmpty, "\(type) has empty displayName")
        }
    }

    // MARK: - PersistenceScope

    func test_persistenceScope_rawValues_areStable() {
        XCTAssertEqual(PersistenceScope.system.rawValue, "system")
        XCTAssertEqual(PersistenceScope.user.rawValue, "user")
    }

    // MARK: - PersistenceItem Identifiable

    func test_persistenceItem_identifiable_uniqueIDs() {
        let item1 = makeSampleItem(id: UUID())
        let item2 = makeSampleItem(id: UUID())
        XCTAssertNotEqual(item1.id, item2.id)
    }

    func test_persistenceItem_identifiable_sameIDIsEqual() {
        let sharedID = UUID()
        let item1 = makeSampleItem(id: sharedID)
        let item2 = makeSampleItem(id: sharedID)
        XCTAssertEqual(item1.id, item2.id)
    }

    // MARK: - PersistenceItem Codable

    func test_persistenceItem_codable_roundTrip() throws {
        let original = makeSampleItem(id: UUID(uuidString: "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE")!)
        let data = try JSONEncoder().encode(original)
        let decoded = try JSONDecoder().decode(PersistenceItem.self, from: data)

        XCTAssertEqual(decoded, original)
    }

    func test_persistenceItem_codable_roundTrip_withSigningStatus() throws {
        let item = PersistenceItem(
            id: UUID(),
            type: .launchAgent,
            name: "com.attacker.persist",
            path: "/Library/LaunchAgents/com.attacker.persist.plist",
            executablePath: "/tmp/payload",
            isEnabled: true,
            signingStatus: .unsigned,
            scope: .system,
            lastModified: Date(timeIntervalSince1970: 0)
        )

        let data = try JSONEncoder().encode(item)
        let decoded = try JSONDecoder().decode(PersistenceItem.self, from: data)

        XCTAssertEqual(decoded.signingStatus, .unsigned)
        XCTAssertEqual(decoded.type, .launchAgent)
    }

    // MARK: - Helpers

    private func makeSampleItem(id: UUID) -> PersistenceItem {
        PersistenceItem(
            id: id,
            type: .launchDaemon,
            name: "com.example.daemon",
            path: "/Library/LaunchDaemons/com.example.daemon.plist",
            executablePath: "/usr/local/bin/exampled",
            isEnabled: true,
            signingStatus: .signed(teamID: "TEAMID123"),
            scope: .system,
            lastModified: nil
        )
    }
}
