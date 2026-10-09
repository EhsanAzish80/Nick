import XCTest
@testable import Nick

final class PrivilegedIncidentFileStoreTests: XCTestCase {
    private var temporaryDirectory: URL!

    override func setUpWithError() throws {
        temporaryDirectory = FileManager.default.temporaryDirectory
            .appendingPathComponent("NickIncidentStoreTests-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(
            at: temporaryDirectory,
            withIntermediateDirectories: true
        )
    }

    override func tearDownWithError() throws {
        if let temporaryDirectory {
            try? FileManager.default.removeItem(at: temporaryDirectory)
        }
    }

    func test_migrationIsIdempotentAndDoesNotReplaceExistingEvidence() throws {
        let fileURL = temporaryDirectory.appendingPathComponent("state/incidents.json")
        let store = PrivilegedIncidentFileStore(fileURL: fileURL)
        let original = try XCTUnwrap("{\"incident\":\"original\"}".data(using: .utf8))
        let replacement = try XCTUnwrap("{\"incident\":\"replacement\"}".data(using: .utf8))

        let first = store.migrate(payload: original)
        let repeated = store.migrate(payload: replacement)
        let firstRecord = try JSONDecoder().decode(PrivilegedIncidentStoreRecord.self, from: first.record)
        let repeatedRecord = try JSONDecoder().decode(PrivilegedIncidentStoreRecord.self, from: repeated.record)

        XCTAssertTrue(first.accepted)
        XCTAssertTrue(repeated.accepted)
        XCTAssertEqual(firstRecord.revision, 1)
        XCTAssertEqual(repeatedRecord, firstRecord)
        XCTAssertEqual(repeatedRecord.payload, original)
    }

    func test_existingRootSettingsIgnoreASecondDefaultsMigration() throws {
        let fileURL = temporaryDirectory.appendingPathComponent("state/settings.json")
        let store = PrivilegedIncidentFileStore(fileURL: fileURL)
        let approved = try XCTUnwrap("{\"threshold\":3}".data(using: .utf8))
        let defaultsTampering = try XCTUnwrap("{\"threshold\":0}".data(using: .utf8))

        XCTAssertTrue(store.migrate(payload: approved).accepted)
        let repeated = store.migrate(payload: defaultsTampering)
        let record = try JSONDecoder().decode(PrivilegedIncidentStoreRecord.self, from: repeated.record)

        XCTAssertTrue(repeated.accepted)
        XCTAssertEqual(record.payload, approved)
    }

    func test_changeOnlyPersistenceKeepsRevisionForIdenticalPayload() throws {
        let fileURL = temporaryDirectory.appendingPathComponent("state/incidents.json")
        let store = PrivilegedIncidentFileStore(fileURL: fileURL)
        let payload = try XCTUnwrap("{\"incidents\":[]}".data(using: .utf8))
        let migrated = store.migrate(payload: payload)
        let first = try JSONDecoder().decode(PrivilegedIncidentStoreRecord.self, from: migrated.record)

        let unchanged = store.replace(payload: payload, expectedRevision: first.revision)
        let second = try JSONDecoder().decode(PrivilegedIncidentStoreRecord.self, from: unchanged.record)

        XCTAssertTrue(unchanged.accepted)
        XCTAssertEqual(second.revision, first.revision)
        XCTAssertEqual(second.payload, payload)
    }

    func test_staleRevisionCannotOverwriteNewerEvidence() throws {
        let fileURL = temporaryDirectory.appendingPathComponent("state/incidents.json")
        let store = PrivilegedIncidentFileStore(fileURL: fileURL)
        let firstPayload = try XCTUnwrap("{\"revision\":1}".data(using: .utf8))
        let secondPayload = try XCTUnwrap("{\"revision\":2}".data(using: .utf8))
        let stalePayload = try XCTUnwrap("{\"revision\":\"stale\"}".data(using: .utf8))
        let migrated = store.migrate(payload: firstPayload)
        let first = try JSONDecoder().decode(PrivilegedIncidentStoreRecord.self, from: migrated.record)
        let replaced = store.replace(payload: secondPayload, expectedRevision: first.revision)
        let second = try JSONDecoder().decode(PrivilegedIncidentStoreRecord.self, from: replaced.record)

        let stale = store.replace(payload: stalePayload, expectedRevision: first.revision)
        let authoritative = try JSONDecoder().decode(PrivilegedIncidentStoreRecord.self, from: stale.record)

        XCTAssertFalse(stale.accepted)
        XCTAssertEqual(authoritative, second)
        XCTAssertEqual(authoritative.payload, secondPayload)
    }

    func test_storeCreatesPrivateDirectoryAndFilePermissions() throws {
        let fileURL = temporaryDirectory.appendingPathComponent("state/incidents.json")
        let store = PrivilegedIncidentFileStore(fileURL: fileURL)
        let payload = try XCTUnwrap("{\"incidents\":[]}".data(using: .utf8))

        XCTAssertTrue(store.migrate(payload: payload).accepted)

        let directoryAttributes = try FileManager.default.attributesOfItem(
            atPath: fileURL.deletingLastPathComponent().path
        )
        let fileAttributes = try FileManager.default.attributesOfItem(atPath: fileURL.path)
        XCTAssertEqual(directoryAttributes[.posixPermissions] as? NSNumber, NSNumber(value: 0o700))
        XCTAssertEqual(fileAttributes[.posixPermissions] as? NSNumber, NSNumber(value: 0o600))
    }

    func test_symlinkedStateDirectoryIsRefused() throws {
        let outside = temporaryDirectory.appendingPathComponent("outside", isDirectory: true)
        try FileManager.default.createDirectory(at: outside, withIntermediateDirectories: true)
        let state = temporaryDirectory.appendingPathComponent("state")
        try FileManager.default.createSymbolicLink(at: state, withDestinationURL: outside)
        let store = PrivilegedIncidentFileStore(fileURL: state.appendingPathComponent("incidents.json"))
        let payload = try XCTUnwrap("{\"incidents\":[]}".data(using: .utf8))

        XCTAssertFalse(store.migrate(payload: payload).accepted)
        XCTAssertFalse(FileManager.default.fileExists(atPath: outside.appendingPathComponent("incidents.json").path))
    }

    func test_incidentVerdictRequiresAnExistingIncident() {
        let existing = UUID()
        XCTAssertTrue(IncidentVerdictValidationPolicy.accepts(
            incidentID: existing.uuidString,
            action: "reviewed",
            existingIncidentIDs: [existing.uuidString],
            hasProtectionAuthorization: false
        ))
        XCTAssertFalse(IncidentVerdictValidationPolicy.accepts(
            incidentID: UUID().uuidString,
            action: "reviewed",
            existingIncidentIDs: [existing.uuidString],
            hasProtectionAuthorization: true
        ))
    }

    func test_securityReducingVerdictRequiresProtectionAuthorization() {
        let existing = UUID()
        for action in ["dismissed", "allowedOnce", "alwaysAllowed"] {
            XCTAssertFalse(IncidentVerdictValidationPolicy.accepts(
                incidentID: existing.uuidString,
                action: action,
                existingIncidentIDs: [existing.uuidString],
                hasProtectionAuthorization: false
            ))
            XCTAssertTrue(IncidentVerdictValidationPolicy.accepts(
                incidentID: existing.uuidString,
                action: action,
                existingIncidentIDs: [existing.uuidString],
                hasProtectionAuthorization: true
            ))
        }
    }

    func test_enablingVerdictLearningRequiresProtectionAuthorizationButDisablingDoesNot() throws {
        func settings(_ enabled: Bool) throws -> Data {
            try JSONSerialization.data(withJSONObject: [
                "schemaVersion": 1,
                "trustedNames": [],
                "trustedEntries": [],
                "suppressionRules": [],
                "ignoredPaths": [],
                "notificationThresholdRaw": 3,
                "verdictLearningEnabled": enabled
            ])
        }
        let disabled = try settings(false)
        let enabled = try settings(true)
        let disabledRecord = try JSONEncoder().encode(
            PrivilegedIncidentStoreRecord(revision: 1, payload: disabled)
        )
        let enabledRecord = try JSONEncoder().encode(
            PrivilegedIncidentStoreRecord(revision: 2, payload: enabled)
        )

        XCTAssertTrue(SecuritySettingsWritePolicy.requiresAuthorization(
            previousRecord: disabledRecord,
            proposedPayload: enabled
        ))
        XCTAssertFalse(SecuritySettingsWritePolicy.requiresAuthorization(
            previousRecord: enabledRecord,
            proposedPayload: disabled
        ))
    }

    func test_authorizationRightPolicyRejectsWeakerDefinitions() {
        let expected: [String: Any] = [
            "class": "rule",
            "rule": ["authenticate-session-owner-or-admin"],
            "timeout": 120,
            "shared": false
        ]
        XCTAssertTrue(ProtectionAuthorizationRightPolicy.isExpected(expected))

        var shared = expected
        shared["shared"] = true
        XCTAssertFalse(ProtectionAuthorizationRightPolicy.isExpected(shared))

        var longerTimeout = expected
        longerTimeout["timeout"] = 300
        XCTAssertFalse(ProtectionAuthorizationRightPolicy.isExpected(longerTimeout))

        var weakerRule = expected
        weakerRule["rule"] = ["allow"]
        XCTAssertFalse(ProtectionAuthorizationRightPolicy.isExpected(weakerRule))
    }

    func test_incidentStoreRequiresAuthorizationForNewReducingStateOrAction() throws {
        let id = UUID().uuidString
        let original = try payload(incidents: [["id": id, "state": "new", "actions": []]])

        let allowed = try payload(incidents: [["id": id, "state": "allowed", "actions": []]])
        XCTAssertTrue(IncidentStoreWritePolicy.requiresAuthorization(
            previousPayload: original,
            proposedPayload: allowed
        ))

        for action in ["dismissed", "allowedOnce", "alwaysAllowed"] {
            let changed = try payload(incidents: [[
                "id": id,
                "state": "new",
                "actions": [["action": action]]
            ]])
            XCTAssertTrue(IncidentStoreWritePolicy.requiresAuthorization(
                previousPayload: original,
                proposedPayload: changed
            ))
        }

        let reviewed = try payload(incidents: [[
            "id": id,
            "state": "reviewed",
            "actions": [["action": "reviewed"]]
        ]])
        XCTAssertFalse(IncidentStoreWritePolicy.requiresAuthorization(
            previousPayload: original,
            proposedPayload: reviewed
        ))
    }

    func test_incidentStoreRequiresAuthorizationForNewProtectedIncidentAndTombstone() throws {
        let original = try payload(incidents: [])
        let newAllowed = try payload(incidents: [[
            "id": UUID().uuidString,
            "state": "allowed",
            "actions": [["action": "alwaysAllowed"]]
        ]])
        XCTAssertTrue(IncidentStoreWritePolicy.requiresAuthorization(
            previousPayload: original,
            proposedPayload: newAllowed
        ))

        let tombstone = try payload(
            incidents: [],
            tombstones: [[
                "incidentKey": "rule|actor",
                "alertDeduplicationKey": "dedupe"
            ]]
        )
        XCTAssertTrue(IncidentStoreWritePolicy.requiresAuthorization(
            previousPayload: original,
            proposedPayload: tombstone
        ))
    }

    func test_incidentStoreRequiresAuthorizationForNewOrRenewedLearningEntry() throws {
        let original = try payload(incidents: [])
        let learned: [[String: Any]] = [[
            "id": UUID().uuidString,
            "teamID": "TEAM123",
            "signingIdentifier": "com.example.editor",
            "ruleID": "system_hardening",
            "contextKey": "parents=;path=application;destination=unknown",
            "expiresAt": 1234.0,
            "confirmedIncidentIDs": [UUID().uuidString]
        ]]
        let proposed = try payload(incidents: [], learnedEntries: learned)
        XCTAssertTrue(IncidentStoreWritePolicy.requiresAuthorization(
            previousPayload: original,
            proposedPayload: proposed
        ))
        XCTAssertFalse(IncidentStoreWritePolicy.requiresAuthorization(
            previousPayload: proposed,
            proposedPayload: original
        ), "Resetting learned state is security-strengthening")
    }

    private func payload(
        incidents: [[String: Any]],
        tombstones: [[String: Any]] = [],
        learnedEntries: [[String: Any]] = []
    ) throws -> Data {
        try JSONSerialization.data(withJSONObject: [
            "schemaVersion": 1,
            "incidents": incidents,
            "dismissalTombstones": tombstones,
            "expectedCooldowns": [:],
            "learnedReviewEntries": learnedEntries
        ])
    }
}
