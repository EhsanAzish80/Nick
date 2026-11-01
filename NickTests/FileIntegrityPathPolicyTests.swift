// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import XCTest
@testable import Nick

final class FileIntegrityPathPolicyTests: XCTestCase {

    func test_unacknowledgedCreatedThenDeletedProducesDeletionEvidence() throws {
        let path = "/Users/example/Library/LaunchAgents/com.example.transient.plist"
        let createdAt = Date(timeIntervalSince1970: 100)
        let removedAt = Date(timeIntervalSince1970: 110)
        let created = IntegrityViolation(
            path: path,
            violationType: .created,
            expectedHash: nil,
            actualHash: "created-hash",
            timestamp: createdAt
        )

        let deletion = try XCTUnwrap(FileIntegrityDeletionEvidence.violation(
            path: path,
            baselineHash: nil,
            pendingViolations: [created],
            removedAt: removedAt
        ))

        XCTAssertEqual(deletion.violationType, .deleted)
        XCTAssertEqual(deletion.expectedHash, "created-hash")
        XCTAssertNil(deletion.actualHash)
        XCTAssertEqual(deletion.metadata?["createdAt"], "1970-01-01T00:01:40Z")
        XCTAssertEqual(deletion.metadata?["removedAt"], "1970-01-01T00:01:50Z")
        XCTAssertEqual(
            deletion.metadata?["evidence"],
            "created at 1970-01-01T00:01:40Z and removed at 1970-01-01T00:01:50Z without review"
        )
    }

    func test_neverSeenAbsentFileProducesNoDeletionEvidence() {
        XCTAssertNil(FileIntegrityDeletionEvidence.violation(
            path: "/Users/example/Library/LaunchAgents/never-seen.plist",
            baselineHash: nil,
            pendingViolations: [],
            removedAt: Date()
        ))
    }

    func test_baselinedFileDeletionRemainsUnchanged() throws {
        let deletion = try XCTUnwrap(FileIntegrityDeletionEvidence.violation(
            path: "/Library/LaunchDaemons/com.example.baselined.plist",
            baselineHash: "baseline-hash",
            pendingViolations: [],
            removedAt: Date(timeIntervalSince1970: 200)
        ))

        XCTAssertEqual(deletion.violationType, .deleted)
        XCTAssertEqual(deletion.expectedHash, "baseline-hash")
        XCTAssertNil(deletion.actualHash)
        XCTAssertNil(deletion.metadata)
    }

    func test_quicklyRestoredShellProfileUsesEventEvidenceInsteadOfPeriodicHashOnly() throws {
        let projectRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let monitorSource = try String(
            contentsOf: projectRoot.appendingPathComponent("NickExtension/FIM/FileIntegrityMonitor.swift"),
            encoding: .utf8
        )
        let handlerSource = try String(
            contentsOf: projectRoot.appendingPathComponent("NickExtension/EventHandler.swift"),
            encoding: .utf8
        )

        XCTAssertTrue(monitorSource.contains("func recordShellProfileEvent("))
        XCTAssertTrue(monitorSource.contains("return recordPending(IntegrityViolation("))
        XCTAssertTrue(handlerSource.contains("case ES_EVENT_TYPE_NOTIFY_WRITE:"))
        XCTAssertTrue(handlerSource.contains("eventDrivenShellProfile: true"))
        XCTAssertTrue(handlerSource.contains("Shell profile AUTH_OPEN received"))
        XCTAssertTrue(handlerSource.contains("Shell profile ES NOTIFY_WRITE received"))
        XCTAssertTrue(handlerSource.contains("FIM reportIntegrityViolation delivering to app"))
        XCTAssertTrue(monitorSource.contains("recordShellProfileEvent persisted"))
        XCTAssertTrue(monitorSource.contains("pendingViolations: [UUID: IntegrityViolation]"))
        XCTAssertTrue(monitorSource.contains("eventCoalescingWindow: TimeInterval = 5"))
        XCTAssertFalse(monitorSource.contains("pendingViolations[expanded] != nil"))
        XCTAssertFalse(handlerSource.contains(
            "Shell profile isExactShellProfile path="
        ))
        XCTAssertTrue(handlerSource.contains(
            "guard isExactProfile else { break }"
        ))
        XCTAssertTrue(handlerSource.contains(
            "fileIntegrityMonitor?.shouldCheck(filePath) == true"
        ))
    }

    func test_notifyWriteUsesDedicatedInvertedExactPathClient() throws {
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
        let main = try String(contentsOf: root.appendingPathComponent("NickExtension/main.swift"))
        let client = try String(contentsOf: root.appendingPathComponent("NickExtension/EndpointSecurityClient.swift"))
        XCTAssertTrue(main.contains("shellProfileWriteClient.invertTargetMuting"))
        XCTAssertFalse(main.components(separatedBy: "let phase4Events")[1]
            .components(separatedBy: "guard esClient.subscribe")[0]
            .contains("ES_EVENT_TYPE_NOTIFY_WRITE"))
        XCTAssertTrue(client.contains("ES_MUTE_INVERSION_TYPE_TARGET_PATH"))
        XCTAssertTrue(client.contains("ES_MUTE_PATH_TYPE_TARGET_LITERAL"))
    }

    func test_individualFilesMatchExactly() {
        let zshrc = "/Users/example/.zshrc"
        XCTAssertTrue(FileIntegrityPathPolicy.isMonitored(
            zshrc,
            configuredPaths: [zshrc],
            directoryPaths: []
        ))
        XCTAssertFalse(FileIntegrityPathPolicy.isMonitored(
            zshrc + "~",
            configuredPaths: [zshrc],
            directoryPaths: []
        ))
        XCTAssertFalse(FileIntegrityPathPolicy.isMonitored(
            zshrc + ".zwc",
            configuredPaths: [zshrc],
            directoryPaths: []
        ))
    }

    func test_directoryRootsIncludeOnlyActualChildren() {
        let root = "/Library/LaunchAgents"
        XCTAssertTrue(FileIntegrityPathPolicy.isMonitored(
            root + "/com.example.agent.plist",
            configuredPaths: [root],
            directoryPaths: [root]
        ))
        XCTAssertFalse(FileIntegrityPathPolicy.isMonitored(
            root + "Backup/com.example.agent.plist",
            configuredPaths: [root],
            directoryPaths: [root]
        ))
    }

    func test_systemAuditExposesBaselineRebuildAndExplainsPendingRefusal() throws {
        let projectRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let sourceURL = projectRoot
            .appendingPathComponent("Nick/App/Dashboard/SystemAuditView.swift")
        let source = try String(contentsOf: sourceURL, encoding: .utf8)

        XCTAssertTrue(source.contains("Button(\"Rebuild Baseline\")"))
        XCTAssertTrue(source.contains("rebuildFIMBaseline()"))
        XCTAssertTrue(source.contains("xpcClient.requestRebuildFIMBaseline"))
        XCTAssertTrue(source.contains(
            "Review and acknowledge pending changes before rebuilding."
        ))
        XCTAssertTrue(source.contains(".disabled(isRebuildingFIM)"))
    }
}
