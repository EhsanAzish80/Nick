// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import XCTest
@testable import Nick

final class FileIntegrityPathPolicyTests: XCTestCase {

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
