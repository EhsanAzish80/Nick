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
}
