// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import XCTest
@testable import Nick

/// Integration tests that interact with real system resources.
/// These are skipped in CI unless the host is a macOS machine with Full Disk Access.
///
/// Run manually:
///   xcodebuild test -scheme Nick -only-testing:NickIntegrationTests -destination 'platform=macOS'
@MainActor
final class NickIntegrationTests: XCTestCase {

    /// Verify that `SystemAuditor` can run at least the SIP check on a real machine.
    func test_systemAuditor_sipCheck_returnsResult() async throws {
        let auditor = SystemAuditor()
        let result = await auditor.runCheck(.sip)
        // On CI the value may be unknown; we just verify a result was returned
        XCTAssertFalse(result.check.displayName.isEmpty)
        XCTAssertNotEqual(result.currentValue, "")
    }

    /// Verify the system connection scanner returns internally consistent records.
    func test_connectionScanner_scan_returnsSomeConnections() async throws {
        let scanner = ConnectionScanner()
        let connections: [NetworkConnectionInfo]
        do {
            connections = try await scanner.scan()
        } catch ConnectionScannerError.unavailable {
            throw XCTSkip("Connection APIs and lsof are unavailable in this environment")
        }

        guard !connections.isEmpty else {
            throw XCTSkip("The host has no network connections visible to the test process")
        }

        for connection in connections {
            XCTAssertGreaterThan(connection.pid, 0)
            XCTAssertFalse(connection.processName.isEmpty)
            XCTAssertGreaterThanOrEqual(connection.localPort, 0)
            XCTAssertLessThanOrEqual(connection.localPort, 65_535)
            if let remotePort = connection.remotePort {
                XCTAssertTrue((0...65_535).contains(remotePort))
            }
        }
    }
}
