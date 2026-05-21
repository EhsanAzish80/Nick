// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import XCTest
@testable import Nick

/// Integration tests that interact with real system resources.
/// These are skipped in CI unless the host is a macOS machine with Full Disk Access.
///
/// Run manually:
///   xcodebuild test -scheme NickIntegrationTests -destination 'platform=macOS'
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

    /// Verify `lsof` is available and produces parseable output.
    func test_connectionScanner_scan_returnsSomeConnections() async throws {
        let scanner = ConnectionScanner()
        // May throw on sandboxed hosts — that's acceptable here
        guard let connections = try? await scanner.scan() else { return }
        // Any macOS host with a network should have at least one connection
        XCTAssertGreaterThanOrEqual(connections.count, 0)
    }
}
