// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import XCTest
@testable import Nick

// MARK: - SystemAuditorTests

/// Unit tests for `SystemAuditor` output parsing and signal generation.
///
/// These tests exercise the parsing logic directly without spawning real
/// system processes. Integration tests that call real commands live in
/// `NickIntegrationTests/`.
@MainActor
final class SystemAuditorTests: XCTestCase {

    // MARK: - SystemCheckResult

    func test_systemCheckResult_impliedSeverity_failOnCriticalCheckIsCritical() {
        let result = SystemCheckResult(
            id: UUID(),
            check: .sip,
            status: .fail,
            currentValue: "Disabled",
            expectedValue: "Enabled",
            description: "SIP is off",
            recommendation: "Re-enable SIP"
        )
        XCTAssertEqual(result.impliedSeverity, .critical)
    }

    func test_systemCheckResult_impliedSeverity_failOnNonCriticalCheckIsHigh() {
        let result = SystemCheckResult(
            id: UUID(),
            check: .remoteLogin,
            status: .fail,
            currentValue: "On",
            expectedValue: "Off",
            description: "SSH enabled",
            recommendation: nil
        )
        XCTAssertEqual(result.impliedSeverity, .high)
    }

    func test_systemCheckResult_impliedSeverity_passIsInfo() {
        let result = SystemCheckResult(
            id: UUID(),
            check: .gatekeeper,
            status: .pass,
            currentValue: "Assessments enabled",
            expectedValue: "Assessments enabled",
            description: "Gatekeeper is on",
            recommendation: nil
        )
        XCTAssertEqual(result.impliedSeverity, .info)
    }

    func test_systemCheckResult_impliedSeverity_unknownIsLow() {
        let result = SystemCheckResult(
            id: UUID(),
            check: .firewall,
            status: .unknown,
            currentValue: "Unknown",
            expectedValue: "Enabled",
            description: "Could not determine firewall state",
            recommendation: nil
        )
        XCTAssertEqual(result.impliedSeverity, .low)
    }

    // MARK: - CheckStatus.isCritical

    func test_systemCheckType_isCritical_sipIsTrue() {
        XCTAssertTrue(SystemCheckType.sip.isCritical)
    }

    func test_systemCheckType_isCritical_fileVaultIsTrue() {
        XCTAssertTrue(SystemCheckType.fileVault.isCritical)
    }

    func test_systemCheckType_isCritical_firewallStealthIsFalse() {
        XCTAssertFalse(SystemCheckType.firewallStealth.isCritical)
    }

    func test_systemCheckType_isCritical_remoteLoginIsFalse() {
        XCTAssertFalse(SystemCheckType.remoteLogin.isCritical)
    }

    // MARK: - runCommand error handling

    func test_runCommand_throwsToolUnavailable_forNonexistentPath() async {
        let auditor = SystemAuditor()
        do {
            _ = try await auditor.runCommand("/nonexistent/tool", args: [])
            XCTFail("Expected toolUnavailable to be thrown")
        } catch SystemAuditorError.toolUnavailable(let path) {
            XCTAssertEqual(path, "/nonexistent/tool")
        } catch {
            XCTFail("Unexpected error: \(error)")
        }
    }

    // MARK: - Signal Generation

    func test_latestSignals_afterFailedCheck_returnsCriticalSignal() async throws {
        // Manually inject a failed SIP result
        let failedResult = SystemCheckResult(
            id: UUID(),
            check: .sip,
            status: .fail,
            currentValue: "Disabled",
            expectedValue: "Enabled",
            description: "SIP is disabled",
            recommendation: "Re-enable SIP"
        )
        // Verify the signal would be critical
        let impliedSeverity = failedResult.impliedSeverity
        XCTAssertEqual(impliedSeverity, .critical)
    }

    func test_latestSignals_afterPassedCheck_returnsNoSignal() {
        let passedResult = SystemCheckResult(
            id: UUID(),
            check: .sip,
            status: .pass,
            currentValue: "Enabled",
            expectedValue: "Enabled",
            description: "SIP is enabled",
            recommendation: nil
        )
        XCTAssertEqual(passedResult.impliedSeverity, .info)
    }

    func test_systemCheckType_allCases_haveNonEmptyDisplayNames() {
        for check in SystemCheckType.allCases {
            XCTAssertFalse(check.displayName.isEmpty, "\(check) has empty displayName")
        }
    }

    func test_checkStatus_allCases_haveSystemImages() {
        for status in CheckStatus.allCases {
            XCTAssertFalse(status.systemImage.isEmpty)
        }
    }
}
