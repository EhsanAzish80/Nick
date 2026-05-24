// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import XCTest
@testable import Nick

// MARK: - ThreatSignalTests

/// Unit tests for `ThreatSignal`, `SignalSeverity`, and `FileInfo`.
final class ThreatSignalTests: XCTestCase {

    // MARK: - SignalSeverity Ordering

    func test_signalSeverity_ordering_infoIsLessThanCritical() {
        XCTAssertLessThan(SignalSeverity.info, SignalSeverity.critical)
    }

    func test_signalSeverity_ordering_lowIsLessThanHigh() {
        XCTAssertLessThan(SignalSeverity.low, SignalSeverity.high)
    }

    func test_signalSeverity_ordering_allCasesAreOrdered() {
        let sorted = SignalSeverity.allCases.sorted()
        let expected: [SignalSeverity] = [.info, .low, .medium, .high, .critical]
        XCTAssertEqual(sorted, expected)
    }

    func test_signalSeverity_comparable_mediumIsNotLessThanMedium() {
        let severity = SignalSeverity.medium
        XCTAssertFalse(severity < severity)
    }

    // MARK: - ThreatSignal Creation

    func test_threatSignal_init_defaultsToNowAndNewUUID() {
        let before = Date()
        let signal = ThreatSignal(
            source: .process,
            severity: .high,
            title: "Test",
            description: "Test description"
        )
        let after = Date()

        XCTAssertGreaterThanOrEqual(signal.timestamp, before)
        XCTAssertLessThanOrEqual(signal.timestamp, after)
        XCTAssertNotEqual(signal.id, UUID()) // different UUID each time
    }

    func test_threatSignal_init_twoSignalsHaveDifferentIDs() {
        let a = ThreatSignal(source: .network, severity: .medium, title: "A", description: "a")
        let b = ThreatSignal(source: .network, severity: .medium, title: "A", description: "a")
        XCTAssertNotEqual(a.id, b.id)
    }

    func test_threatSignal_metadata_defaultsToEmpty() {
        let signal = ThreatSignal(source: .yara, severity: .low, title: "T", description: "D")
        XCTAssertTrue(signal.metadata.isEmpty)
    }

    // MARK: - Codable Round-Trip

    func test_threatSignal_codable_roundTrip_preservesAllScalarFields() throws {
        let original = ThreatSignal(
            id: UUID(uuidString: "12345678-1234-1234-1234-123456789abc")!,
            source: .systemAudit,
            severity: .critical,
            timestamp: Date(timeIntervalSince1970: 1_000_000),
            title: "SIP Disabled",
            description: "System Integrity Protection has been disabled.",
            context: ThreatSignalContext(metadata: ["csrutil": "disabled"])
        )

        let data = try JSONEncoder().encode(original)
        let decoded = try JSONDecoder().decode(ThreatSignal.self, from: data)

        XCTAssertEqual(decoded.id, original.id)
        XCTAssertEqual(decoded.source, original.source)
        XCTAssertEqual(decoded.severity, original.severity)
        XCTAssertEqual(decoded.title, original.title)
        XCTAssertEqual(decoded.description, original.description)
        XCTAssertEqual(decoded.metadata, original.metadata)
    }

    func test_threatSignal_codable_roundTrip_withProcessInfo() throws {
        let processInfo = NickProcessInfo(
            pid: 1234,
            path: "/tmp/evil",
            name: "evil",
            parentPID: 1,
            parentName: "launchd",
            signingStatus: .unsigned,
            metadata: ProcessMetadata(user: "ehsan", startTime: nil)
        )
        let signal = ThreatSignal(
            source: .process,
            severity: .high,
            title: "Unsigned binary",
            description: "Unsigned binary in /tmp",
            context: ThreatSignalContext(processInfo: processInfo)
        )

        let data = try JSONEncoder().encode(signal)
        let decoded = try JSONDecoder().decode(ThreatSignal.self, from: data)

        XCTAssertEqual(decoded.processInfo?.pid, 1234)
        XCTAssertEqual(decoded.processInfo?.signingStatus, .unsigned)
    }

    // MARK: - SigningStatus Codable

    func test_signingStatus_codable_roundTrip_signedWithTeamID() throws {
        let status = SigningStatus.signed(teamID: "TEAM123")
        let data = try JSONEncoder().encode(status)
        let decoded = try JSONDecoder().decode(SigningStatus.self, from: data)
        XCTAssertEqual(decoded, status)
    }

    func test_signingStatus_codable_roundTrip_unsigned() throws {
        let status = SigningStatus.unsigned
        let data = try JSONEncoder().encode(status)
        let decoded = try JSONDecoder().decode(SigningStatus.self, from: data)
        XCTAssertEqual(decoded, status)
    }

    func test_signingStatus_codable_roundTrip_adHoc() throws {
        let data = try JSONEncoder().encode(SigningStatus.adHoc)
        let decoded = try JSONDecoder().decode(SigningStatus.self, from: data)
        XCTAssertEqual(decoded, .adHoc)
    }

    func test_signingStatus_isSuspicious_unsigned() {
        XCTAssertTrue(SigningStatus.unsigned.isSuspicious)
        XCTAssertTrue(SigningStatus.invalid.isSuspicious)
    }

    func test_signingStatus_isNotSuspicious_signedBinary() {
        XCTAssertFalse(SigningStatus.signed(teamID: "APPLE").isSuspicious)
    }
}
