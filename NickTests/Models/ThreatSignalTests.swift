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
        XCTAssertFalse(SignalSeverity.medium < SignalSeverity.medium)
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

    // MARK: - Evidence

    func test_evidence_fromSignal_capturesVersionedTypedIdentity() throws {
        let observedAt = Date(timeIntervalSince1970: 1_234_567)
        let signal = ThreatSignal(
            source: .yara,
            severity: .high,
            timestamp: observedAt,
            title: "Known family",
            description: "Signature matched a file.",
            context: ThreatSignalContext(
                fileInfo: FileInfo(
                    path: "/private/tmp/sample",
                    sha256Hash: "ABCDEF",
                    entropy: 7.4,
                    signingStatus: .unsigned,
                    sizeBytes: 42
                ),
                metadata: [
                    "class": "signature",
                    "rule": "known_family_rule",
                    "device_id": "17",
                    "inode": "99",
                    "modification_time": "1234.5"
                ]
            )
        )

        let evidence = Evidence(signal: signal)
        let decoded = try JSONDecoder().decode(
            Evidence.self,
            from: JSONEncoder().encode(evidence)
        )

        XCTAssertEqual(decoded.schemaVersion, Evidence.currentSchemaVersion)
        XCTAssertEqual(decoded.source, .yara)
        XCTAssertEqual(decoded.ruleClass, .signature)
        XCTAssertEqual(decoded.ruleID, "known_family_rule")
        XCTAssertEqual(decoded.ruleTier, .protectedDetection)
        XCTAssertEqual(decoded.signingIdentity?.kind, .unsigned)
        XCTAssertEqual(decoded.parentChain, [])
        XCTAssertEqual(decoded.parentChainIsComplete, false)
        XCTAssertEqual(decoded.pathClass, .temporary)
        XCTAssertEqual(decoded.destinationClass, .unknown)
        XCTAssertEqual(decoded.lifecycle?.verdict, .unreviewed)
        XCTAssertEqual(decoded.lifecycle?.actor, .automatic)
        XCTAssertEqual(decoded.lifecycle?.timestamp, observedAt)
        XCTAssertEqual(decoded.subject.kind, .file)
        XCTAssertEqual(decoded.fileIdentity?.deviceID, 17)
        XCTAssertEqual(decoded.fileIdentity?.inode, 99)
        XCTAssertEqual(decoded.fileIdentity?.modificationTime, 1234.5)
        XCTAssertEqual(decoded.timestamps.observedAt, observedAt)
        XCTAssertEqual(decoded.threatSignal, signal)
    }

    func test_unknownRuleDefaultsToProtectedDetection() {
        let signal = ThreatSignal(
            source: .process,
            severity: .medium,
            title: "Previously unseen behavior",
            description: "No rule metadata",
            context: ThreatSignalContext()
        )

        let evidence = Evidence(signal: signal)

        XCTAssertEqual(evidence.ruleTier, .protectedDetection)
        XCTAssertTrue(evidence.ruleID?.contains("unclassified") == true)
    }

    func test_unknownAuditRuleWithOnlyAPlatformActorPathRemainsProtected() {
        let signal = ThreatSignal(
            source: .endpointSecurity,
            severity: .info,
            title: "Unknown audit observation",
            description: "Unknown audit observation",
            context: ThreatSignalContext(
                processInfo: NickProcessInfo(
                    pid: 42,
                    path: "/usr/bin/exampletool",
                    name: "exampletool",
                    parentPID: 1,
                    parentName: "launchd",
                    signingStatus: .unknown
                ),
                metadata: [
                    "class": "audit",
                    "rule": "unlisted_audit_rule",
                ]
            )
        )

        XCTAssertEqual(Evidence(signal: signal).ruleTier, .protectedDetection)
    }

    func test_yaraPersistenceHashAndHighRiskPathsAreAlwaysProtected() {
        let fixtures: [ThreatSignal] = [
            ThreatSignal(source: .yara, severity: .medium, title: "YARA", description: "match"),
            ThreatSignal(source: .persistence, severity: .medium, title: "Persistence", description: "item"),
            ThreatSignal(source: .process, severity: .medium, title: "Hash", description: "hash", context: ThreatSignalContext(fileInfo: FileInfo(path: "/Users/test/file", sha256Hash: "abc", entropy: nil, signingStatus: nil, sizeBytes: nil))),
            ThreatSignal(source: .process, severity: .medium, title: "Temp", description: "temp", context: ThreatSignalContext(fileInfo: FileInfo(path: "/private/tmp/file", sha256Hash: nil, entropy: nil, signingStatus: nil, sizeBytes: nil))),
        ]

        XCTAssertTrue(fixtures.allSatisfy { Evidence(signal: $0).ruleTier == .protectedDetection })
    }

    func test_pathClassUsesPassedConsoleUserHome() {
        let signal = ThreatSignal(
            source: .process,
            severity: .low,
            title: "User file",
            description: "fixture",
            context: ThreatSignalContext(fileInfo: FileInfo(path: "/Users/alice/Documents/file", sha256Hash: nil, entropy: nil, signingStatus: nil, sizeBytes: nil))
        )

        XCTAssertEqual(EvidencePathClass(signal: signal, userHomePath: "/Users/alice"), .user)
        XCTAssertNotEqual(EvidencePathClass(signal: signal, userHomePath: "/var/root"), .user)
    }

    // MARK: - SigningStatus Codable

    func test_signingStatus_codable_roundTrip_signedWithTeamID() throws {
        let status = SigningStatus.signed(teamID: "TEAM123", signingID: "com.example.app")
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
