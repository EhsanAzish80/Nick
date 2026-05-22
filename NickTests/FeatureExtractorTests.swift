// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import XCTest
@testable import Nick

// MARK: - FeatureExtractorTests

/// Unit tests for `FeatureExtractor`.
///
/// Verifies that all 40 features are populated correctly from known signal
/// combinations and that zero-signal input returns a safe all-zero vector.
final class FeatureExtractorTests: XCTestCase {

    private var extractor: FeatureExtractor!

    override func setUp() {
        super.setUp()
        extractor = FeatureExtractor()
    }

    // MARK: - All-zero baseline

    func test_emptySignals_returnsZeroVector() {
        let vec = extractor.extract(from: [], windowDuration: 30)
        XCTAssertEqual(vec.asArray.count, 40, "asArray must have exactly 40 elements")
        XCTAssertTrue(vec.asArray.allSatisfy { $0 == 0 }, "Empty input must yield all zeros")
    }

    // MARK: - Process features

    func test_unsignedProcess_setsUnsignedFlag() {
        let signal = makeProcessSignal(signingStatus: .unsigned, path: "/usr/bin/curl")
        let vec = extractor.extract(from: [signal], windowDuration: 30)
        XCTAssertEqual(vec.processIsUnsigned, 1)
        XCTAssertEqual(vec.processIsAdHocSigned, 0)
    }

    func test_adHocProcess_setsAdHocFlag() {
        let signal = makeProcessSignal(signingStatus: .adHoc, path: "/usr/bin/curl")
        let vec = extractor.extract(from: [signal], windowDuration: 30)
        XCTAssertEqual(vec.processIsAdHocSigned, 1)
        XCTAssertEqual(vec.processIsUnsigned, 0)
    }

    func test_processInTmp_setsTmpFlag() {
        let signal = makeProcessSignal(signingStatus: .unsigned, path: "/tmp/malware")
        let vec = extractor.extract(from: [signal], windowDuration: 30)
        XCTAssertEqual(vec.processInTmp, 1)
    }

    func test_processInHiddenDir_setsHiddenFlag() {
        let signal = makeProcessSignal(signingStatus: .unsigned, path: "/Users/user/.hidden/exec")
        let vec = extractor.extract(from: [signal], windowDuration: 30)
        XCTAssertEqual(vec.processInHiddenDir, 1)
    }

    func test_shellProcess_setsShellFlag() {
        for shell in ["bash", "zsh", "sh", "python", "python3", "ruby", "perl"] {
            let signal = makeProcessSignal(signingStatus: .adHoc, path: "/bin/\(shell)", name: shell)
            let vec = extractor.extract(from: [signal], windowDuration: 30)
            XCTAssertEqual(vec.processIsShell, 1, "Expected processIsShell=1 for \(shell)")
        }
    }

    func test_lolbinMetadata_setsLolbinFlag() {
        var signal = makeProcessSignal(signingStatus: .unsigned, path: "/usr/bin/osascript")
        signal = withMetadata(signal, ["isLolbin": "true"])
        let vec = extractor.extract(from: [signal], windowDuration: 30)
        XCTAssertEqual(vec.processIsLolbin, 1)
    }

    func test_parentChainDepth_cappedAt10() {
        var signal = makeProcessSignal(signingStatus: .unsigned, path: "/bin/bash")
        signal = withMetadata(signal, ["parentChainDepth": "15"])
        let vec = extractor.extract(from: [signal], windowDuration: 30)
        XCTAssertEqual(vec.processParentChainDepth, 10, "parentChainDepth must be clamped to 10")
    }

    // MARK: - Network features

    func test_outboundEstablishedConnection_setsFlag() {
        let signal = makeNetworkSignal(remoteAddr: "203.0.113.1", remotePort: 4444, state: .established)
        let vec = extractor.extract(from: [signal], windowDuration: 30)
        XCTAssertEqual(vec.netHasOutboundConnection, 1)
        XCTAssertEqual(vec.netRemoteIsRawIP, 1)
        XCTAssertEqual(vec.netRemotePort, 4444)
        XCTAssertEqual(vec.netUsesUncommonPort, 1)
        XCTAssertEqual(vec.netRemotePortIsCommon, 0)
    }

    func test_commonPort443_setsCommonPortFlag() {
        let signal = makeNetworkSignal(remoteAddr: "1.2.3.4", remotePort: 443, state: .established)
        let vec = extractor.extract(from: [signal], windowDuration: 30)
        XCTAssertEqual(vec.netRemotePortIsCommon, 1)
        XCTAssertEqual(vec.netUsesUncommonPort, 0)
    }

    func test_listeningSocket_setsListeningFlag() {
        let signal = makeNetworkSignal(remoteAddr: "0.0.0.0", remotePort: 8080, state: .listen)
        let vec = extractor.extract(from: [signal], windowDuration: 30)
        XCTAssertEqual(vec.netIsListening, 1)
        XCTAssertEqual(vec.netHasOutboundConnection, 0)
    }

    // MARK: - File system features

    func test_highEntropyFile_setsEntropyFlags() {
        let signal = makeFilesystemSignal(path: "/tmp/payload", entropy: 7.8)
        let vec = extractor.extract(from: [signal], windowDuration: 30)
        XCTAssertEqual(vec.fsFileEntropy, 7.8, accuracy: 0.001)
        XCTAssertEqual(vec.fsFileEntropyIsHigh, 1)
        XCTAssertEqual(vec.fsFileInTmp, 1)
    }

    func test_lowEntropyFile_doesNotSetHighEntropyFlag() {
        let signal = makeFilesystemSignal(path: "/Users/user/doc.txt", entropy: 4.2)
        let vec = extractor.extract(from: [signal], windowDuration: 30)
        XCTAssertEqual(vec.fsFileEntropyIsHigh, 0)
        XCTAssertEqual(vec.fsFileInTmp, 0)
    }

    func test_rapidCreationMetadata_setsFlag() {
        var signal = makeFilesystemSignal(path: "/tmp/x", entropy: 5.0)
        signal = withMetadata(signal, ["rapidCreation": "true"])
        let vec = extractor.extract(from: [signal], windowDuration: 30)
        XCTAssertEqual(vec.fsRapidCreationDetected, 1)
    }

    // MARK: - Persistence features

    func test_newLaunchAgent_setsFlag() {
        let signal = makePersistenceSignal(persistType: "launchAgent", targetUnsigned: true)
        let vec = extractor.extract(from: [signal], windowDuration: 30)
        XCTAssertEqual(vec.persistNewLaunchAgent, 1)
        XCTAssertEqual(vec.persistNewLaunchDaemon, 0)
        XCTAssertEqual(vec.persistExecutableUnsigned, 1)
    }

    func test_newLaunchDaemon_setsFlag() {
        let signal = makePersistenceSignal(persistType: "launchDaemon", targetUnsigned: false)
        let vec = extractor.extract(from: [signal], windowDuration: 30)
        XCTAssertEqual(vec.persistNewLaunchDaemon, 1)
        XCTAssertEqual(vec.persistNewLaunchAgent, 0)
        XCTAssertEqual(vec.persistExecutableUnsigned, 0)
    }

    // MARK: - YARA features

    func test_yaraSignals_setsMatchCountAndSeverity() {
        let s1 = makeYaraSignal(severity: .high)
        let s2 = makeYaraSignal(severity: .medium)
        let vec = extractor.extract(from: [s1, s2], windowDuration: 30)
        XCTAssertEqual(vec.yaraMatchCount, 2)
        XCTAssertEqual(vec.yaraMaxSeverity, Double(SignalSeverity.high.rawValue))
    }

    // MARK: - System audit features

    func test_sipDisabledMetadata_setsFlag() {
        let signal = makeAuditSignal(check: "sip_disabled")
        let vec = extractor.extract(from: [signal], windowDuration: 30)
        XCTAssertEqual(vec.auditSipDisabled, 1)
        XCTAssertEqual(vec.auditFilevaultDisabled, 0)
    }

    // MARK: - Temporal features

    func test_multipleMonitors_setsUniqueMonitorCount() {
        let signals = [
            makeProcessSignal(signingStatus: .unsigned, path: "/tmp/x"),
            makeNetworkSignal(remoteAddr: "1.2.3.4", remotePort: 4444, state: .established),
            makeYaraSignal(severity: .high),
        ]
        let vec = extractor.extract(from: signals, windowDuration: 30)
        XCTAssertEqual(vec.temporalSignalsInWindow, 3)
        XCTAssertEqual(vec.temporalUniqueMonitorsFiring, 3)
    }

    func test_allFeatureNames_has40Elements() {
        XCTAssertEqual(FeatureVector.featureNames.count, 40)
    }

    func test_asArray_has40Elements() {
        let vec = FeatureVector()
        XCTAssertEqual(vec.asArray.count, 40)
    }

    func test_noNaNOrInfinityInExtractedVector() {
        let signals = [
            makeProcessSignal(signingStatus: .unsigned, path: "/tmp/x"),
            makeNetworkSignal(remoteAddr: "10.0.0.1", remotePort: 4444, state: .established),
            makeFilesystemSignal(path: "/tmp/payload", entropy: 7.9),
        ]
        let vec = extractor.extract(from: signals, windowDuration: 30)
        for (i, value) in vec.asArray.enumerated() {
            XCTAssertFalse(value.isNaN, "Feature \(i) (\(FeatureVector.featureNames[i])) is NaN")
            XCTAssertFalse(value.isInfinite, "Feature \(i) (\(FeatureVector.featureNames[i])) is Inf")
        }
    }

    // MARK: - Helpers

    private func makeProcessSignal(
        signingStatus: SigningStatus,
        path: String,
        name: String = "process"
    ) -> ThreatSignal {
        let procInfo = NickProcessInfo(
            pid: 1234,
            path: path,
            name: name,
            parentPID: 1,
            parentName: nil,
            signingStatus: signingStatus,
            user: "user",
            startTime: Date(timeIntervalSinceNow: -60)
        )
        return ThreatSignal(
            id: UUID(),
            source: .process,
            severity: .medium,
            timestamp: Date(),
            title: "Test process signal",
            description: "Test",
            processInfo: procInfo,
            networkInfo: nil,
            fileInfo: nil,
            metadata: [:]
        )
    }

    private func makeNetworkSignal(
        remoteAddr: String,
        remotePort: Int,
        state: ConnectionState
    ) -> ThreatSignal {
        let netInfo = NetworkConnectionInfo(
            id: UUID(),
            pid: 1234,
            processName: "process",
            transportProtocol: .tcp,
            localAddress: "127.0.0.1",
            localPort: 54321,
            remoteAddress: remoteAddr,
            remotePort: remotePort,
            state: state
        )
        return ThreatSignal(
            id: UUID(),
            source: .network,
            severity: .high,
            timestamp: Date(),
            title: "Test network signal",
            description: "Test",
            processInfo: nil,
            networkInfo: netInfo,
            fileInfo: nil,
            metadata: [:]
        )
    }

    private func makeFilesystemSignal(path: String, entropy: Double) -> ThreatSignal {
        let fileInfo = FileInfo(
            path: path,
            sha256Hash: nil,
            entropy: entropy,
            signingStatus: nil,
            sizeBytes: 1024
        )
        return ThreatSignal(
            id: UUID(),
            source: .filesystem,
            severity: .medium,
            timestamp: Date(),
            title: "Test fs signal",
            description: "Test",
            processInfo: nil,
            networkInfo: nil,
            fileInfo: fileInfo,
            metadata: [:]
        )
    }

    private func makePersistenceSignal(persistType: String, targetUnsigned: Bool) -> ThreatSignal {
        ThreatSignal(
            id: UUID(),
            source: .persistence,
            severity: .high,
            timestamp: Date(),
            title: "Test persistence signal",
            description: "Test",
            processInfo: nil,
            networkInfo: nil,
            fileInfo: nil,
            metadata: [
                "persistType": persistType,
                "targetUnsigned": targetUnsigned ? "true" : "false",
            ]
        )
    }

    private func makeYaraSignal(severity: SignalSeverity) -> ThreatSignal {
        ThreatSignal(
            id: UUID(),
            source: .yara,
            severity: severity,
            timestamp: Date(),
            title: "YARA match",
            description: "Test",
            processInfo: nil,
            networkInfo: nil,
            fileInfo: nil,
            metadata: [:]
        )
    }

    private func makeAuditSignal(check: String) -> ThreatSignal {
        ThreatSignal(
            id: UUID(),
            source: .systemAudit,
            severity: .critical,
            timestamp: Date(),
            title: "System audit",
            description: "Test",
            processInfo: nil,
            networkInfo: nil,
            fileInfo: nil,
            metadata: ["check": check]
        )
    }

    private func withMetadata(_ signal: ThreatSignal, _ metadata: [String: String]) -> ThreatSignal {
        ThreatSignal(
            id: signal.id,
            source: signal.source,
            severity: signal.severity,
            timestamp: signal.timestamp,
            title: signal.title,
            description: signal.description,
            processInfo: signal.processInfo,
            networkInfo: signal.networkInfo,
            fileInfo: signal.fileInfo,
            metadata: signal.metadata.merging(metadata) { _, new in new }
        )
    }
}
