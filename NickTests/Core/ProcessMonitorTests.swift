// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import XCTest
@testable import Nick

// MARK: - ProcessMonitorTests

/// Unit tests for `ProcessScanner` signal derivation and path classification.
///
/// These tests do not call real system APIs — they construct `NickProcessInfo`
/// values directly and verify the signal logic. Integration tests that perform
/// real `sysctl` scans live in `NickIntegrationTests/`.
final class ProcessMonitorTests: XCTestCase {

    private var scanner: ProcessScanner!

    override func setUp() {
        super.setUp()
        scanner = ProcessScanner()
    }

    override func tearDown() {
        scanner = nil
        super.tearDown()
    }

    // MARK: - Signal: Unsigned binary in temp path

    func test_signals_unsignedBinaryInTmpPath_returnsMediumContext() {
        let proc = makeProcess(pid: 100, name: "evil", path: "/tmp/evil", signing: .unsigned)
        let signals = scanner.signals(from: [proc])
        XCTAssertEqual(signals.count, 1)
        XCTAssertEqual(signals[0].severity, .medium)
    }

    func test_signals_unsignedBinaryInVarFolders_returnsMediumContext() {
        let proc = makeProcess(pid: 101, name: "payload", path: "/var/folders/ab/cd/T/payload", signing: .unsigned)
        let signals = scanner.signals(from: [proc])
        XCTAssertEqual(signals[0].severity, .medium)
    }

    func test_signals_invalidBinaryInPrivateTmp_returnsHighSeverity() {
        let proc = makeProcess(pid: 102, name: "tampered", path: "/private/tmp/tampered", signing: .invalid)
        let signals = scanner.signals(from: [proc])
        XCTAssertEqual(signals[0].severity, .high)
    }

    // MARK: - Signal: Unsigned binary in non-system path

    func test_signals_unsignedBinaryInDownloads_returnsMediumSeverity() {
        let proc = makeProcess(pid: 200, name: "tool", path: "/Users/test/Downloads/tool", signing: .unsigned)
        let signals = scanner.signals(from: [proc])
        XCTAssertEqual(signals.count, 1)
        XCTAssertEqual(signals[0].severity, .medium)
    }

    func test_signals_signedBinary_returnsNoSignal() {
        let proc = makeProcess(pid: 201, name: "signed", path: "/Applications/Signed.app/Contents/MacOS/signed", signing: .signed(teamID: "APPLE123"))
        let signals = scanner.signals(from: [proc])
        XCTAssertTrue(signals.isEmpty)
    }

    func test_signals_unsignedBinaryInSystemPath_returnsNoSignal() {
        let proc = makeProcess(pid: 202, name: "tool", path: "/usr/bin/tool", signing: .unsigned)
        // System path — we skip it (trust the OS)
        let signals = scanner.signals(from: [proc])
        XCTAssertTrue(signals.isEmpty)
    }

    // MARK: - Signal: LOLBin

    func test_signals_bashSpawnedByOsascript_returnsMediumLolbinSignal() {
        // osascript spawning bash is a recognised LOLBin pattern (not a legitimate
        // terminal parent).  ProcessScanner.signals() emits reason "lolbin" with
        // severity .medium for shells whose parent is neither a terminal emulator
        // nor in the trusted-process allowlist.
        //
        // Note: launchd IS in the trusted list, so bash-from-launchd is intentionally
        // suppressed.  osascript is NOT trusted, so the signal is emitted.
        let osascriptProc = makeProcess(pid: 499, name: "osascript",
                                        path: "/usr/bin/osascript",
                                        signing: .signed(teamID: "APPLE"))
        let bashProc = makeProcess(pid: 300, name: "bash",
                                   path: "/bin/bash",
                                   signing: .signed(teamID: "APPLE"),
                                   parentPID: 499)
        let signals = scanner.signals(from: [osascriptProc, bashProc])
        let lolbinSignals = signals.filter { $0.metadata["reason"] == "lolbin" }
        XCTAssertEqual(lolbinSignals.count, 1)
        XCTAssertEqual(lolbinSignals[0].severity, .medium)
    }

    func test_signals_zshSpawnedByTerminal_returnsNoLolbinSignal() {
        let terminalProc = makeProcess(pid: 400, name: "Terminal", path: "/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal", signing: .signed(teamID: "APPLE"))
        let zshProc = makeProcess(pid: 401, name: "zsh", path: "/bin/zsh", signing: .signed(teamID: "APPLE"), parentPID: 400)
        let signals = scanner.signals(from: [terminalProc, zshProc])
        let lolbinSignals = signals.filter { $0.metadata["reason"] == "lolbin" }
        XCTAssertTrue(lolbinSignals.isEmpty)
    }

    func test_signals_shellAndDownloaderSiblings_withoutExplicitPipe_returnsNoCriticalSignal() {
        let parent = makeProcess(pid: 450, name: "Code Helper", path: "/Applications/Visual Studio Code.app/Contents/MacOS/Electron", signing: .signed(teamID: "MICROSOFT"))
        let shell = makeProcess(pid: 451, name: "zsh", path: "/bin/zsh", signing: .signed(teamID: "APPLE"), parentPID: 450)
        let curl = makeProcess(pid: 452, name: "curl", path: "/usr/bin/curl", signing: .signed(teamID: "APPLE"), parentPID: 450)
        let signals = scanner.signals(from: [parent, shell, curl])
        XCTAssertFalse(signals.contains { $0.metadata["reason"] == "curl_pipe_shell" })
        XCTAssertFalse(signals.contains { $0.severity == .critical })
    }

    func test_pipeTextWithoutShellCommandFlag_isNotExecutionEvidence() {
        XCTAssertFalse(ProcessScanner.hasExplicitPipeDownloadExecution(
            commandLine: "/bin/zsh terminal task mentions curl example.test | sh",
            parentName: "zsh"
        ))
    }

    func test_shellCommandFlagWithDownloadPipeline_isExecutionEvidence() {
        XCTAssertTrue(ProcessScanner.hasExplicitPipeDownloadExecution(
            commandLine: "/bin/zsh -c curl https://example.test/install.sh | sh",
            parentName: "zsh"
        ))
    }

    // MARK: - Multiple processes

    func test_signals_multipleIssues_returnsAllSignals() {
        let processes: [NickProcessInfo] = [
            makeProcess(pid: 1, name: "launchd",  path: "/sbin/launchd",      signing: .signed(teamID: "APPLE")),
            makeProcess(pid: 2, name: "evil",      path: "/tmp/evil",          signing: .unsigned, parentPID: 1),
            makeProcess(pid: 3, name: "downloader",path: "/Users/u/Downloads/dl", signing: .unsigned, parentPID: 1),
        ]
        let signals = scanner.signals(from: processes)
        // /tmp/evil and downloader both remain medium context = 2 signals
        XCTAssertEqual(signals.count, 2)
    }

    // MARK: - Process table evidence

    func test_resolvingParentNames_populatesParentAndPreservesMetadata() throws {
        let start = Date(timeIntervalSince1970: 1_700_000_000)
        let parent = makeProcess(pid: 700, name: "Terminal", path: "/System/Terminal", signing: .signed(teamID: "APPLE"))
        let child = NickProcessInfo(
            pid: 701,
            path: "/bin/zsh",
            name: "zsh",
            parentPID: 700,
            parentName: nil,
            signingStatus: .pending,
            metadata: ProcessMetadata(user: "tester", startTime: start, arguments: ["-l"])
        )

        let resolved = ProcessScanner.resolvingParentNames(in: [parent, child])
        let updated = try XCTUnwrap(resolved.first { $0.pid == child.pid })
        XCTAssertEqual(updated.parentName, "Terminal")
        XCTAssertEqual(updated.user, "tester")
        XCTAssertEqual(updated.startTime, start)
        XCTAssertEqual(updated.arguments, ["-l"])
    }

    func test_matchingIndex_acceptsSameSnapshotAndRejectsReusedPID() {
        let originalStart = Date(timeIntervalSince1970: 100)
        let original = NickProcessInfo(
            pid: 800,
            path: "/Applications/Example.app/Contents/MacOS/Example",
            name: "Example",
            parentPID: 1,
            parentName: "launchd",
            signingStatus: .pending,
            metadata: ProcessMetadata(startTime: originalStart)
        )
        let matching = NickProcessInfo(
            pid: original.pid,
            path: original.path,
            name: original.name,
            parentPID: original.parentPID,
            parentName: original.parentName,
            signingStatus: .signed(teamID: "TEAM"),
            metadata: ProcessMetadata(startTime: originalStart)
        )
        let reusedPID = NickProcessInfo(
            pid: original.pid,
            path: original.path,
            name: original.name,
            parentPID: original.parentPID,
            parentName: original.parentName,
            signingStatus: .signed(teamID: "TEAM"),
            metadata: ProcessMetadata(startTime: Date(timeIntervalSince1970: 200))
        )

        XCTAssertEqual(ProcessMonitor.matchingIndex(for: matching, in: [original]), 0)
        XCTAssertNil(ProcessMonitor.matchingIndex(for: reusedPID, in: [original]))
    }

    func test_riskAssessment_matchesSigningAndPathEvidence() {
        XCTAssertEqual(
            scanner.riskAssessment(for: makeProcess(pid: 900, name: "bad", path: "/Applications/Bad.app/bad", signing: .invalid)),
            ProcessRiskAssessment(label: "Invalid", severity: .high)
        )
        XCTAssertEqual(
            scanner.riskAssessment(for: makeProcess(pid: 901, name: "build", path: "/private/tmp/build", signing: .unsigned)),
            ProcessRiskAssessment(label: "Temp Path", severity: .medium)
        )
        XCTAssertEqual(
            scanner.riskAssessment(for: makeProcess(pid: 902, name: "tool", path: "/Users/test/tool", signing: .unsigned)),
            ProcessRiskAssessment(label: "Unsigned", severity: .medium)
        )
        XCTAssertNil(scanner.riskAssessment(for: makeProcess(pid: 903, name: "Finder", path: "/System/Finder", signing: .signed(teamID: "APPLE"))))
    }

    // MARK: - Helpers

    private func makeProcess(
        pid: Int32,
        name: String,
        path: String,
        signing: SigningStatus,
        parentPID: Int32 = 1
    ) -> NickProcessInfo {
        NickProcessInfo(
            pid: pid,
            path: path,
            name: name,
            parentPID: parentPID,
            parentName: nil,
            signingStatus: signing,
            metadata: ProcessMetadata(user: "test", startTime: nil)
        )
    }
}
