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

    func test_signals_unsignedBinaryInTmpPath_returnsHighSeverity() {
        let proc = makeProcess(pid: 100, name: "evil", path: "/tmp/evil", signing: .unsigned)
        let signals = scanner.signals(from: [proc])
        XCTAssertEqual(signals.count, 1)
        XCTAssertEqual(signals[0].severity, .high)
    }

    func test_signals_unsignedBinaryInVarFolders_returnsHighSeverity() {
        let proc = makeProcess(pid: 101, name: "payload", path: "/var/folders/ab/cd/T/payload", signing: .unsigned)
        let signals = scanner.signals(from: [proc])
        XCTAssertEqual(signals[0].severity, .high)
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

    func test_signals_bashSpawnedByLaunchd_returnsMediumSignal() {
        // bash whose parent is "launchd" (not a terminal) → LOLBin
        let bashProc = makeProcess(pid: 300, name: "bash", path: "/bin/bash", signing: .signed(teamID: "APPLE"), parentPID: 1)
        let launchdProc = makeProcess(pid: 1, name: "launchd", path: "/sbin/launchd", signing: .signed(teamID: "APPLE"))
        let signals = scanner.signals(from: [bashProc, launchdProc])
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

    // MARK: - Multiple processes

    func test_signals_multipleIssues_returnsAllSignals() {
        let processes: [NickProcessInfo] = [
            makeProcess(pid: 1, name: "launchd",  path: "/sbin/launchd",      signing: .signed(teamID: "APPLE")),
            makeProcess(pid: 2, name: "evil",      path: "/tmp/evil",          signing: .unsigned, parentPID: 1),
            makeProcess(pid: 3, name: "downloader",path: "/Users/u/Downloads/dl", signing: .unsigned, parentPID: 1),
        ]
        let signals = scanner.signals(from: processes)
        // /tmp/evil → high, downloader → medium = 2 signals
        XCTAssertEqual(signals.count, 2)
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
            user: "test",
            startTime: nil
        )
    }
}
