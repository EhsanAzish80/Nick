// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import XCTest
@testable import Nick

// MARK: - LOLBinDetectorTests

final class LOLBinDetectorTests: XCTestCase {

    // MARK: - Helpers

    private func makeProc(
        pid: Int32 = 100,
        name: String,
        path: String = "/bin/bash",
        parentPID: Int32 = 1,
        parentName: String = ""
    ) -> NickProcessInfo {
        NickProcessInfo(
            pid: pid,
            path: path,
            name: name,
            parentPID: parentPID,
            parentName: parentName,
            signingStatus: .adHoc,
            metadata: ProcessMetadata(user: "root", startTime: Date())
        )
    }

    // MARK: - curl pipe shell

    func test_evaluate_bashWithCurlParent_returnsCriticalSignal() {
        let proc = makeProc(name: "bash", parentName: "sh")
        let signal = LOLBinDetector.evaluate(proc, parentName: "curl")
        XCTAssertNotNil(signal)
        XCTAssertEqual(signal?.severity, .critical)
    }

    func test_evaluate_shWithCurlInArgs_returnsCriticalSignal() {
        // curl in path string simulates argv[0] from parent
        let procWithCurlPath = NickProcessInfo(
            pid: 101, path: "/usr/bin/curl | sh", name: "sh",
            parentPID: 1, parentName: "curl",
            signingStatus: .adHoc, metadata: ProcessMetadata(user: "root", startTime: Date())
        )
        let signal = LOLBinDetector.evaluate(procWithCurlPath, parentName: "curl")
        XCTAssertNotNil(signal)
    }

    func test_evaluate_bashWithWgetParent_returnsCriticalSignal() {
        let proc = makeProc(name: "bash", parentName: "wget")
        let signal = LOLBinDetector.evaluate(proc, parentName: "wget")
        XCTAssertNotNil(signal)
        XCTAssertEqual(signal?.severity, .critical)
    }

    // MARK: - osascript

    func test_evaluate_osascriptWithShellScript_returnsHighSignal() {
        let proc = NickProcessInfo(
            pid: 102, path: "/usr/bin/osascript do shell script", name: "osascript",
            parentPID: 1, parentName: "",
            signingStatus: .signed(teamID: "APPLE"), metadata: ProcessMetadata(user: "root", startTime: Date())
        )
        let signal = LOLBinDetector.evaluate(proc, parentName: nil)
        XCTAssertNotNil(signal)
        XCTAssertEqual(signal?.severity, .high)
    }

    // MARK: - xattr quarantine removal

    func test_evaluate_xattrRemovingQuarantine_returnsHighSignal() {
        let proc = NickProcessInfo(
            pid: 103, path: "/usr/bin/xattr -d com.apple.quarantine /tmp/app", name: "xattr",
            parentPID: 1, parentName: "",
            signingStatus: .signed(teamID: "APPLE"), metadata: ProcessMetadata(user: "root", startTime: Date())
        )
        let signal = LOLBinDetector.evaluate(proc, parentName: nil)
        XCTAssertNotNil(signal)
        XCTAssertEqual(signal?.severity, .high)
    }

    // MARK: - base64 payload

    func test_evaluate_python3WithBase64_returnsHighSignal() {
        let proc = NickProcessInfo(
            pid: 104, path: "/usr/bin/python3 -c import base64", name: "python3",
            parentPID: 1, parentName: "",
            signingStatus: .adHoc, metadata: ProcessMetadata(user: "user", startTime: Date())
        )
        let signal = LOLBinDetector.evaluate(proc, parentName: nil)
        XCTAssertNotNil(signal)
        XCTAssertEqual(signal?.severity, .high)
    }

    func test_evaluate_rubyWithBase64_returnsHighSignal() {
        let proc = NickProcessInfo(
            pid: 105, path: "/usr/bin/ruby base64", name: "ruby",
            parentPID: 1, parentName: "",
            signingStatus: .adHoc, metadata: ProcessMetadata(user: "user", startTime: Date())
        )
        let signal = LOLBinDetector.evaluate(proc, parentName: nil)
        XCTAssertNotNil(signal)
    }

    // MARK: - launchctl from tmp

    func test_evaluate_launchctlLoadFromTmp_returnsCriticalSignal() {
        let proc = NickProcessInfo(
            pid: 106, path: "/bin/launchctl load /tmp/com.evil.plist", name: "launchctl",
            parentPID: 1, parentName: "",
            signingStatus: .signed(teamID: "APPLE"), metadata: ProcessMetadata(user: "root", startTime: Date())
        )
        let signal = LOLBinDetector.evaluate(proc, parentName: nil)
        XCTAssertNotNil(signal)
        XCTAssertEqual(signal?.severity, .critical)
    }

    // MARK: - Trusted parent suppression

    func test_evaluate_trustedParentTerminal_returnsNil() {
        let proc = makeProc(name: "bash", parentName: "Terminal")
        let trusted = TrustedProcessList()
        // Terminal is in builtIn list
        let signal = LOLBinDetector.evaluate(proc, parentName: "Terminal", trustedProcessList: trusted)
        XCTAssertNil(signal)
    }

    // MARK: - Safe process — no match

    func test_evaluate_safariNoMatch_returnsNil() {
        let proc = makeProc(name: "Safari", path: "/Applications/Safari.app")
        let signal = LOLBinDetector.evaluate(proc, parentName: nil)
        XCTAssertNil(signal)
    }

    func test_evaluate_grepNormalArgs_returnsNil() {
        let proc = makeProc(name: "grep", path: "/usr/bin/grep pattern /var/log/system.log")
        let signal = LOLBinDetector.evaluate(proc, parentName: nil)
        XCTAssertNil(signal)
    }

    // MARK: - signals(from:)

    func test_signals_multipleLOLBinProcesses_returnsExpectedCount() {
        let processes: [NickProcessInfo] = [
            NickProcessInfo(pid: 200, path: "/bin/bash curl something", name: "bash",
                            parentPID: 1, parentName: "curl",
                            signingStatus: .adHoc, metadata: ProcessMetadata(user: "root", startTime: Date())),
            NickProcessInfo(pid: 201, path: "/usr/bin/xattr -d com.apple.quarantine /tmp/app", name: "xattr",
                            parentPID: 1, parentName: "",
                            signingStatus: .signed(teamID: "APPLE"), metadata: ProcessMetadata(user: "root", startTime: Date())),
            makeProc(pid: 202, name: "Safari", path: "/Applications/Safari.app"),
        ]
        let signals = LOLBinDetector.signals(from: processes)
        XCTAssertEqual(signals.count, 2)
    }

    func test_signals_noLOLBinProcesses_returnsEmpty() {
        let processes = [makeProc(name: "Safari"), makeProc(pid: 300, name: "Finder")]
        let signals = LOLBinDetector.signals(from: processes)
        XCTAssertTrue(signals.isEmpty)
    }

    func test_signals_trustedParentDoesNotHideStrongPattern() {
        let processes = [
            NickProcessInfo(pid: 400, path: "/bin/bash curl x", name: "bash",
                            parentPID: 1, parentName: "Terminal",
                            signingStatus: .adHoc, metadata: ProcessMetadata(user: "user", startTime: Date()))
        ]
        let signals = LOLBinDetector.signals(from: processes)
        XCTAssertEqual(signals.first?.severity, .critical)
        XCTAssertEqual(signals.first?.metadata["reason"], "curl_pipe_shell")
    }

    func test_signals_codeHelperParentDoesNotHideStrongPattern() {
        let processes = [
            NickProcessInfo(pid: 401, path: "/bin/bash curl payload | bash", name: "bash",
                            parentPID: 2, parentName: "Code Helper",
                            signingStatus: .adHoc, metadata: ProcessMetadata(user: "user", startTime: Date()))
        ]
        let signals = LOLBinDetector.signals(from: processes)
        XCTAssertEqual(signals.first?.severity, .critical)
    }

    // MARK: - Metadata

    func test_evaluate_signal_containsDetectorMetadata() {
        let proc = NickProcessInfo(
            pid: 500, path: "/usr/bin/xattr -d com.apple.quarantine /tmp/x", name: "xattr",
            parentPID: 1, parentName: "",
            signingStatus: .signed(teamID: "APPLE"), metadata: ProcessMetadata(user: "root", startTime: Date())
        )
        let signal = LOLBinDetector.evaluate(proc, parentName: nil)
        XCTAssertEqual(signal?.metadata["detector"], "LOLBinDetector")
    }
}
