// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import XCTest
@testable import Nick

// MARK: - NetworkAnalyzerTests

/// Unit tests for `ConnectionScanner` signal generation logic.
///
/// These tests construct `NetworkConnectionInfo` values directly and verify
/// the signal derivation rules without spawning `lsof`. Integration tests
/// that call the real scanner live in `NickIntegrationTests/`.
final class NetworkAnalyzerTests: XCTestCase {

    private var scanner: ConnectionScanner!

    override func setUp() {
        super.setUp()
        scanner = ConnectionScanner()
    }

    override func tearDown() {
        scanner = nil
        super.tearDown()
    }

    // MARK: - Reverse Shell Detection

    func test_signals_bashWithEstablishedOutbound_returnsMediumObservation() {
        let conn = makeConnection(
            processName: "bash",
            remoteAddress: "203.0.113.99",
            remotePort: 4444,
            state: .established
        )
        let signals = scanner.signals(from: [conn])
        XCTAssertEqual(signals.count, 1)
        XCTAssertEqual(signals[0].severity, .medium)
        XCTAssertEqual(signals[0].metadata["reason"], "shell_network_observation")
    }

    func test_signals_zshWithEstablishedOutbound_returnsMediumObservation() {
        let conn = makeConnection(processName: "zsh", remoteAddress: "1.2.3.4", remotePort: 9001, state: .established)
        let signals = scanner.signals(from: [conn])
        XCTAssertEqual(signals[0].severity, .medium)
    }

    func test_signals_ncWithEstablishedOutbound_returnsMediumObservation() {
        let conn = makeConnection(processName: "nc", remoteAddress: "10.0.0.1", remotePort: 1234, state: .established)
        let signals = scanner.signals(from: [conn])
        XCTAssertEqual(signals[0].severity, .medium)
    }

    func test_signals_safariWithEstablishedOutbound_returnsNoReverseShellSignal() {
        let conn = makeConnection(processName: "Safari", remoteAddress: "17.253.144.10", remotePort: 443, state: .established)
        let signals = scanner.signals(from: [conn]).filter { $0.metadata["reason"] == "reverse_shell" }
        XCTAssertTrue(signals.isEmpty)
    }

    // MARK: - Raw IP Detection

    func test_signals_unknownProcessToRawIPv4_returnsLowSignal() {
        let conn = makeConnection(
            processName: "someapp",
            remoteAddress: "203.0.113.1",
            remotePort: 8080,
            state: .established
        )
        let signals = scanner.signals(from: [conn])
        XCTAssertEqual(signals.count, 1)
        XCTAssertEqual(signals[0].severity, .low)
        XCTAssertEqual(signals[0].metadata["reason"], "raw_ip_outbound")
    }

    func test_signals_loopbackConnection_returnsNoSignal() {
        let conn = makeConnection(
            processName: "someapp",
            remoteAddress: "127.0.0.1",
            remotePort: 8080,
            state: .established
        )
        let signals = scanner.signals(from: [conn])
        XCTAssertTrue(signals.isEmpty)
    }

    func test_signals_listeningConnection_returnsNoSignal() {
        let conn = makeConnection(
            processName: "apache",
            remoteAddress: nil,
            remotePort: nil,
            state: .listen
        )
        let signals = scanner.signals(from: [conn])
        XCTAssertTrue(signals.isEmpty)
    }

    func test_signals_bogusRemoteAddress_returnsNoSignal() {
        for bogus in ["0.0.0.0", "::", "", "0:0:0:0:0:0:0:0"] {
            let conn = makeConnection(processName: "someapp", remoteAddress: bogus, remotePort: 80, state: .established)
            let signals = scanner.signals(from: [conn]).filter { $0.metadata["reason"] == "raw_ip_outbound" }
            XCTAssertTrue(signals.isEmpty, "Expected no raw_ip_outbound signal for bogus address '\(bogus)'")
        }
    }

    func test_signals_linkLocalIPv6_returnsNoSignal() {
        let conn = makeConnection(processName: "someapp", remoteAddress: "fe80::1%lo0", remotePort: 5353, state: .established)
        let signals = scanner.signals(from: [conn]).filter { $0.metadata["reason"] == "raw_ip_outbound" }
        XCTAssertTrue(signals.isEmpty)
    }

    func test_signals_unresolvedTrustedName_failsClosed() {
        for process in ["Spotify", "Xcode", "Claude Helper", "rapportd", "identityservicesd", "Safari"] {
            // A trusted-looking name is not proof of identity. If proc_pidpath cannot
            // resolve the executable, Nick must keep the observation instead of
            // silently trusting a potentially impersonated process.
            let conn = makeConnection(
                pid: Int32.max,
                processName: process,
                remoteAddress: "203.0.113.1",
                remotePort: 443,
                state: .established
            )
            let signals = scanner.signals(from: [conn]).filter { $0.metadata["reason"] == "raw_ip_outbound" }
            XCTAssertEqual(signals.count, 1, "Expected unresolved trusted-looking process to fail closed: \(process)")
        }
    }

    func test_signals_privateNetworkAddresses_returnsNoSignal() {
        let privateAddresses = [
            "10.0.0.1", "10.128.5.9",
            "192.168.1.1", "192.168.100.200",
            "172.16.0.1", "172.20.5.5", "172.31.255.254"
        ]
        for addr in privateAddresses {
            let conn = makeConnection(processName: "someapp", remoteAddress: addr, remotePort: 80, state: .established)
            let signals = scanner.signals(from: [conn]).filter { $0.metadata["reason"] == "raw_ip_outbound" }
            XCTAssertTrue(signals.isEmpty, "Expected no raw_ip_outbound signal for private address '\(addr)'")
        }
    }

    // MARK: - Multiple connections

    func test_signals_mixedConnections_returnsCorrectCount() {
        let reverseShell = makeConnection(processName: "bash", remoteAddress: "1.2.3.4", remotePort: 4444, state: .established)
        let normal       = makeConnection(processName: "Safari", remoteAddress: "17.x.x.x", remotePort: 443, state: .established)
        let rawIP        = makeConnection(processName: "myapp", remoteAddress: "99.99.99.99", remotePort: 8080, state: .established)

        let signals = scanner.signals(from: [reverseShell, normal, rawIP])
        // Safari is a trusted process, so only reverseShell + rawIP (myapp) fire → 2 signals
        XCTAssertEqual(signals.count, 2)
    }

    // MARK: - ConnectionState rawString init

    func test_connectionState_rawStringInit_knownValue() {
        XCTAssertEqual(ConnectionState(rawString: "ESTABLISHED"), .established)
        XCTAssertEqual(ConnectionState(rawString: "LISTEN"), .listen)
        XCTAssertEqual(ConnectionState(rawString: "TIME_WAIT"), .timeWait)
    }

    func test_connectionState_rawStringInit_unknownFallback() {
        XCTAssertEqual(ConnectionState(rawString: "SOME_NEW_STATE"), .unknown)
    }

    // MARK: - NetworkConnectionInfo computed properties

    func test_isOutbound_withRemoteAddress_returnsTrue() {
        let conn = makeConnection(processName: "app", remoteAddress: "1.2.3.4", remotePort: 80, state: .established)
        XCTAssertTrue(conn.isOutbound)
    }

    func test_isOutbound_withoutRemoteAddress_returnsFalse() {
        let conn = makeConnection(processName: "app", remoteAddress: nil, remotePort: nil, state: .listen)
        XCTAssertFalse(conn.isOutbound)
    }

    func test_isShellProcess_bash_returnsTrue() {
        let conn = makeConnection(processName: "bash", remoteAddress: nil, remotePort: nil, state: .listen)
        XCTAssertTrue(conn.isShellProcess)
    }

    func test_isShellProcess_safari_returnsFalse() {
        let conn = makeConnection(processName: "Safari", remoteAddress: nil, remotePort: nil, state: .listen)
        XCTAssertFalse(conn.isShellProcess)
    }

    // MARK: - Helpers

    private func makeConnection(
        pid: Int32 = 999,
        processName: String,
        remoteAddress: String?,
        remotePort: Int?,
        state: ConnectionState
    ) -> NetworkConnectionInfo {
        NetworkConnectionInfo(
            id: UUID(),
            pid: pid,
            processName: processName,
            transportProtocol: .tcp,
            localAddress: "0.0.0.0",
            localPort: 12345,
            remoteAddress: remoteAddress,
            remotePort: remotePort,
            state: state
        )
    }
}
