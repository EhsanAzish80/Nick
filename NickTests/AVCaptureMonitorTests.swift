// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import XCTest
@testable import Nick

// MARK: - AVCaptureMonitorTests

/// Unit tests for `AVCaptureMonitor`, `DetectedCaptureProcess`, and the
/// `unexpectedCaptureDeviceRule` correlation rule.
///
/// Hardware-dependent paths (CoreMediaIO enumeration, live CoreAudio queries)
/// cannot run in the unit-test sandbox and are therefore excluded.  All tests
/// exercise the signal-generation logic and the correlation rule in isolation.
@MainActor
final class AVCaptureMonitorTests: XCTestCase {

    // MARK: - Fixtures

    private var monitor: AVCaptureMonitor!

    override func setUp() async throws {
        try await super.setUp()
        monitor = AVCaptureMonitor()
    }

    override func tearDown() async throws {
        await monitor.stop()
        monitor = nil
        try await super.tearDown()
    }

    // MARK: - Signal Generation: source

    func test_makeCaptureSignal_source_isAVCapture() async {
        let signal = monitor.makeCaptureSignal(
            mediaType: "camera", deviceName: "FaceTime HD Camera", process: nil
        )
        XCTAssertEqual(signal.source, .avCapture)
    }

    // MARK: - Signal Generation: severity

    func test_makeCaptureSignal_nilProcess_severityMedium() async {
        let signal = monitor.makeCaptureSignal(
            mediaType: "camera", deviceName: "Camera", process: nil
        )
        XCTAssertEqual(signal.severity, .medium)
    }

    func test_makeCaptureSignal_signedProcess_severityMedium() async {
        let process = DetectedCaptureProcess(
            pid:           12345,
            name:          "Zoom",
            path:          "/Applications/zoom.us.app/Contents/MacOS/zoom.us",
            signingStatus: .signed(teamID: "BJ4HAAB9B3")
        )
        let signal = monitor.makeCaptureSignal(
            mediaType: "camera", deviceName: "Camera", process: process
        )
        XCTAssertEqual(signal.severity, .medium)
    }

    func test_makeCaptureSignal_unsignedProcess_severityHigh() async {
        let process = DetectedCaptureProcess(
            pid:           9999,
            name:          "evilspy",
            path:          "/tmp/evilspy",
            signingStatus: .unsigned
        )
        let signal = monitor.makeCaptureSignal(
            mediaType: "camera", deviceName: "Camera", process: process
        )
        XCTAssertEqual(signal.severity, .high)
    }

    func test_makeCaptureSignal_invalidSignature_severityHigh() async {
        let process = DetectedCaptureProcess(
            pid:           8888,
            name:          "tampered",
            path:          "/tmp/tampered",
            signingStatus: .invalid
        )
        let signal = monitor.makeCaptureSignal(
            mediaType: "microphone", deviceName: "MacBook Pro Microphone", process: process
        )
        XCTAssertEqual(signal.severity, .high)
    }

    // MARK: - Signal Generation: metadata

    func test_makeCaptureSignal_metadata_containsExpectedKeys() async {
        let signal = monitor.makeCaptureSignal(
            mediaType:  "microphone",
            deviceName: "MacBook Pro Microphone",
            process:    nil
        )
        XCTAssertEqual(signal.metadata["mediaType"],  "microphone")
        XCTAssertEqual(signal.metadata["deviceName"], "MacBook Pro Microphone")
        XCTAssertEqual(signal.metadata["reason"],     "capture_device_active")
        XCTAssertNotNil(signal.metadata["process"])
    }

    // MARK: - Signal Generation: processInfo

    func test_makeCaptureSignal_withProcess_populatesProcessInfo() async {
        let process = DetectedCaptureProcess(
            pid:           1234,
            name:          "SuspiciousApp",
            path:          "/Applications/SuspiciousApp.app/Contents/MacOS/SuspiciousApp",
            signingStatus: .unsigned
        )
        let signal = monitor.makeCaptureSignal(
            mediaType: "camera", deviceName: "Camera", process: process
        )
        XCTAssertNotNil(signal.processInfo)
        XCTAssertEqual(signal.processInfo?.pid,  1234)
        XCTAssertEqual(signal.processInfo?.name, "SuspiciousApp")
    }

    func test_makeCaptureSignal_nilProcess_processInfoIsNil() async {
        let signal = monitor.makeCaptureSignal(
            mediaType: "camera", deviceName: "Camera", process: nil
        )
        XCTAssertNil(signal.processInfo)
    }

    // MARK: - Signal Generation: title & description

    func test_makeCaptureSignal_title_includesDeviceName() async {
        let signal = monitor.makeCaptureSignal(
            mediaType: "camera", deviceName: "Logitech BRIO", process: nil
        )
        XCTAssertTrue(signal.title.contains("Logitech BRIO"), "title = \(signal.title)")
    }

    func test_makeCaptureSignal_description_mentionsMalware() async {
        let signal = monitor.makeCaptureSignal(
            mediaType: "camera", deviceName: "Camera", process: nil
        )
        XCTAssertTrue(
            signal.description.lowercased().contains("malware"),
            "Expected description to contain 'malware'; got: \(signal.description)"
        )
    }

    // MARK: - latestSignals drains buffer

    func test_latestSignals_freshMonitor_returnsEmpty() async {
        let signals = await monitor.latestSignals()
        XCTAssertTrue(signals.isEmpty)
    }

    // MARK: - Published state defaults

    func test_initialState_cameraNotActive() async {
        XCTAssertFalse(monitor.isCameraActive)
    }

    func test_initialState_microphoneNotActive() async {
        XCTAssertFalse(monitor.isMicrophoneActive)
    }

    func test_initialState_notRunning() async {
        XCTAssertFalse(monitor.isRunning)
    }

    // MARK: - MonitorType

    func test_monitorType_isAVCapture() async {
        XCTAssertEqual(monitor.monitorType, .avCapture)
    }

    // MARK: - CorrelationRule

    func test_unexpectedCaptureDeviceRule_firesForAVCaptureSignal() {
        let signal = makeCaptureSignal(severity: .medium)
        let rule   = correlationRule(named: "unexpected_capture_device")
        let alert  = rule?.evaluate([signal])
        XCTAssertNotNil(alert, "Rule should produce an alert for .avCapture signals")
        XCTAssertEqual(alert?.severity, .high)
    }

    func test_unexpectedCaptureDeviceRule_doesNotFireForOtherSources() {
        let signal = makeProcessSignal()
        let rule   = correlationRule(named: "unexpected_capture_device")
        let alert  = rule?.evaluate([signal])
        XCTAssertNil(alert, "Rule must not fire for non-avCapture signals")
    }

    func test_unexpectedCaptureDeviceRule_alertContainsDeviceAndProcessNames() {
        let signal = makeCaptureSignal(
            severity:   .medium,
            deviceName: "FaceTime HD Camera",
            process:    "evilspy"
        )
        let rule  = correlationRule(named: "unexpected_capture_device")
        let alert = rule?.evaluate([signal])
        XCTAssertTrue(alert?.description.contains("FaceTime HD Camera") == true)
        XCTAssertTrue(alert?.description.contains("evilspy") == true)
    }

    // MARK: - MonitorType display helpers

    func test_monitorType_displayName() {
        XCTAssertEqual(MonitorType.avCapture.displayName, "Camera & Microphone")
    }

    func test_monitorType_systemImage() {
        XCTAssertEqual(MonitorType.avCapture.systemImage, "camera")
    }
}

// MARK: - Helpers

private extension AVCaptureMonitorTests {

    /// Builds a minimal `.avCapture` ThreatSignal for correlation-rule tests.
    func makeCaptureSignal(
        severity:   SignalSeverity = .medium,
        deviceName: String         = "Camera",
        process:    String         = "unknown"
    ) -> ThreatSignal {
        ThreatSignal(
            source:      .avCapture,
            severity:    severity,
            title:       "\(deviceName) activated by \(process)",
            description: "Test signal",
            processInfo: nil,
            metadata: [
                "mediaType":  "camera",
                "deviceName": deviceName,
                "process":    process,
                "reason":     "capture_device_active"
            ]
        )
    }

    /// Returns a `.process` signal for negative-rule testing.
    func makeProcessSignal() -> ThreatSignal {
        ThreatSignal(
            source:      .process,
            severity:    .high,
            title:       "Suspicious process",
            description: "Test",
            processInfo: nil,
            metadata:    [:]
        )
    }

    /// Returns the `CorrelationRule` with the given name, or `nil` if not found.
    func correlationRule(named name: String) -> CorrelationRule? {
        CorrelationRule.standard.first { $0.name == name }
    }
}
