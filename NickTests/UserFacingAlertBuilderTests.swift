// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import XCTest
@testable import Nick

final class UserFacingAlertBuilderTests: XCTestCase {

    func test_legacyShazamdAttribution_isInformational() {
        let alert = makeCaptureAlert(
            processName: "shazamd",
            path: "/Library/Developer/CoreSimulator/Volumes/iOS_Test/RuntimeRoot/System/Library/Frameworks/ShazamKit.framework/shazamd",
            signingStatus: .adHoc,
            severity: .info
        )

        let result = UserFacingAlertBuilder.shared.build(from: alert)

        XCTAssertEqual(result.severity, .safe)
        XCTAssertEqual(result.assessment, "Informational activity")
        XCTAssertTrue(result.headline.contains("became active"))
        XCTAssertTrue(result.explanation.contains("were not evidence"))
        XCTAssertTrue(result.recommendedAction.contains("Driftor"))
        XCTAssertFalse(result.actions.contains(.quarantine))
    }

    func test_unverifiedUnsignedCapture_doesNotAccuseOrRecommendDeletion() {
        let alert = makeCaptureAlert(
            processName: "unknown-camera-tool",
            path: "/tmp/unknown-camera-tool",
            signingStatus: .unsigned,
            severity: .high
        )

        let result = UserFacingAlertBuilder.shared.build(from: alert)

        XCTAssertEqual(result.severity, .safe)
        XCTAssertEqual(result.assessment, "Informational activity")
        XCTAssertTrue(result.explanation.contains("were not evidence"))
        XCTAssertFalse(result.recommendedAction.lowercased().contains("delete"))
    }

    func test_genericFallback_doesNotClaimNickBlockedAnything() {
        let alert = ThreatAlert(
            score: 0.6,
            content: AlertContent(
                title: "Unclassified event",
                description: "A detector observed an unusual event.",
                severity: .medium,
                recommendedAction: "Review the event."
            ),
            contributingSignals: []
        )

        let result = UserFacingAlertBuilder.shared.build(from: alert)

        XCTAssertFalse(result.explanation.lowercased().contains("taken protective action"))
        XCTAssertFalse(result.explanation.lowercased().contains("blocked"))
        XCTAssertTrue(result.explanation.contains("does not by itself prove"))
    }

    func test_nickTemporaryBuildYARAMatch_isSafeDeveloperActivity() {
        let path = "/private/tmp/NickPerformanceAuditTests/Build/Products/Debug/Nick.app/Contents/MacOS/Nick.debug.dylib"
        let signal = ThreatSignal(
            source: .yara,
            severity: .high,
            title: "YARA match: macos_launchagent_install",
            description: "Matched a persistence heuristic.",
            context: ThreatSignalContext(
                fileInfo: FileInfo(
                    path: path,
                    sha256Hash: nil,
                    entropy: nil,
                    signingStatus: nil,
                    sizeBytes: nil
                ),
                metadata: ["yaraRules": "macos_launchagent_install"]
            )
        )
        let alert = ThreatAlert(
            score: 0.9,
            content: AlertContent(
                title: "Known threat detected",
                description: "YARA match",
                severity: .high,
                recommendedAction: "Quarantine."
            ),
            contributingSignals: [signal]
        )

        let result = UserFacingAlertBuilder.shared.build(from: alert)

        XCTAssertEqual(result.severity, .safe)
        XCTAssertEqual(result.assessment, "Safe developer activity")
        XCTAssertFalse(result.actions.contains(.quarantine))
    }

    func test_mediumYARAHeuristic_isReviewNotKnownMalware() {
        let signal = ThreatSignal(
            source: .yara,
            severity: .medium,
            title: "YARA match: macos_launchagent_install",
            description: "Matched a persistence heuristic.",
            context: ThreatSignalContext(
                fileInfo: FileInfo(
                    path: "/Users/test/Downloads/Installer",
                    sha256Hash: nil,
                    entropy: nil,
                    signingStatus: nil,
                    sizeBytes: nil
                ),
                metadata: ["yaraRules": "macos_launchagent_install"]
            )
        )
        let alert = ThreatAlert(
            score: 0.7,
            content: AlertContent(
                title: "Known threat detected",
                description: "YARA match",
                severity: .medium,
                recommendedAction: "Review."
            ),
            contributingSignals: [signal]
        )

        let result = UserFacingAlertBuilder.shared.build(from: alert)

        XCTAssertEqual(result.severity, .warning)
        XCTAssertTrue(result.headline.contains("suspicious behavior"))
        XCTAssertTrue(result.explanation.contains("not a confirmed malware detection"))
        XCTAssertTrue(result.actions.contains(.quarantine))
        XCTAssertTrue(result.actions.contains(.allowOnce))
        XCTAssertTrue(result.actions.contains(.keepBlocked))
    }

    func test_highYARAHeuristic_isStillReviewableAndNeverAutoQuarantine() {
        let process = NickProcessInfo(
            pid: 42,
            path: "/Applications/Xcode.app/Contents/SharedFrameworks/XCBuild.framework/XCBuild",
            name: "SWBBuildService",
            parentPID: 1,
            parentName: "Xcode",
            signingStatus: .signed(teamID: "APPLE"),
            metadata: ProcessMetadata()
        )
        let signal = ThreatSignal(
            source: .yara,
            severity: .critical,
            title: "YARA match: macos_mass_file_rename",
            description: "Matched a behavioral rule.",
            context: ThreatSignalContext(
                processInfo: process,
                fileInfo: FileInfo(
                    path: "/Users/test/Library/Developer/Xcode/DerivedData/App/Build/Products/Debug/App",
                    sha256Hash: "changing-build-hash",
                    entropy: nil,
                    signingStatus: nil,
                    sizeBytes: nil
                ),
                metadata: ["yaraRules": "macos_mass_file_rename"]
            )
        )
        let alert = ThreatAlert(
            score: 0.95,
            content: AlertContent(
                title: "Known threat detected",
                description: "YARA match",
                severity: .critical,
                recommendedAction: "Quarantine."
            ),
            contributingSignals: [signal]
        )

        let result = UserFacingAlertBuilder.shared.build(from: alert)

        XCTAssertEqual(result.severity, .warning)
        XCTAssertEqual(result.assessment, "Needs your review")
        XCTAssertTrue(result.explanation.contains("not a confirmed malware"))
        XCTAssertTrue(result.actions.contains(.quarantine))
        XCTAssertTrue(result.actions.contains(.allowOnce))
        XCTAssertTrue(result.actions.contains(.keepBlocked))
    }

    private func makeCaptureAlert(
        processName: String,
        path: String,
        signingStatus: SigningStatus,
        severity: SignalSeverity
    ) -> ThreatAlert {
        let process = NickProcessInfo(
            pid: 68348,
            path: path,
            name: processName,
            parentPID: 1,
            parentName: nil,
            signingStatus: signingStatus,
            metadata: ProcessMetadata()
        )
        let signal = ThreatSignal(
            source: .avCapture,
            severity: severity,
            title: "HD Web Camera activated by \(processName)",
            description: "Capture activity",
            context: ThreatSignalContext(
                processInfo: process,
                metadata: [
                    "deviceName": "HD Web Camera",
                    "mediaType": "camera",
                    "process": processName,
                    "reason": "capture_device_active"
                ]
            )
        )
        return ThreatAlert(
            score: severity == .info ? 0.2 : 0.85,
            content: AlertContent(
                title: "Camera or microphone activity needs review",
                description: "HD Web Camera became active.",
                severity: severity,
                recommendedAction: "Review camera access."
            ),
            contributingSignals: [signal]
        )
    }
}
