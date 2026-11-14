import XCTest
@testable import Nick

final class TCCAffectedClientTrustTests: XCTestCase {
    func testAffectedClientNeverUsesUnrelatedInstigatorName() {
        XCTAssertEqual(TCCAffectedClientTrustPolicy.affectedClientName(appBundleID: "com.example.target", appPath: "", actorBundleID: "com.apple.tccd", actorPath: "/usr/libexec/tccd", actorName: "tccd"), "com.example.target")
        XCTAssertEqual(TCCAffectedClientTrustPolicy.affectedClientName(appBundleID: "com.example.target", appPath: "", actorBundleID: "com.example.target", actorPath: nil, actorName: "Target"), "Target")
        XCTAssertEqual(TCCAffectedClientTrustPolicy.affectedClientName(appBundleID: "", appPath: "/Applications/Target.app", actorBundleID: nil, actorPath: "/usr/libexec/tccd", actorName: "tccd"), "Target")
    }
    func testValidatedAppleAffectedPathIsTimelineOnlyDespitePathSpellingMismatch() {
        XCTAssertTrue(TCCAffectedClientTrustPolicy.isValidatedAppleClient(
            appBundleID: "",
            appPath: "/usr/libexec/sandboxd",
            liveBundleID: "com.apple.installer",
            livePath: "/System/Library/CoreServices/Installer.app",
            liveIsValidatedApple: true,
            validateApplePath: { $0 == "/usr/libexec/sandboxd" }
        ))
    }

    func testUnvalidatedAffectedPathDoesNotBecomeTimelineOnly() {
        XCTAssertFalse(TCCAffectedClientTrustPolicy.isValidatedAppleClient(
            appBundleID: "example.helper",
            appPath: "/tmp/helper",
            liveBundleID: "example.helper",
            livePath: "/tmp/helper",
            liveIsValidatedApple: false,
            validateApplePath: { _ in false }
        ))
    }

    func testMatchingValidatedAppleBundleRemainsTimelineOnly() {
        XCTAssertTrue(TCCAffectedClientTrustPolicy.isValidatedAppleClient(
            appBundleID: "com.apple.sandboxd",
            appPath: "",
            liveBundleID: "com.apple.sandboxd",
            livePath: "/usr/libexec/sandboxd",
            liveIsValidatedApple: true,
            validateApplePath: { _ in false }
        ))
    }

    func testValidatedAppleRevocationIsTimelineOnly() {
        XCTAssertEqual(TCCAffectedClientTrustPolicy.disposition(
            validatedAppleClient: true,
            isGranted: false,
            service: "kTCCServiceSystemPolicyAllFiles",
            affectsNick: false
        ), .timelineOnly)
    }

    func testValidatedAppleSensitiveGrantsRemainActionable() {
        let sensitiveServices = [
            "kTCCServiceSystemPolicyAllFiles",
            "kTCCServiceAccessibility",
            "kTCCServiceScreenCapture",
            "kTCCServiceListenEvent",
            "kTCCServicePostEvent",
        ]

        for service in sensitiveServices {
            XCTAssertEqual(TCCAffectedClientTrustPolicy.disposition(
                validatedAppleClient: true,
                isGranted: true,
                service: service,
                affectsNick: false
            ), .actionable, "Apple-signed client grant must remain actionable for \(service)")
        }
    }

    func testNickPermissionRevocationRemainsActionable() {
        XCTAssertEqual(TCCAffectedClientTrustPolicy.disposition(
            validatedAppleClient: true,
            isGranted: false,
            service: "kTCCServiceSystemPolicyAllFiles",
            affectsNick: true
        ), .actionable)
    }

    func testValidatedAppleNonSensitiveGrantIsInformational() {
        XCTAssertEqual(TCCAffectedClientTrustPolicy.disposition(
            validatedAppleClient: true,
            isGranted: true,
            service: "kTCCServiceCalendar",
            affectsNick: false
        ), .inform)
    }
}
