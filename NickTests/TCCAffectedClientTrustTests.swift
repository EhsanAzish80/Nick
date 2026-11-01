import XCTest
@testable import Nick

final class TCCAffectedClientTrustTests: XCTestCase {
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
}
