import XCTest
@testable import Nick

final class SignatureValidatorPolicyTests: XCTestCase {
    func test_sealedSystemLocationsSkipExpensiveTrustEvaluation() {
        XCTAssertTrue(SignatureValidator.isSealedSystemBinaryPath(
            "/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder"
        ))
        XCTAssertTrue(SignatureValidator.isSealedSystemBinaryPath("/usr/libexec/sharingd"))
        XCTAssertTrue(SignatureValidator.isSealedSystemBinaryPath("/usr/bin/git"))
        XCTAssertTrue(SignatureValidator.isSealedSystemBinaryPath("/bin/ls"))
        XCTAssertTrue(SignatureValidator.isSealedSystemBinaryPath("/sbin/mount"))
    }

    func test_writableAndThirdPartyLocationsStillRequireValidation() {
        XCTAssertFalse(SignatureValidator.isSealedSystemBinaryPath(
            "/Applications/Example.app/Contents/MacOS/Example"
        ))
        XCTAssertFalse(SignatureValidator.isSealedSystemBinaryPath(
            "/Library/PrivilegedHelperTools/example"
        ))
        XCTAssertFalse(SignatureValidator.isSealedSystemBinaryPath("/usr/local/bin/tool"))
        XCTAssertFalse(SignatureValidator.isSealedSystemBinaryPath("/Users/example/tool"))
        XCTAssertFalse(SignatureValidator.isSealedSystemBinaryPath("/private/tmp/tool"))
    }
}
