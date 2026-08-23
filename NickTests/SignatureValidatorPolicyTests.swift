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

    @MainActor
    func test_backfillSettlesMissingPathAndPreservesProcessEvidence() async {
        let start = Date(timeIntervalSince1970: 1_700_000_000)
        let process = NickProcessInfo(
            pid: 42,
            path: "",
            name: "restricted",
            parentPID: 1,
            parentName: "launchd",
            signingStatus: .pending,
            metadata: ProcessMetadata(user: "root", startTime: start, arguments: ["--flag"])
        )
        var updates: [NickProcessInfo] = []

        await SignatureValidator.shared.backfill(processes: [process]) { updated in
            updates.append(updated)
        }

        XCTAssertEqual(updates.count, 1)
        XCTAssertEqual(updates[0].signingStatus, .unknown)
        XCTAssertEqual(updates[0].parentName, "launchd")
        XCTAssertEqual(updates[0].user, "root")
        XCTAssertEqual(updates[0].startTime, start)
        XCTAssertEqual(updates[0].arguments, ["--flag"])
    }
}
