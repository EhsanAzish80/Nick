import XCTest
@testable import Nick

final class InteractiveShellPipelinePolicyTests: XCTestCase {
    func test_typedCurlPipeToShellAcrossSiblingProcessesAlerts() throws {
        let policy = InteractiveShellPipelinePolicy()
        let time = Date(timeIntervalSince1970: 100)
        XCTAssertNil(policy.observe(.init(
            pid: 10,
            parentPID: 5,
            executablePath: "/usr/bin/curl",
            arguments: ["curl", "https://user:secret@example.test/x?token=secret"],
            pipeIdentifiers: [99],
            timestamp: time
        )))
        let finding = try XCTUnwrap(policy.observe(.init(
            pid: 11,
            parentPID: 5,
            executablePath: "/bin/sh",
            arguments: ["sh"],
            pipeIdentifiers: [99],
            timestamp: time.addingTimeInterval(0.1)
        )))
        XCTAssertEqual(finding.reason, "curl_pipe_shell")
        XCTAssertEqual(finding.actorPID, 11)
        XCTAssertTrue(finding.matchedCommand.contains("<redacted>"))
        XCTAssertFalse(finding.matchedCommand.contains("secret"))
    }

    func test_nonShellPipesStaySilent() {
        for consumer in ["grep", "jq", "shasum"] {
            let policy = InteractiveShellPipelinePolicy()
            let time = Date()
            _ = policy.observe(.init(
                pid: 10,
                parentPID: 5,
                executablePath: "/usr/bin/curl",
                arguments: ["curl", "https://example.test/x"],
                pipeIdentifiers: [42],
                timestamp: time
            ))
            XCTAssertNil(policy.observe(.init(
                pid: 11,
                parentPID: 5,
                executablePath: "/usr/bin/\(consumer)",
                arguments: [consumer],
                pipeIdentifiers: [42],
                timestamp: time.addingTimeInterval(0.1)
            )), consumer)
        }
    }

    func test_sameParentWithoutSharedPipeStaysSilent() {
        let policy = InteractiveShellPipelinePolicy()
        let time = Date()
        _ = policy.observe(.init(
            pid: 10, parentPID: 5, executablePath: "/usr/bin/wget",
            arguments: ["wget", "https://example.test/x"], pipeIdentifiers: [1], timestamp: time
        ))
        XCTAssertNil(policy.observe(.init(
            pid: 11, parentPID: 5, executablePath: "/bin/zsh",
            arguments: ["zsh"], pipeIdentifiers: [2], timestamp: time.addingTimeInterval(0.1)
        )))
    }
}
