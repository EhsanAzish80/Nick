import XCTest
@testable import Nick

final class InteractiveShellPipelinePolicyTests: XCTestCase {
    func test_retriesOnlyPlausiblePipelineParticipants() {
        let policy = InteractiveShellPipelinePolicy()
        let now = Date()
        XCTAssertFalse(policy.shouldRetry(.init(
            pid: 1,
            parentPID: 0,
            executablePath: "/usr/bin/true",
            arguments: ["true"],
            pipeIdentifiers: [],
            timestamp: now
        )))
        XCTAssertTrue(policy.shouldRetry(.init(
            pid: 2,
            parentPID: 1,
            executablePath: "/private/tmp/reader",
            arguments: ["reader", "https://example.test/x"],
            pipeIdentifiers: [],
            timestamp: now
        )))
        XCTAssertTrue(policy.shouldRetry(.init(
            pid: 3,
            parentPID: 1,
            executablePath: "/bin/zsh",
            arguments: ["zsh"],
            pipeIdentifiers: [42],
            standardInputPipeIdentifier: 42,
            timestamp: now
        )))
    }

    func test_typedCurlPipeToShellAcrossSiblingProcessesAlerts() throws {
        let policy = InteractiveShellPipelinePolicy()
        let time = Date(timeIntervalSince1970: 100)
        XCTAssertNil(policy.observe(.init(
            pid: 10,
            parentPID: 5,
            executablePath: "/usr/bin/curl",
            arguments: ["curl", "https://user:secret@example.test/x?token=secret"],
            pipeIdentifiers: [99],
            hasNetworkSocket: true,
            timestamp: time
        )))
        let finding = try XCTUnwrap(policy.observe(.init(
            pid: 11,
            parentPID: 5,
            executablePath: "/bin/sh",
            arguments: ["sh"],
            pipeIdentifiers: [99],
            standardInputPipeIdentifier: 99,
            timestamp: time.addingTimeInterval(0.1)
        )))
        XCTAssertEqual(finding.reason, "download_pipe_interpreter")
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
                hasNetworkSocket: true,
                timestamp: time
            ))
            XCTAssertNil(policy.observe(.init(
                pid: 11,
                parentPID: 5,
                executablePath: "/usr/bin/\(consumer)",
                arguments: [consumer],
                pipeIdentifiers: [42],
                standardInputPipeIdentifier: 42,
                timestamp: time.addingTimeInterval(0.1)
            )), consumer)
        }
    }

    func test_sameParentWithoutSharedPipeStaysSilent() {
        let policy = InteractiveShellPipelinePolicy()
        let time = Date()
        _ = policy.observe(.init(
            pid: 10, parentPID: 5, executablePath: "/usr/bin/wget",
            arguments: ["wget", "https://example.test/x"], pipeIdentifiers: [1],
            hasNetworkSocket: true, timestamp: time
        ))
        XCTAssertNil(policy.observe(.init(
            pid: 11, parentPID: 5, executablePath: "/bin/zsh",
            arguments: ["zsh"], pipeIdentifiers: [2], standardInputPipeIdentifier: 2,
            timestamp: time.addingTimeInterval(0.1)
        )))
    }

    func test_renamedNetworkReaderStillCorrelatesWithInterpreter() throws {
        let policy = InteractiveShellPipelinePolicy()
        let time = Date()
        XCTAssertNil(policy.observe(.init(
            pid: 20, parentPID: 5, executablePath: "/private/tmp/fetch-helper",
            arguments: ["fetch-helper", "https://example.test/payload"],
            pipeIdentifiers: [77], hasNetworkSocket: true, timestamp: time
        )))
        let finding = try XCTUnwrap(policy.observe(.init(
            pid: 21, parentPID: 5, executablePath: "/bin/zsh",
            arguments: ["zsh"], pipeIdentifiers: [77], standardInputPipeIdentifier: 77,
            timestamp: time.addingTimeInterval(0.02)
        )))
        XCTAssertEqual(finding.reason, "download_pipe_interpreter")
    }

    func test_networkAndURLAreBothRequired() {
        let policy = InteractiveShellPipelinePolicy()
        let time = Date()
        _ = policy.observe(.init(
            pid: 30, parentPID: 5, executablePath: "/tmp/fetch-helper",
            arguments: ["fetch-helper", "https://example.test/payload"],
            pipeIdentifiers: [88], hasNetworkSocket: false, timestamp: time
        ))
        XCTAssertNil(policy.observe(.init(
            pid: 31, parentPID: 5, executablePath: "/bin/sh",
            arguments: ["sh"], pipeIdentifiers: [88], standardInputPipeIdentifier: 88,
            timestamp: time.addingTimeInterval(0.01)
        )))
    }

    func test_forkEvidenceClosesShortLivedDescriptorRace() throws {
        let policy = InteractiveShellPipelinePolicy()
        let time = Date()
        policy.recordFork(
            childPID: 40, parentPID: 5, pipeIdentifiers: [101],
            standardInputPipeIdentifier: nil, timestamp: time
        )
        policy.recordFork(
            childPID: 41, parentPID: 5, pipeIdentifiers: [101],
            standardInputPipeIdentifier: 101, timestamp: time
        )
        XCTAssertNil(policy.observe(.init(
            pid: 40, parentPID: 5, executablePath: "/tmp/renamed-reader",
            arguments: ["renamed-reader", "https://example.test/x"],
            pipeIdentifiers: [], hasNetworkSocket: true, timestamp: time.addingTimeInterval(0.01)
        )))
        let finding = try XCTUnwrap(policy.observe(.init(
            pid: 41, parentPID: 5, executablePath: "/bin/bash",
            arguments: ["bash"], pipeIdentifiers: [],
            timestamp: time.addingTimeInterval(0.02)
        )))
        XCTAssertEqual(finding.actorPID, 41)
    }

    func test_codeIdentityAdjustsConfidenceButNotEligibility() throws {
        func finding(validated: Bool) throws -> InteractiveShellPipelinePolicy.Finding {
            let policy = InteractiveShellPipelinePolicy()
            let time = Date()
            _ = policy.observe(.init(
                pid: 50, parentPID: 5, executablePath: "/tmp/reader",
                arguments: ["reader", "https://example.test/x"], pipeIdentifiers: [202],
                hasNetworkSocket: true, codeIdentityValidated: validated, timestamp: time
            ))
            return try XCTUnwrap(policy.observe(.init(
                pid: 51, parentPID: 5, executablePath: "/bin/sh", arguments: ["sh"],
                pipeIdentifiers: [202], standardInputPipeIdentifier: 202,
                codeIdentityValidated: validated, timestamp: time.addingTimeInterval(0.01)
            )))
        }

        XCTAssertEqual(try finding(validated: false).confidence, "medium")
        XCTAssertEqual(try finding(validated: true).confidence, "high")
    }
}
