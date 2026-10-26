import XCTest
@testable import Nick

final class InteractiveShellPipelinePolicyTests: XCTestCase {
    func testForkHandlerDoesNotInspectProcessDescriptorsOnESCallbackQueue() throws {
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let source = try String(
            contentsOf: root.appendingPathComponent("NickExtension/EventHandler.swift"),
            encoding: .utf8
        )
        let forkStart = try XCTUnwrap(source.range(of: "case ES_EVENT_TYPE_NOTIFY_FORK:"))
        let exitStart = try XCTUnwrap(
            source.range(of: "case ES_EVENT_TYPE_NOTIFY_EXIT:", range: forkStart.upperBound..<source.endIndex)
        )
        let forkHandler = source[forkStart.lowerBound..<exitStart.lowerBound]
            .split(separator: "\n")
            .filter { !$0.trimmingCharacters(in: .whitespaces).hasPrefix("//") }
            .joined(separator: "\n")

        XCTAssertFalse(forkHandler.contains("ProcessPipeResolver"))
        XCTAssertFalse(forkHandler.contains("proc_pidinfo"))
        XCTAssertFalse(forkHandler.contains("proc_pidfdinfo"))
    }

    func test_retriesOnlyPlausiblePipelineParticipants() {
        let policy = InteractiveShellPipelinePolicy()
        let now = Date()
        XCTAssertFalse(policy.shouldRetry(.init(
            pid: 1,
            parentPID: 0,
            executablePath: "/usr/bin/true",
            arguments: ["true"],
            timestamp: now
        )))
        XCTAssertTrue(policy.shouldRetry(.init(
            pid: 2,
            parentPID: 1,
            executablePath: "/private/tmp/reader",
            arguments: ["reader", "https://example.test/x"],
            timestamp: now
        )))
        XCTAssertTrue(policy.shouldRetry(.init(
            pid: 3,
            parentPID: 1,
            executablePath: "/bin/zsh",
            arguments: ["zsh"],
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
            standardOutputPipeIdentifier: 99,
            hasNetworkSocket: true,
            timestamp: time
        )))
        let finding = try XCTUnwrap(policy.observe(.init(
            pid: 11,
            parentPID: 5,
            executablePath: "/bin/sh",
            arguments: ["sh"],
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
                standardOutputPipeIdentifier: 42,
                hasNetworkSocket: true,
                timestamp: time
            ))
            XCTAssertNil(policy.observe(.init(
                pid: 11,
                parentPID: 5,
                executablePath: "/usr/bin/\(consumer)",
                arguments: [consumer],
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
            arguments: ["wget", "https://example.test/x"], standardOutputPipeIdentifier: 1,
            hasNetworkSocket: true, timestamp: time
        ))
        XCTAssertNil(policy.observe(.init(
            pid: 11, parentPID: 5, executablePath: "/bin/zsh",
            arguments: ["zsh"], standardInputPipeIdentifier: 2,
            timestamp: time.addingTimeInterval(0.1)
        )))
    }

    func test_renamedNetworkReaderStillCorrelatesWithInterpreter() throws {
        let policy = InteractiveShellPipelinePolicy()
        let time = Date()
        XCTAssertNil(policy.observe(.init(
            pid: 20, parentPID: 5, executablePath: "/private/tmp/fetch-helper",
            arguments: ["fetch-helper", "https://example.test/payload"],
            standardOutputPipeIdentifier: 77, hasNetworkSocket: true, timestamp: time
        )))
        let finding = try XCTUnwrap(policy.observe(.init(
            pid: 21, parentPID: 5, executablePath: "/bin/zsh",
            arguments: ["zsh"], standardInputPipeIdentifier: 77,
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
            standardOutputPipeIdentifier: 88, hasNetworkSocket: false, timestamp: time
        ))
        XCTAssertNil(policy.observe(.init(
            pid: 31, parentPID: 5, executablePath: "/bin/sh",
            arguments: ["sh"], standardInputPipeIdentifier: 88,
            timestamp: time.addingTimeInterval(0.01)
        )))
    }

    func test_forkEvidenceClosesShortLivedDescriptorRace() throws {
        let policy = InteractiveShellPipelinePolicy()
        let time = Date()
        policy.recordFork(
            childPID: 40, parentPID: 5,
            standardInputPipeIdentifier: nil, standardOutputPipeIdentifier: 101, timestamp: time
        )
        policy.recordFork(
            childPID: 41, parentPID: 5,
            standardInputPipeIdentifier: 101, standardOutputPipeIdentifier: nil, timestamp: time
        )
        XCTAssertNil(policy.observe(.init(
            pid: 40, parentPID: 5, executablePath: "/tmp/renamed-reader",
            arguments: ["renamed-reader", "https://example.test/x"],
            hasNetworkSocket: true, timestamp: time.addingTimeInterval(0.01)
        )))
        let finding = try XCTUnwrap(policy.observe(.init(
            pid: 41, parentPID: 5, executablePath: "/bin/bash",
            arguments: ["bash"],
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
                arguments: ["reader", "https://example.test/x"], standardOutputPipeIdentifier: 202,
                hasNetworkSocket: true, codeIdentityValidated: validated, timestamp: time
            ))
            return try XCTUnwrap(policy.observe(.init(
                pid: 51, parentPID: 5, executablePath: "/bin/sh", arguments: ["sh"],
                standardInputPipeIdentifier: 202,
                codeIdentityValidated: validated, timestamp: time.addingTimeInterval(0.01)
            )))
        }

        XCTAssertEqual(try finding(validated: false).confidence, "medium")
        XCTAssertEqual(try finding(validated: true).confidence, "high")
    }

    func test_sharedInheritedPipeWithoutDownloaderStdoutToShellStdinStaysSilent() {
        let policy = InteractiveShellPipelinePolicy()
        let time = Date()
        policy.recordFork(
            childPID: 60, parentPID: 5,
            standardInputPipeIdentifier: 700, standardOutputPipeIdentifier: 701,
            timestamp: time
        )
        policy.recordFork(
            childPID: 61, parentPID: 5,
            standardInputPipeIdentifier: 702, standardOutputPipeIdentifier: 700,
            timestamp: time
        )
        _ = policy.observe(.init(
            pid: 60, parentPID: 5, executablePath: "/tmp/reader",
            arguments: ["reader", "https://example.test/x"],
            hasNetworkSocket: true, timestamp: time.addingTimeInterval(0.01)
        ))
        XCTAssertNil(policy.observe(.init(
            pid: 61, parentPID: 5, executablePath: "/bin/zsh", arguments: ["zsh"],
            timestamp: time.addingTimeInterval(0.02)
        )))
    }

    func test_validatedInterpreterIdentitySurvivesRenamedExecutable() throws {
        let policy = InteractiveShellPipelinePolicy()
        let time = Date()
        _ = policy.observe(.init(
            pid: 70, parentPID: 5, executablePath: "/tmp/reader",
            arguments: ["reader", "https://example.test/x"],
            standardOutputPipeIdentifier: 900, hasNetworkSocket: true, timestamp: time
        ))
        let finding = try XCTUnwrap(policy.observe(.init(
            pid: 71, parentPID: 5, executablePath: "/tmp/copied-interpreter",
            arguments: ["copied-interpreter"], standardInputPipeIdentifier: 900,
            codeIdentityValidated: true, signingIdentifier: "com.apple.zsh",
            timestamp: time.addingTimeInterval(0.01)
        )))
        XCTAssertEqual(finding.actorPID, 71)
    }

    func test_interpreterMustExecuteStandardInputAsCode() {
        func finding(interpreter: String, arguments: [String]) -> InteractiveShellPipelinePolicy.Finding? {
            let policy = InteractiveShellPipelinePolicy()
            let time = Date()
            _ = policy.observe(.init(
                pid: 80, parentPID: 5, executablePath: "/tmp/network-reader",
                arguments: ["reader", "https://example.test/x"],
                standardOutputPipeIdentifier: 1_001, hasNetworkSocket: true, timestamp: time
            ))
            return policy.observe(.init(
                pid: 81, parentPID: 5, executablePath: interpreter,
                arguments: arguments, standardInputPipeIdentifier: 1_001,
                timestamp: time.addingTimeInterval(0.01)
            ))
        }

        XCTAssertNil(finding(
            interpreter: "/usr/bin/python3",
            arguments: ["python3", "-c", "import json, sys; json.load(sys.stdin)"]
        ))
        XCTAssertNotNil(finding(interpreter: "/usr/bin/python3", arguments: ["python3"]))
        XCTAssertNotNil(finding(interpreter: "/bin/sh", arguments: ["sh"]))
        XCTAssertNil(finding(interpreter: "/bin/sh", arguments: ["sh", "-c", "cat"]))
        XCTAssertNotNil(finding(interpreter: "/bin/bash", arguments: ["bash", "-e"]))
        XCTAssertNotNil(finding(interpreter: "/bin/sh", arguments: ["sh", "-ex"]))
        XCTAssertNil(finding(interpreter: "/bin/sh", arguments: ["sh", "-ec", "cat"]))
        XCTAssertNotNil(finding(
            interpreter: "/usr/bin/python3",
            arguments: ["python3", "-W", "ignore"]
        ))
    }
}
