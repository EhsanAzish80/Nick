import XCTest
@testable import Nick

final class CredentialAccessPolicyTests: XCTestCase {
    private let unknown = CredentialAccessPolicy.ValidatedIdentity(
        bundleID: nil, teamID: nil, signingValidated: false, isApplePlatform: false
    )

    func testUntrustedProcessReadingCredentialStoresProducesMetadataOnlyFindings() {
        let cases: [(String, CredentialAccessPolicy.Store)] = [
            ("/Users/test/Library/Application Support/Google/Chrome/Default/Cookies", .browserCookies),
            ("/Users/test/Library/Application Support/Firefox/Profiles/a/logins.json", .browserLogins),
            ("/Users/test/.ssh/id_ed25519", .sshPrivateKey),
            ("/Users/test/Library/Application Support/Electrum/wallets/default_wallet", .cryptocurrencyWallet)
        ]
        for (path, store) in cases {
            let finding = CredentialAccessPolicy.findingForOpen(path: path, responsibleIdentity: unknown)
            XCTAssertEqual(finding?.store, store)
            XCTAssertFalse(finding?.title.contains(path) == true)
        }
    }

    func testValidatedBrowserAndPasswordManagerIdentitiesRemainSilent() {
        let chrome = CredentialAccessPolicy.ValidatedIdentity(
            bundleID: "com.google.Chrome", teamID: "EQHXZ8M8AV",
            signingValidated: true, isApplePlatform: false
        )
        let onePassword = CredentialAccessPolicy.ValidatedIdentity(
            bundleID: "com.1password.1password", teamID: "2BUA8C4S2C",
            signingValidated: true, isApplePlatform: false
        )
        XCTAssertNil(CredentialAccessPolicy.findingForOpen(
            path: "/Users/test/Library/Application Support/Google/Chrome/Default/Login Data",
            responsibleIdentity: chrome
        ))
        XCTAssertNil(CredentialAccessPolicy.findingForOpen(
            path: "/Users/test/.ssh/id_rsa", responsibleIdentity: onePassword
        ))
    }

    func testSpoofedIdentifierWithoutValidatedSignerDoesNotExemptAccess() {
        let spoof = CredentialAccessPolicy.ValidatedIdentity(
            bundleID: "com.google.Chrome", teamID: "EQHXZ8M8AV",
            signingValidated: false, isApplePlatform: false
        )
        XCTAssertNotNil(CredentialAccessPolicy.findingForOpen(
            path: "/Users/test/Library/Application Support/Google/Chrome/Default/Cookies",
            responsibleIdentity: spoof
        ))
    }

    func testValidatedAppsReadingTheirOwnStoresStaySilentButCrossAppReadsAlert() {
        let fixtures: [(String, String)] = [
            ("com.openai.chat", "ChatGPT"),
            ("com.tinyspeck.slackmacgap", "Slack"),
            ("com.anthropic.claudefordesktop", "Claude")
        ]
        for (bundleID, name) in fixtures {
            let identity = CredentialAccessPolicy.ValidatedIdentity(
                bundleID: bundleID, teamID: "VALIDTEAM", signingValidated: true,
                isApplePlatform: false
            )
            let ownPaths = [
                "/Users/test/Library/Containers/\(bundleID)/Data/Library/Cookies/Cookies",
                "/Users/test/Library/HTTPStorages/\(bundleID)/Cookies",
                "/Users/test/Library/Application Support/\(bundleID)/Cookies"
            ]
            for path in ownPaths {
                XCTAssertNil(
                    CredentialAccessPolicy.findingForOpen(path: path, responsibleIdentity: identity),
                    "\(name) own-store read should stay silent: \(path)"
                )
            }
            XCTAssertNotNil(CredentialAccessPolicy.findingForOpen(
                path: "/Users/test/Library/HTTPStorages/com.example.other/Cookies",
                responsibleIdentity: identity
            ))
        }
    }

    func testUnvalidatedReaderNeverQualifiesForStoreOwnership() {
        let spoof = CredentialAccessPolicy.ValidatedIdentity(
            bundleID: "com.openai.chat", teamID: "SPOOF", signingValidated: false,
            isApplePlatform: false
        )
        XCTAssertNotNil(CredentialAccessPolicy.findingForOpen(
            path: "/Users/test/Library/HTTPStorages/com.openai.chat/Cookies",
            responsibleIdentity: spoof
        ))
    }

    func testKeychainDumpAndSecretReadCommandsAlertWithoutRecordingArguments() {
        let appleSecurityCLI = CredentialAccessPolicy.ValidatedIdentity(
            bundleID: "com.apple.security", teamID: nil,
            signingValidated: true, isApplePlatform: true
        )
        XCTAssertEqual(
            CredentialAccessPolicy.findingForExec(
                executablePath: "/usr/bin/security",
                arguments: ["security", "dump-keychain", "-d", "login.keychain-db"],
                responsibleIdentity: appleSecurityCLI
            )?.reason,
            "keychain_dump"
        )
        XCTAssertEqual(
            CredentialAccessPolicy.findingForExec(
                executablePath: "/usr/bin/security",
                arguments: ["security", "find-generic-password", "-a", "dummy", "-w"],
                responsibleIdentity: unknown
            )?.reason,
            "keychain_secret_read"
        )
        XCTAssertNil(CredentialAccessPolicy.findingForExec(
            executablePath: "/usr/bin/security",
            arguments: ["security", "find-generic-password", "-a", "dummy"],
            responsibleIdentity: unknown
        ))
    }

    func testPublicSSHMaterialIsNotClassifiedAsCredentialContent() {
        XCTAssertNil(CredentialAccessPolicy.findingForOpen(path: "/Users/test/.ssh/id_ed25519.pub", responsibleIdentity: unknown))
        XCTAssertNil(CredentialAccessPolicy.findingForOpen(path: "/Users/test/.ssh/known_hosts", responsibleIdentity: unknown))
        XCTAssertNil(CredentialAccessPolicy.findingForOpen(path: "/Users/test/.ssh/config", responsibleIdentity: unknown))
    }

    func testUnrelatedReadPathIsRejectedBeforeIdentityWork() {
        XCTAssertNil(CredentialAccessPolicy.sensitiveStore(at: "/tmp/ordinary-document.txt"))
    }

    func testChromiumFamilyCredentialStoresUseSharedStoreNames() {
        // Decode at runtime so the combined multi-browser YARA fixture does
        // not become a false match in the built NickTests product.
        let paths = [
            "L1VzZXJzL3Rlc3QvTGlicmFyeS9BcHBsaWNhdGlvbiBTdXBwb3J0L0JyYXZlU29mdHdhcmUvQnJhdmUtQnJvd3Nlci9EZWZhdWx0L0xvZ2luIERhdGE=",
            "L1VzZXJzL3Rlc3QvTGlicmFyeS9BcHBsaWNhdGlvbiBTdXBwb3J0L01pY3Jvc29mdCBFZGdlL0RlZmF1bHQvQ29va2llcw==",
            "L1VzZXJzL3Rlc3QvTGlicmFyeS9BcHBsaWNhdGlvbiBTdXBwb3J0L0FyYy9Vc2VyIERhdGEvRGVmYXVsdC9Mb2dpbiBEYXRh",
            "L1VzZXJzL3Rlc3QvTGlicmFyeS9BcHBsaWNhdGlvbiBTdXBwb3J0L2NvbS5vcGVyYXNvZnR3YXJlLk9wZXJhL0RlZmF1bHQvQ29va2llcw==",
            "L1VzZXJzL3Rlc3QvTGlicmFyeS9BcHBsaWNhdGlvbiBTdXBwb3J0L1ZpdmFsZGkvRGVmYXVsdC9Mb2dpbiBEYXRh"
        ].map {
            String(data: Data(base64Encoded: $0)!, encoding: .utf8)!
        }
        for path in paths {
            XCTAssertNotNil(CredentialAccessPolicy.findingForOpen(
                path: path,
                responsibleIdentity: unknown
            ), path)
        }
    }

    func testAdditionalCredentialStoresAreMetadataOnlyFindings() {
        let paths = [
            "/Users/test/Library/Keychains/login.keychain-db",
            "/Users/test/Library/Safari/Form Values",
            "/Users/test/.aws/credentials",
            "/Users/test/.config/gcloud/credentials.db",
            "/Users/test/.kube/config",
            "/Users/test/.docker/config.json",
            "/Users/test/Library/Application Support/Telegram Desktop/tdata/key_datas",
            "/Users/test/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite",
            "/Users/test/Library/Passes/example.pkpass",
            "/Users/test/Library/Application Support/Google/Chrome/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn/000003.log"
        ]
        for path in paths {
            XCTAssertNotNil(CredentialAccessPolicy.findingForOpen(
                path: path,
                responsibleIdentity: unknown
            ), path)
        }
    }

    func testHiddenAnswerAppleScriptProducesPasswordPromptFinding() {
        let finding = CredentialAccessPolicy.findingForExec(
            executablePath: "/usr/bin/osascript",
            arguments: ["osascript", "-e", "display dialog \"Password\" default answer \"\" with hidden answer"],
            responsibleIdentity: unknown
        )
        XCTAssertEqual(finding?.reason, "hidden_password_prompt")
        XCTAssertEqual(finding?.store, .passwordPrompt)
        XCTAssertNil(CredentialAccessPolicy.findingForExec(
            executablePath: "/usr/bin/osascript",
            arguments: ["osascript", "-e", "display dialog \"Continue?\""],
            responsibleIdentity: unknown
        ))
    }

    func testPlatformCPLaunchedFromTerminalReadingKeychainAlerts() {
        let terminal = CredentialAccessPolicy.ValidatedIdentity(
            bundleID: "com.apple.Terminal", teamID: nil,
            signingValidated: true, isApplePlatform: true
        )
        XCTAssertNil(CredentialAccessPolicy.findingForOpen(
            path: "/Users/test/Library/Keychains/login.keychain-db",
            responsibleIdentity: terminal,
            actorIdentityValidated: true,
            actorIsValidatedApplePlatform: true,
            actorIsOwnResponsibleProcess: false
        ))
    }

    func testPlainKeychainReadByAnyValidatedDistributionIdentityStaysSilent() {
        let developerID = CredentialAccessPolicy.ValidatedIdentity(
            bundleID: "com.example.tool", teamID: "TEAM123456",
            signingValidated: true, isApplePlatform: false
        )
        XCTAssertNil(CredentialAccessPolicy.findingForOpen(
            path: "/Users/test/Library/Keychains/login.keychain-db",
            responsibleIdentity: developerID,
            actorIdentityValidated: true
        ))
        XCTAssertNotNil(CredentialAccessPolicy.findingForOpen(
            path: "/Users/test/Library/Keychains/login.keychain-db",
            responsibleIdentity: unknown,
            actorIdentityValidated: false
        ))
    }

    func testKeychainTransferAndCommandCorrelationAreProtectedCriticalFindings() {
        let transfer = CredentialAccessPolicy.findingForKeychainTransfer()
        XCTAssertEqual(transfer.reason, "keychain_store_transfer")
        XCTAssertEqual(transfer.tier, "protected")
        XCTAssertEqual(transfer.severity, "critical")

        let correlated = CredentialAccessPolicy.findingForOpen(
            path: "/Users/test/Library/Keychains/login.keychain-db",
            responsibleIdentity: unknown,
            actorIdentityValidated: true,
            hasRecentKeychainCommand: true
        )
        XCTAssertEqual(correlated?.reason, "keychain_command_correlation")
        XCTAssertEqual(correlated?.tier, "protected")
        XCTAssertEqual(correlated?.severity, "critical")
    }

    func testAtomicCloneWithinKeychainsIsSilentButCopyToTmpIsCritical() {
        let source = "/Users/test/Library/Keychains/login.keychain-db"
        XCTAssertFalse(CredentialAccessPolicy.shouldReportKeychainTransfer(
            sourcePath: source,
            destinationPath: "/Users/test/Library/Keychains/login.keychain-db.sb-123",
            actorIsValidatedApplePlatform: true,
            actorParentIsLaunchd: true
        ))
        XCTAssertFalse(CredentialAccessPolicy.shouldReportKeychainTransfer(
            sourcePath: "/Library/Keychains/System.keychain",
            destinationPath: "/Library/Keychains/System.keychain-new"
        ))
        XCTAssertTrue(CredentialAccessPolicy.shouldReportKeychainTransfer(
            sourcePath: source,
            destinationPath: "/tmp/login.keychain-db"
        ))
        XCTAssertEqual(
            CredentialAccessPolicy.findingForKeychainTransfer().severity,
            "critical"
        )
    }

    func testSecuritySecretReadDoesNotArmKeychainCorrelation() throws {
        let finding = try XCTUnwrap(CredentialAccessPolicy.findingForExec(
            executablePath: "/usr/bin/security",
            arguments: ["security", "find-generic-password", "-w"],
            responsibleIdentity: unknown
        ))

        XCTAssertEqual(finding.reason, "keychain_secret_read")
        XCTAssertFalse(CredentialAccessPolicy.armsKeychainCorrelation(reason: finding.reason))
        XCTAssertTrue(CredentialAccessPolicy.armsKeychainCorrelation(reason: "hidden_password_prompt"))
    }

    func testHiddenPromptFollowUpByDifferentProcessCorrelatesWithinTenMinutes() throws {
        let start = Date(timeIntervalSince1970: 50_000)
        let arm = CredentialAccessPolicy.RecentHiddenPrompt(
            chainKey: "TEAM|app|chain",
            armedAt: start,
            processPID: 100,
            processPIDVersion: 7
        )

        XCTAssertFalse(arm.matchesFollowUp(
            chainKey: "TEAM|app|chain",
            processPID: 100,
            processPIDVersion: 7,
            at: start.addingTimeInterval(30)
        ), "The hidden-prompt process must not correlate with its own keychain open")
        XCTAssertTrue(arm.matchesFollowUp(
            chainKey: "TEAM|app|chain",
            processPID: 101,
            processPIDVersion: 1,
            at: start.addingTimeInterval(9 * 60)
        ))

        let critical = CredentialAccessPolicy.findingForOpen(
            path: "/Users/test/Library/Keychains/login.keychain-db",
            responsibleIdentity: unknown,
            actorIdentityValidated: true,
            hasRecentKeychainCommand: true
        )
        XCTAssertEqual(critical?.reason, "keychain_command_correlation")
        XCTAssertEqual(critical?.tier, "protected")
        XCTAssertEqual(critical?.severity, "critical")
    }

    func testHiddenPromptFollowUpAfterElevenMinutesDoesNotCorrelate() {
        let start = Date(timeIntervalSince1970: 60_000)
        let arm = CredentialAccessPolicy.RecentHiddenPrompt(
            chainKey: "TEAM|app|chain",
            armedAt: start,
            processPID: 100,
            processPIDVersion: 7
        )

        XCTAssertFalse(arm.matchesFollowUp(
            chainKey: "TEAM|app|chain",
            processPID: 102,
            processPIDVersion: 1,
            at: start.addingTimeInterval(11 * 60)
        ))
        XCTAssertNil(CredentialAccessPolicy.findingForOpen(
            path: "/Users/test/Library/Keychains/login.keychain-db",
            responsibleIdentity: unknown,
            actorIdentityValidated: true,
            hasRecentKeychainCommand: false
        ))
    }

    func testLaunchdOwnedPlatformDaemonIsSilentForOtherStoresButInterpreterIsNot() {
        XCTAssertNil(CredentialAccessPolicy.findingForOpen(
            path: "/Users/test/.aws/credentials",
            responsibleIdentity: nil,
            actorIdentityValidated: true,
            actorIsValidatedApplePlatform: true,
            actorIsOwnResponsibleProcess: true,
            actorParentIsLaunchd: true,
            actorIsInterpreter: false
        ))
        XCTAssertNotNil(CredentialAccessPolicy.findingForOpen(
            path: "/Users/test/.aws/credentials",
            responsibleIdentity: nil,
            actorIdentityValidated: true,
            actorIsValidatedApplePlatform: true,
            actorIsOwnResponsibleProcess: true,
            actorParentIsLaunchd: true,
            actorIsInterpreter: true
        ))
    }

    func testSimulatorLaunchServiceOwnedPlatformDaemonIsSilentForOwnCookieStore() {
        XCTAssertTrue(CredentialAccessPolicy.isValidatedAppleLaunchService(
            signingID: "com.apple.xpc.launchd_sim",
            isValidatedAppleCode: true
        ))
        XCTAssertFalse(CredentialAccessPolicy.isValidatedAppleLaunchService(
            signingID: "com.apple.xpc.launchd_sim",
            isValidatedAppleCode: false
        ), "A copied name or self-reported identifier must not create trust")

        XCTAssertNil(CredentialAccessPolicy.findingForOpen(
            path: "/Users/test/Library/HTTPStorages/com.apple.amsaccountsd/Cookies.binarycookies",
            responsibleIdentity: nil,
            actorIdentityValidated: true,
            actorIsValidatedApplePlatform: true,
            actorIsOwnResponsibleProcess: true,
            actorParentIsLaunchd: false,
            actorParentIsValidatedAppleLaunchService: true,
            actorIsInterpreter: false
        ))
    }

    func testPlainReadThenExternalWriteDetectsUserSpaceKeychainCopies() {
        let process = Nick.ProcessInstanceIdentity(
            pid: 77, startSeconds: 100, startMicroseconds: 2, pidVersion: 9
        )
        let source = "/tmp/home/Library/Keychains/login.keychain-db"
        let base = Date(timeIntervalSince1970: 1_000)

        for (offset, destination) in [
            "/tmp/copied-by-cp.db",
            "/tmp/copied-by-ditto.db",
            "/tmp/copied-by-python.db"
        ].enumerated() {
            var tracker = KeychainTransferFallbackTracker()
            tracker.recordRead(sourcePath: source, process: process, at: base)
            let transfer = tracker.consumeExternalWrite(
                destinationPath: destination,
                process: process,
                at: base.addingTimeInterval(Double(offset) + 1)
            )
            XCTAssertEqual(transfer?.sourcePath, source)
        }
    }

    func testInFolderAppleDaemonMaintenanceDoesNotBecomeFallbackTransfer() {
        var tracker = KeychainTransferFallbackTracker()
        let process = Nick.ProcessInstanceIdentity(
            pid: 88, startSeconds: 200, startMicroseconds: 3, pidVersion: 10
        )
        let base = Date(timeIntervalSince1970: 2_000)
        tracker.recordRead(
            sourcePath: "/Users/test/Library/Keychains/login.keychain-db",
            process: process,
            at: base
        )
        XCTAssertNil(tracker.consumeExternalWrite(
            destinationPath: "/Users/test/Library/Keychains/login.keychain-db-new",
            process: process,
            at: base.addingTimeInterval(1)
        ))
    }

    func testTodayCredentialWorkloadReplayStaysBelowNoiseBudget() {
        let validatedTool = CredentialAccessPolicy.ValidatedIdentity(
            bundleID: "com.example.release-tool", teamID: "VALIDTEAM",
            signingValidated: true, isApplePlatform: false
        )
        let chatGPT = CredentialAccessPolicy.ValidatedIdentity(
            bundleID: "com.openai.chat", teamID: "2DC432GLL2",
            signingValidated: true, isApplePlatform: false
        )
        var findings: [CredentialAccessPolicy.Finding] = []

        // Thousands of ordinary release-tool keychain reads and own-store
        // reads collapse to no findings under the replacement policy.
        for _ in 0..<1_700 {
            if let finding = CredentialAccessPolicy.findingForOpen(
                path: "/Users/test/Library/Keychains/login.keychain-db",
                responsibleIdentity: validatedTool,
                actorIdentityValidated: true
            ) { findings.append(finding) }
        }
        for _ in 0..<100 {
            if let finding = CredentialAccessPolicy.findingForOpen(
                path: "/Users/test/Library/HTTPStorages/com.openai.chat/Cookies",
                responsibleIdentity: chatGPT,
                actorIdentityValidated: true
            ) { findings.append(finding) }
        }
        // The representative cross-app and unvalidated reads remain visible.
        if let finding = CredentialAccessPolicy.findingForOpen(
            path: "/Users/test/Library/Application Support/Google/Chrome/Default/Cookies",
            responsibleIdentity: chatGPT,
            actorIdentityValidated: true
        ) { findings.append(finding) }
        if let finding = CredentialAccessPolicy.findingForOpen(
            path: "/Users/test/Library/Keychains/login.keychain-db",
            responsibleIdentity: unknown,
            actorIdentityValidated: false
        ) { findings.append(finding) }

        XCTAssertLessThan(findings.count, 20)
        XCTAssertLessThan(findings.filter { $0.tier == "review" }.count, 3)
    }

    func testHiddenPromptNormalizesWhitespaceAndRecognizesJXA() {
        XCTAssertNotNil(CredentialAccessPolicy.findingForExec(
            executablePath: "/usr/bin/osascript",
            arguments: ["osascript", "-e", "display\n\tdialog \"Password\" with hidden\tanswer"],
            responsibleIdentity: unknown
        ))
        XCTAssertNotNil(CredentialAccessPolicy.findingForExec(
            executablePath: "/usr/bin/osascript",
            arguments: [
                "osascript", "-l", "JavaScript", "-e",
                "Application('System Events').displayDialog('Password', { hiddenAnswer: true })"
            ],
            responsibleIdentity: unknown
        ))
    }
}
