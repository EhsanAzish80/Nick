import XCTest
@testable import Nick

final class CredentialAccessPolicyTests: XCTestCase {
    func testChromeAUTHOwnershipAndValidatedContainingHelper() {
        let chrome = CredentialAccessPolicy.ValidatedIdentity(bundleID: "com.google.Chrome", teamID: "EQHXZ8M8AV", signingValidated: true, isApplePlatform: false)
        let helper = CredentialAccessPolicy.ValidatedIdentity(bundleID: "com.google.Chrome.helper", teamID: "EQHXZ8M8AV", signingValidated: true, isApplePlatform: false)
        let path = "/Users/test/Library/Application Support/Google/Chrome/Default/Login Data"
        XCTAssertTrue(CredentialAccessPolicy.ownsStore(path: path, identity: chrome))
        XCTAssertFalse(CredentialAccessPolicy.ownsStore(path: path, identity: helper), "helpers require validated containing-app ownership")
        XCTAssertNil(CredentialAccessPolicy.findingForOpen(path: path, responsibleIdentity: chrome, actorIdentity: helper))
        XCTAssertFalse(CredentialAccessPolicy.ownsStore(path: "/Users/test/Library/Application Support/Claude/Cookies", identity: chrome))
        XCTAssertFalse(CredentialAccessPolicy.ownsStore(path: path, identity: .init(bundleID: "com.google.Chrome", teamID: "SPOOF", signingValidated: true, isApplePlatform: false)))
        XCTAssertFalse(CredentialAccessPolicy.ownsStore(path: path, identity: .init(bundleID: "com.google.Chrome", teamID: "EQHXZ8M8AV", signingValidated: false, isApplePlatform: false)))
    }
    func testNickBrowserScanRequiresExactValidatedIdentityAndReadOnlyAccess() {
        func identity(_ id: String = "com.ehsanazish.nick", _ team: String = "UXGW5V3BY6", _ valid: Bool = true) -> CredentialAccessPolicy.ValidatedIdentity {
            .init(bundleID: id, teamID: team, signingValidated: valid, isApplePlatform: false)
        }
        XCTAssertTrue(CredentialAccessPolicy.isNickBrowserScan(identity: identity(), store: .browserCookies, readOnly: true))
        XCTAssertTrue(CredentialAccessPolicy.isNickBrowserScan(identity: identity(), store: .browserLogins, readOnly: true))
        XCTAssertFalse(CredentialAccessPolicy.isNickBrowserScan(identity: identity(), store: .browserCookies, readOnly: false))
        XCTAssertFalse(CredentialAccessPolicy.isNickBrowserScan(identity: identity(), store: .sshPrivateKey, readOnly: true))
        XCTAssertFalse(CredentialAccessPolicy.isNickBrowserScan(identity: identity("com.ehsanazish.nick", "OTHER"), store: .browserCookies, readOnly: true))
        XCTAssertFalse(CredentialAccessPolicy.isNickBrowserScan(identity: identity("com.ehsanazish.nick", "UXGW5V3BY6", false), store: .browserCookies, readOnly: true))
        XCTAssertFalse(CredentialAccessPolicy.isNickBrowserScan(identity: identity("other"), store: .browserCookies, readOnly: true))
    }
    func testKeychainCommandEvidenceNeverRetainsSecretArguments() {
        let evidence = CredentialAccessPolicy.keychainCommandEvidence(arguments:
            ["security", "dump-keychain", "-dr", "/tmp/private.keychain-db", "secret-value"])
        XCTAssertEqual(evidence["keychainDecryptRequested"], "true")
        XCTAssertEqual(evidence["keychainRawRequested"], "true")
        XCTAssertEqual(evidence["keychainInteractiveRequested"], "false")
        XCTAssertFalse(evidence.values.contains { $0.contains("secret-value") || $0.contains("/tmp") })
    }
    func testGitSSHTransportRequiresOwnedKeyAndGitRemoteCommand() {
        let key = "/Users/test/.ssh/id_ed25519"
        func finding(_ arguments: [String], uid: UInt32 = 501) -> CredentialAccessPolicy.Finding? {
            CredentialAccessPolicy.gitSSHTransportFinding(
                arguments: arguments, keyPath: key, actorUID: 501, fileUID: uid,
                actorIsAppleSSH: true, parentIsAppleGit: true
            )
        }
        let normal = ["ssh", "-o", "SendEnv=GIT_PROTOCOL", "git@example.org", "git-upload-pack 'repo'"]
        XCTAssertEqual(finding(normal)?.tier, "observed")
        XCTAssertNil(finding(normal, uid: 502))
        XCTAssertNil(finding(["ssh", "-i", "/tmp/other", "git@example.org", "git-upload-pack 'repo'"]))
        XCTAssertNil(finding(["ssh", "git@example.org", "cat /tmp/key"]))
    }

    func testGitSSHSigningRequiresAppleIdentitiesAndExactOwnedKey() {
        let key = "/Users/test/.ssh/id_ed25519"
        let sign = ["ssh-keygen", "-Y", "sign", "-n", "git", "-f", key, "/tmp/message"]
        func finding(_ args: [String], fileUID: UInt32 = 501, appleGit: Bool = true)
            -> CredentialAccessPolicy.Finding? {
            CredentialAccessPolicy.gitSSHSigningFinding(
                arguments: args, keyPath: key, actorUID: 501, fileUID: fileUID,
                actorIsAppleKeygen: true, parentIsAppleGit: appleGit
            )
        }
        XCTAssertEqual(finding(sign)?.tier, "observed")
        XCTAssertNil(finding(sign, fileUID: 502))
        XCTAssertNil(finding(sign, appleGit: false))
        XCTAssertEqual(finding(["ssh-keygen", "-y", "-f", key])?.tier, "observed")
        XCTAssertNil(finding(["ssh-keygen", "-y", "-f", key], appleGit: false))
        XCTAssertNil(finding(["ssh-keygen", "-y", "-f", key], fileUID: 502))
    }
    func testSSHAgentAuthenticationRequiresExactOwnedKeyAndAppleIdentity() {
        let key = "/Users/test/.ssh/id_ed25519_signing"
        func finding(_ args: [String], owner: UInt32 = 501, apple: Bool = true) -> CredentialAccessPolicy.Finding? {
            CredentialAccessPolicy.sshAddFinding(arguments: args, keyPath: key, actorUID: 501,
                fileUID: owner, actorIsAppleSSHAdd: apple)
        }
        let args = ["ssh-add", "--apple-use-keychain", key]
        XCTAssertEqual(finding(args)?.tier, "observed")
        XCTAssertNil(finding(args, owner: 502))
        XCTAssertNil(finding(args, apple: false))
        XCTAssertNil(finding(["ssh-add", "-L", key]))
        XCTAssertNil(finding(["ssh-add", key, "/tmp/other"]))
    }

    func testProductProfileAliasRequiresValidatedExactDistributionIdentity() {
        let path = "/Users/test/Library/Application Support/Claude/Cookies"
        for (team, validated, expected) in [("Q6L2SF6YDW", true, true), ("SPOOF", true, false), ("Q6L2SF6YDW", false, false)] {
            let identity = CredentialAccessPolicy.ValidatedIdentity(bundleID: "com.anthropic.claudefordesktop", teamID: team,
                signingValidated: validated, isApplePlatform: false)
            XCTAssertEqual(CredentialAccessPolicy.ownsStore(path: path, identity: identity), expected)
            XCTAssertFalse(CredentialAccessPolicy.ownsStore(path: "/Users/test/Library/Application Support/Chrome/Cookies", identity: identity))
        }
    }

    private let unknown = CredentialAccessPolicy.ValidatedIdentity(
        bundleID: nil, teamID: nil, signingValidated: false, isApplePlatform: false
    )

    func testCredentialClassificationRequiresARegularFileOpen() {
        XCTAssertFalse(CredentialAccessPolicy.shouldEvaluateOpen(
            isRead: true, isRegularFile: false, isBlocked: false,
            isApprovedStorageMetadataRead: false
        ), "enumerating a credential directory is not credential access")
        XCTAssertTrue(CredentialAccessPolicy.shouldEvaluateOpen(
            isRead: true, isRegularFile: true, isBlocked: false,
            isApprovedStorageMetadataRead: false
        ), "opening a regular credential file remains eligible")
    }

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
                    CredentialAccessPolicy.findingForOpen(
                        path: path, responsibleIdentity: identity, actorIdentity: identity
                    ),
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

    func testResponsibleAppStoreRequiresValidatedSameTeamHelper() {
        let app = CredentialAccessPolicy.ValidatedIdentity(
            bundleID: "com.openai.chat", teamID: "APPTEAM",
            signingValidated: true, isApplePlatform: false
        )
        let path = "/Users/test/Library/HTTPStorages/com.openai.chat/Cookies"
        for (team, validated, expectsFinding) in [
            ("APPTEAM", true, false), ("APPTEAM", false, true), ("OTHERTEAM", true, true)
        ] {
            let helper = CredentialAccessPolicy.ValidatedIdentity(
                bundleID: "com.openai.codex.service", teamID: team,
                signingValidated: validated, isApplePlatform: false
            )
            XCTAssertEqual(CredentialAccessPolicy.findingForOpen(
                path: path, responsibleIdentity: app, actorIdentity: helper
            ) != nil, expectsFinding)
        }
    }

    func testValidatedHelperOwnsItsStoreWhenResponsibleAppDiffers() {
        let responsibleApp = CredentialAccessPolicy.ValidatedIdentity(
            bundleID: "com.openai.chat", teamID: "VALIDTEAM",
            signingValidated: true, isApplePlatform: false
        )
        let helper = CredentialAccessPolicy.ValidatedIdentity(
            bundleID: "com.openai.codex.service", teamID: "VALIDTEAM",
            signingValidated: true, isApplePlatform: false
        )
        let path = "/Users/test/Library/HTTPStorages/com.openai.codex.service/Cookies"
        XCTAssertNil(CredentialAccessPolicy.findingForOpen(
            path: path,
            responsibleIdentity: responsibleApp,
            actorIdentity: helper,
            actorIdentityValidated: true
        ))

        let unvalidatedHelper = CredentialAccessPolicy.ValidatedIdentity(
            bundleID: "com.openai.codex.service", teamID: "SPOOF",
            signingValidated: false, isApplePlatform: false
        )
        XCTAssertNotNil(CredentialAccessPolicy.findingForOpen(
            path: path,
            responsibleIdentity: responsibleApp,
            actorIdentity: unvalidatedHelper,
            actorIdentityValidated: false
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

    func testBrowserSafeStorageSecretReadsStayLoudWhileRoutineTokenReadsDigest() throws {
        let terminal = CredentialAccessPolicy.ValidatedIdentity(
            bundleID: "com.apple.Terminal", teamID: "APPLE",
            signingValidated: true, isApplePlatform: true
        )
        let safeStorage = try XCTUnwrap(CredentialAccessPolicy.findingForExec(
            executablePath: "/usr/bin/security",
            arguments: ["security", "find-generic-password", "-wa", "Chrome Safe Storage"],
            responsibleIdentity: terminal
        ))
        let loud = CredentialAccessPolicy.deliveryProfile(
            for: safeStorage,
            actorIdentityValidated: true,
            responsibleChainValidated: true
        )
        XCTAssertEqual(safeStorage.severity, "high")
        XCTAssertEqual(loud, .init(tier: "review", severity: "high", deliveryLevel: "interrupt"))

        let token = try XCTUnwrap(CredentialAccessPolicy.findingForExec(
            executablePath: "/usr/bin/security",
            arguments: ["security", "find-generic-password", "-s", "gh:github.com", "-w"],
            responsibleIdentity: terminal
        ))
        let digest = CredentialAccessPolicy.deliveryProfile(
            for: token,
            actorIdentityValidated: true,
            responsibleChainValidated: true
        )
        XCTAssertEqual(token.severity, "medium")
        XCTAssertEqual(digest, .init(tier: "review", severity: "info", deliveryLevel: "inform"))
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

    func testContentVerifiedCloseDetectsCpDittoAndPythonKeychainCopies() {
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
            let transfer = tracker.pendingReadForExternalClose(
                destinationPath: destination,
                process: process,
                at: base.addingTimeInterval(Double(offset) + 1)
            )
            XCTAssertEqual(transfer?.sourcePath, source)
            XCTAssertTrue(KeychainTransferContentPolicy.isVerifiedTransfer(
                sourcePrefix: Data("kych source".utf8),
                sourceSize: 11,
                destinationPrefix: Data("kych copy".utf8),
                destinationSize: 9
            ), destination)
        }
    }

    func testContentVerifiedCloseRejectsUnrelatedLogAfterKeychainRead() {
        XCTAssertFalse(KeychainTransferContentPolicy.isVerifiedTransfer(
            sourcePrefix: Data("kych source".utf8),
            sourceSize: 11,
            destinationPrefix: Data("ordinary release log".utf8),
            destinationSize: 20
        ))
    }

    func testSQLiteKeychainCopyRequiresSameSizeAndMatchingFirst64KBHash() {
        let prefix = Data("SQLite format 3\0".utf8) + Data(repeating: 0x41, count: 256)
        XCTAssertTrue(KeychainTransferContentPolicy.isVerifiedTransfer(
            sourcePrefix: prefix, sourceSize: 1_024,
            destinationPrefix: prefix, destinationSize: 1_024
        ))
        XCTAssertFalse(KeychainTransferContentPolicy.isVerifiedTransfer(
            sourcePrefix: prefix, sourceSize: 1_024,
            destinationPrefix: prefix, destinationSize: 2_048
        ))
        XCTAssertFalse(KeychainTransferContentPolicy.isVerifiedTransfer(
            sourcePrefix: prefix, sourceSize: 1_024,
            destinationPrefix: Data("ordinary release log".utf8), destinationSize: 1_024
        ))
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
        XCTAssertNil(tracker.pendingReadForExternalClose(
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
                actorIdentity: chatGPT,
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
