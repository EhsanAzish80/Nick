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
        XCTAssertNotNil(CredentialAccessPolicy.findingForOpen(
            path: "/Users/test/Library/Keychains/login.keychain-db",
            responsibleIdentity: terminal,
            actorIsValidatedApplePlatform: true,
            actorIsOwnResponsibleProcess: false
        ))
    }

    func testSelfResponsibleValidatedPlatformDaemonReadingKeychainStaysSilent() {
        XCTAssertNil(CredentialAccessPolicy.findingForOpen(
            path: "/Users/test/Library/Keychains/login.keychain-db",
            responsibleIdentity: nil,
            actorIsValidatedApplePlatform: true,
            actorIsOwnResponsibleProcess: true
        ))
        XCTAssertNotNil(CredentialAccessPolicy.findingForOpen(
            path: "/Users/test/.aws/credentials", responsibleIdentity: nil,
            actorIsValidatedApplePlatform: true,
            actorIsOwnResponsibleProcess: true
        ))
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
