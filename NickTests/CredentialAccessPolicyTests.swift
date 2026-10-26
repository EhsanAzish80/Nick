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
        XCTAssertEqual(
            CredentialAccessPolicy.findingForExec(
                executablePath: "/usr/bin/security",
                arguments: ["security", "dump-keychain", "-d", "login.keychain-db"],
                responsibleIdentity: unknown
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
}
