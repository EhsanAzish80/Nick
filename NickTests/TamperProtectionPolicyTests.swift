// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import XCTest
@testable import Nick

final class TamperProtectionPolicyTests: XCTestCase {
    private let valid = ExecutionTrustPolicy.csValid

    func test_nickAndResignedSparkleInstallerAreTrustedByExactIdentity() {
        XCTAssertTrue(TamperProtectionPolicy.isTrustedMaintenanceActor(identity(
            team: TamperProtectionPolicy.nickTeamID,
            signing: "com.ehsanazish.nick"
        ), nickIdentityValidated: true))
        XCTAssertTrue(TamperProtectionPolicy.isTrustedMaintenanceActor(identity(
            team: TamperProtectionPolicy.nickTeamID,
            signing: "org.sparkle-project.InstallerLauncher"
        ), nickIdentityValidated: true))
    }

    func test_appleInstallerRequiresPlatformIdentity() {
        XCTAssertTrue(TamperProtectionPolicy.isTrustedMaintenanceActor(identity(
            signing: "com.apple.installd",
            platform: true
        ), nickIdentityValidated: false))
        XCTAssertTrue(TamperProtectionPolicy.isTrustedMaintenanceActor(identity(
            signing: "com.apple.shove",
            platform: true
        ), nickIdentityValidated: false))
        XCTAssertFalse(TamperProtectionPolicy.isTrustedMaintenanceActor(identity(
            signing: "com.apple.installd",
            platform: false
        ), nickIdentityValidated: false))
        XCTAssertFalse(TamperProtectionPolicy.isTrustedMaintenanceActor(identity(
            signing: "com.apple.shove",
            platform: false
        ), nickIdentityValidated: false))
    }

    func test_fakeTeamInvalidAndUnknownIdentityAreRejected() {
        XCTAssertFalse(TamperProtectionPolicy.isTrustedMaintenanceActor(identity(
            team: TamperProtectionPolicy.nickTeamID,
            signing: "com.ehsanazish.nick",
            flags: ExecutionTrustPolicy.csValid | ExecutionTrustPolicy.csAdhoc
        ), nickIdentityValidated: false))
        XCTAssertFalse(TamperProtectionPolicy.isTrustedMaintenanceActor(identity(
            team: TamperProtectionPolicy.nickTeamID,
            signing: "com.example.not-nick"
        ), nickIdentityValidated: true))
    }

    func test_selfSignedActorClaimingNickTeamAndIdentifierIsRejectedWithoutSecCodeValidation() {
        let selfAsserted = identity(
            team: TamperProtectionPolicy.nickTeamID,
            signing: "com.ehsanazish.nick"
        )
        XCTAssertFalse(TamperProtectionPolicy.isTrustedMaintenanceActor(
            selfAsserted,
            nickIdentityValidated: false
        ))
    }

    func test_finderUninstallOnlyAllowsNickMoveIntoTrash() {
        let finder = identity(signing: "com.apple.finder", platform: true)
        let consoleUser = TamperConsoleUser(uid: 501, homeDirectory: "/Users/test")
        XCTAssertTrue(TamperProtectionPolicy.isDocumentedFinderUninstall(
            sourcePath: "/Applications/Nick.app",
            destinationPath: "/Users/test/.Trash/Nick.app",
            identity: finder,
            consoleUser: consoleUser
        ))
        XCTAssertTrue(TamperProtectionPolicy.isDocumentedFinderUninstall(
            sourcePath: "/Applications/Nick.app",
            destinationPath: "/Volumes/External/.Trashes/501/Nick 2.app",
            identity: finder,
            consoleUser: consoleUser
        ))
        XCTAssertFalse(TamperProtectionPolicy.isDocumentedFinderUninstall(
            sourcePath: "/private/tmp/Fake.app",
            destinationPath: "/Applications/Nick.app",
            identity: finder,
            consoleUser: consoleUser
        ))
        XCTAssertFalse(TamperProtectionPolicy.isDocumentedFinderUninstall(
            sourcePath: "/Applications/Nick.app",
            destinationPath: "/private/tmp/Nick.app",
            identity: finder,
            consoleUser: consoleUser
        ))
        XCTAssertFalse(TamperProtectionPolicy.isDocumentedFinderUninstall(
            sourcePath: "/Applications/Nick.app",
            destinationPath: "/tmp/x/.Trash/Nick.app",
            identity: finder,
            consoleUser: consoleUser
        ))
        XCTAssertFalse(TamperProtectionPolicy.isDocumentedFinderUninstall(
            sourcePath: "/Applications/Nick.app",
            destinationPath: "/Users/other/.Trash/Nick.app",
            identity: finder,
            consoleUser: consoleUser
        ))
    }

    private func identity(
        team: String? = nil,
        signing: String,
        platform: Bool = false,
        flags: UInt32? = nil
    ) -> TamperActorIdentity {
        TamperActorIdentity(
            teamID: team,
            signingID: signing,
            codesigningFlags: flags ?? valid,
            isPlatformBinary: platform
        )
    }
}
