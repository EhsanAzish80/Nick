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
        )))
        XCTAssertTrue(TamperProtectionPolicy.isTrustedMaintenanceActor(identity(
            team: TamperProtectionPolicy.nickTeamID,
            signing: "org.sparkle-project.InstallerLauncher"
        )))
    }

    func test_appleInstallerRequiresPlatformIdentity() {
        XCTAssertTrue(TamperProtectionPolicy.isTrustedMaintenanceActor(identity(
            signing: "com.apple.installd",
            platform: true
        )))
        XCTAssertFalse(TamperProtectionPolicy.isTrustedMaintenanceActor(identity(
            signing: "com.apple.installd",
            platform: false
        )))
    }

    func test_fakeTeamInvalidAndUnknownIdentityAreRejected() {
        XCTAssertFalse(TamperProtectionPolicy.isTrustedMaintenanceActor(identity(
            team: TamperProtectionPolicy.nickTeamID,
            signing: "com.ehsanazish.nick",
            flags: ExecutionTrustPolicy.csValid | ExecutionTrustPolicy.csAdhoc
        )))
        XCTAssertFalse(TamperProtectionPolicy.isTrustedMaintenanceActor(identity(
            team: TamperProtectionPolicy.nickTeamID,
            signing: "com.example.not-nick"
        )))
    }

    func test_finderUninstallOnlyAllowsNickMoveIntoTrash() {
        let finder = identity(signing: "com.apple.finder", platform: true)
        XCTAssertTrue(TamperProtectionPolicy.isDocumentedFinderUninstall(
            sourcePath: "/Applications/Nick.app",
            destinationPath: "/Users/test/.Trash/Nick.app",
            identity: finder
        ))
        XCTAssertFalse(TamperProtectionPolicy.isDocumentedFinderUninstall(
            sourcePath: "/private/tmp/Fake.app",
            destinationPath: "/Applications/Nick.app",
            identity: finder
        ))
        XCTAssertFalse(TamperProtectionPolicy.isDocumentedFinderUninstall(
            sourcePath: "/Applications/Nick.app",
            destinationPath: "/private/tmp/Nick.app",
            identity: finder
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
