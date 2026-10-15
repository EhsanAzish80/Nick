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

    func test_updateLeaseFailsClosedUnlessDestinationBuildIsStrictlyNewer() {
        XCTAssertNil(NickUpdateLeasePolicy.makeLease(
            consoleUID: 501,
            sourceBuild: 5017,
            destinationBuild: 5017,
            duration: 600,
            now: Date(timeIntervalSince1970: 1),
            uptime: 10
        ))
        let lease = NickUpdateLeasePolicy.makeLease(
            consoleUID: 501,
            sourceBuild: 5017,
            destinationBuild: 5018,
            duration: 600,
            now: Date(timeIntervalSince1970: 1),
            uptime: 10
        )
        XCTAssertEqual(lease?.consoleUID, 501)
        XCTAssertEqual(lease?.expiresAtUptime, 610)
        XCTAssertNil(NickUpdateLeasePolicy.makeLease(
            consoleUID: 501,
            sourceBuild: 5017,
            destinationBuild: 5018,
            duration: 601,
            now: Date(),
            uptime: 10
        ))
    }

    func test_updateLeaseOnlyCoversExactNickBundleTree() {
        XCTAssertTrue(NickUpdateLeasePolicy.containsProtectedUpdateDestination(
            "/Applications/Nick.app"
        ))
        XCTAssertTrue(NickUpdateLeasePolicy.containsProtectedUpdateDestination(
            "/Applications/Nick.app/Contents/MacOS/Nick"
        ))
        XCTAssertFalse(NickUpdateLeasePolicy.containsProtectedUpdateDestination(
            "/Applications/Nick.app-evil/Contents/MacOS/Nick"
        ))
        XCTAssertFalse(NickUpdateLeasePolicy.containsProtectedUpdateDestination(
            "/Applications/Other.app"
        ))
    }

    func test_updateLeaseAcceptsValidatedOmittedSparkleIdentityButNotSelfAssertion() {
        let autoupdate = identity(
            team: TamperProtectionPolicy.nickTeamID,
            signing: "Autoupdate"
        )
        XCTAssertFalse(TamperProtectionPolicy.isTrustedMaintenanceActor(
            autoupdate,
            nickIdentityValidated: true
        ))
        XCTAssertTrue(NickUpdateLeasePolicy.isEligibleInstallerActor(
            identity: autoupdate,
            nickUpdateIdentityValidated: true,
            actorPath: "/Applications/Nick.app/Contents/Frameworks/Sparkle.framework/Autoupdate"
        ))
        XCTAssertFalse(NickUpdateLeasePolicy.isEligibleInstallerActor(
            identity: autoupdate,
            nickUpdateIdentityValidated: false,
            actorPath: "/Applications/Nick.app/Contents/Frameworks/Sparkle.framework/Autoupdate"
        ))
    }

    func test_updateLeaseConsumesOnlyAtTopLevelReplacementBoundary() {
        XCTAssertFalse(NickUpdateLeasePolicy.isReplacementBoundary(
            sourcePath: "/private/tmp/Nick.app/Contents/MacOS/Nick",
            destinationPath: "/Applications/Nick.app/Contents/MacOS/Nick",
            operation: .rename
        ))
        XCTAssertTrue(NickUpdateLeasePolicy.isReplacementBoundary(
            sourcePath: "/private/tmp/Nick.app",
            destinationPath: "/Applications/Nick.app",
            operation: .rename
        ))
        XCTAssertFalse(NickUpdateLeasePolicy.isReplacementBoundary(
            sourcePath: "/private/tmp/Nick.app",
            destinationPath: "/Applications/Nick.app",
            operation: .write
        ))
    }

    func test_updateLeaseDecisionExpiresRejectsAndConsumes() throws {
        let lease = try XCTUnwrap(NickUpdateLeasePolicy.makeLease(
            consoleUID: 501,
            sourceBuild: 5017,
            destinationBuild: 5018,
            duration: 60,
            now: Date(),
            uptime: 100
        ))
        let autoupdate = identity(
            team: TamperProtectionPolicy.nickTeamID,
            signing: "Autoupdate"
        )
        XCTAssertEqual(NickUpdateLeasePolicy.decision(
            lease: lease,
            uptime: 161,
            targetPath: "/Applications/Nick.app",
            operation: .rename,
            actorPath: "/Applications/Nick.app/Contents/Frameworks/Sparkle.framework/Autoupdate",
            identity: autoupdate,
            nickUpdateIdentityValidated: true
        ), .expired)
        XCTAssertEqual(NickUpdateLeasePolicy.decision(
            lease: lease,
            uptime: 120,
            targetPath: "/Applications/Other.app",
            operation: .write,
            actorPath: "/Applications/Nick.app/Contents/Frameworks/Sparkle.framework/Autoupdate",
            identity: autoupdate,
            nickUpdateIdentityValidated: true
        ), .rejected)
        XCTAssertEqual(NickUpdateLeasePolicy.decision(
            lease: lease,
            uptime: 120,
            targetPath: "/Applications/Nick.app",
            sourcePath: "/private/tmp/Nick.app",
            operation: .rename,
            actorPath: "/Applications/Nick.app/Contents/Frameworks/Sparkle.framework/Autoupdate",
            identity: autoupdate,
            nickUpdateIdentityValidated: true
        ), .allowed(consume: true))
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

    func test_systemExtensionCommandClassificationKeepsRemovalSensitive() {
        XCTAssertFalse(TamperProtectionPolicy.isSensitiveSystemExtensionCommand(
            arguments: ["systemextensionsctl", "list"]
        ))
        XCTAssertTrue(TamperProtectionPolicy.isSensitiveSystemExtensionCommand(
            arguments: ["systemextensionsctl", "uninstall", "UXGW5V3BY6", "com.example.Extension"]
        ))
        XCTAssertTrue(TamperProtectionPolicy.isSensitiveSystemExtensionCommand(
            arguments: ["systemextensionsctl", "reset"]
        ))
    }

    func test_signalProtectionDeniesUntrustedTerminationButAllowsValidatedMaintenance() {
        let target = identity(team: TamperProtectionPolicy.nickTeamID, signing: "com.ehsanazish.nick")
        let terminal = identity(team: "OTHERTEAM", signing: "com.apple.Terminal")
        XCTAssertTrue(NickSignalProtectionPolicy.shouldDeny(
            signal: SIGKILL, targetIdentity: target,
            senderIdentity: terminal, senderNickIdentityValidated: false
        ))
        XCTAssertFalse(NickSignalProtectionPolicy.shouldDeny(
            signal: SIGKILL, targetIdentity: target,
            senderIdentity: terminal, senderNickIdentityValidated: true
        ))
        let launchd = identity(signing: "com.apple.launchd", platform: true)
        XCTAssertFalse(NickSignalProtectionPolicy.shouldDeny(
            signal: SIGTERM, targetIdentity: target,
            senderIdentity: launchd, senderNickIdentityValidated: false
        ))
        XCTAssertFalse(NickSignalProtectionPolicy.shouldDeny(
            signal: SIGUSR1, targetIdentity: target,
            senderIdentity: terminal, senderNickIdentityValidated: false
        ))
    }

    func test_continuityPolicySameBootIsGapAndRebootIsInformational() {
        let boot = Date(timeIntervalSince1970: 10_000)
        let sameBoot = ProtectionContinuityPolicy.evaluate(
            previous: .init(sequence: 7, wallTime: boot, bootSessionUUID: "A"),
            currentBootSessionUUID: "A", bootTime: boot
        )
        XCTAssertEqual(sameBoot.kind, .interrupted)

        let restarted = ProtectionContinuityPolicy.evaluate(
            previous: .init(sequence: 8, wallTime: boot.addingTimeInterval(-30), bootSessionUUID: "A"),
            currentBootSessionUUID: "B", bootTime: boot
        )
        XCTAssertEqual(restarted.kind, .resumedAfterRestart)

        let preexistingGap = ProtectionContinuityPolicy.evaluate(
            previous: .init(sequence: 9, wallTime: boot.addingTimeInterval(-300), bootSessionUUID: "A"),
            currentBootSessionUUID: "B", bootTime: boot
        )
        XCTAssertEqual(preexistingGap.kind, .interrupted)
    }

    func test_continuityHeartbeatSequenceRejectsRollbackAndReplay() {
        XCTAssertTrue(ProtectionContinuityPolicy.acceptsSequence(current: nil, proposed: 1))
        XCTAssertTrue(ProtectionContinuityPolicy.acceptsSequence(current: 41, proposed: 42))
        XCTAssertFalse(ProtectionContinuityPolicy.acceptsSequence(current: 42, proposed: 42))
        XCTAssertFalse(ProtectionContinuityPolicy.acceptsSequence(current: 42, proposed: 1))
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
