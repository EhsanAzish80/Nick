// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import XCTest
@testable import Nick

@MainActor
final class SmartScanStatusTests: XCTestCase {
    func testNetworkFilterVersionActivationIsRequiredWhenVersionChanges() {
        XCTAssertTrue(
            NetworkFilterInstaller.needsBundledVersionActivation(
                bundledVersion: "410",
                activatedVersion: "408"
            )
        )
    }

    func testNetworkFilterVersionActivationIsSkippedForCurrentVersion() {
        XCTAssertFalse(
            NetworkFilterInstaller.needsBundledVersionActivation(
                bundledVersion: "410",
                activatedVersion: "410"
            )
        )
        XCTAssertFalse(
            NetworkFilterInstaller.needsBundledVersionActivation(
                bundledVersion: nil,
                activatedVersion: "410"
            )
        )
    }


    func test_runScan_withoutVerifiedDependencies_neverShowsFalseGreen() {
        let checker = SmartScanChecker(useLiveRuntimeState: false)

        let status = checker.runScan()

        XCTAssertFalse(status.isFullyProtected)
        XCTAssertGreaterThan(status.issueCount, 0)
        XCTAssertFalse(status.checks.contains { $0.status == .protected })
        XCTAssertEqual(
            status.checks.first { $0.id == "endpoint_security" }?.status,
            .critical
        )
        XCTAssertEqual(
            status.checks.first { $0.id == "file_integrity" }?.status,
            .warning
        )
        XCTAssertEqual(
            status.checks.first { $0.id == "system_settings" }?.status,
            .warning
        )
    }

    func test_networkFilterHealth_rejectsLegacyUnsafeConfiguration() {
        let now = Date().timeIntervalSince1970
        let legacyHealth: [String: Any] = [
            "active": true,
            "updatedAt": now
        ]

        XCTAssertFalse(
            SmartScanChecker.isCurrentNetworkFilterHealth(legacyHealth, now: now)
        )
    }

    func test_networkFilterHealth_requiresFreshFailOpenConfiguration() {
        let now = Date().timeIntervalSince1970
        let currentHealth: [String: Any] = [
            "active": true,
            "updatedAt": now - 5,
            "configurationVersion": NetworkProtectionConfiguration.configurationVersion,
            "failOpen": true
        ]

        XCTAssertTrue(
            SmartScanChecker.isCurrentNetworkFilterHealth(currentHealth, now: now)
        )

        var staleHealth = currentHealth
        staleHealth["updatedAt"] = now - 31
        XCTAssertFalse(
            SmartScanChecker.isCurrentNetworkFilterHealth(staleHealth, now: now)
        )
    }

    func test_emailGuardHealth_requiresFreshScannerProof() {
        let now = Date().timeIntervalSince1970
        let ready: [String: Any] = [
            "active": true,
            "emailGuardActive": true,
            "emailScannerReady": true,
            "fullDiskAccessReady": true,
            "updatedAt": now - 5
        ]
        XCTAssertTrue(SmartScanChecker.isEmailScannerReady(ready, now: now))

        var noScanner = ready
        noScanner["emailScannerReady"] = false
        XCTAssertFalse(SmartScanChecker.isEmailScannerReady(noScanner, now: now))

        var noDiskAccess = ready
        noDiskAccess["fullDiskAccessReady"] = false
        XCTAssertFalse(SmartScanChecker.isEmailScannerReady(noDiskAccess, now: now))

        var stale = ready
        stale["updatedAt"] = now - 31
        XCTAssertFalse(SmartScanChecker.isEmailScannerReady(stale, now: now))

        XCTAssertFalse(SmartScanChecker.isEmailScannerReady(nil, now: now))
    }

    func test_endpointExtensionUpdate_requiresMatchingBundledBuild() {
        XCTAssertTrue(
            SmartScanChecker.extensionNeedsUpdate(
                runningVersion: "406",
                bundledVersion: "407"
            )
        )
        XCTAssertFalse(
            SmartScanChecker.extensionNeedsUpdate(
                runningVersion: "407",
                bundledVersion: "407"
            )
        )
        XCTAssertFalse(
            SmartScanChecker.extensionNeedsUpdate(
                runningVersion: nil,
                bundledVersion: "407"
            )
        )
    }

    func test_uninstallDoesNotFailWhenLaunchAtLoginRemovalIsDenied() {
        let denied = NSError(
            domain: NSPOSIXErrorDomain,
            code: Int(EPERM)
        )
        let inaccessible = NSError(
            domain: NSPOSIXErrorDomain,
            code: Int(EACCES)
        )
        let unrelated = NSError(
            domain: NSCocoaErrorDomain,
            code: NSFileWriteUnknownError
        )

        XCTAssertTrue(AppDelegate.isIgnorableLaunchAtLoginRemovalError(denied))
        XCTAssertTrue(AppDelegate.isIgnorableLaunchAtLoginRemovalError(inaccessible))
        XCTAssertFalse(AppDelegate.isIgnorableLaunchAtLoginRemovalError(unrelated))
    }
}
