// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import XCTest
@testable import Nick

/// Policies shared by the app and the Endpoint Security extension.
final class DetectionPolicyTests: XCTestCase {

    // MARK: - YARAVerdictPolicy

    func test_ruleClassComesFromMetadataThenLegacyList() {
        XCTAssertEqual(YARAVerdictPolicy.ruleClass(ruleName: "x", metadata: ["class": "behavior"]), .behavior)
        XCTAssertEqual(YARAVerdictPolicy.ruleClass(ruleName: "x", metadata: ["class": " Signature "]), .signature)
        XCTAssertEqual(YARAVerdictPolicy.ruleClass(ruleName: "macos_reverse_shell", metadata: [:]), .behavior)
        XCTAssertEqual(YARAVerdictPolicy.ruleClass(ruleName: "osx_atomic_stealer", metadata: [:]), .signature)
    }

    func test_missingSeverityIsMediumOnEveryPath() {
        XCTAssertEqual(YARAVerdictPolicy.severity(metadata: [:], tags: []), .medium)
        XCTAssertEqual(YARAVerdictPolicy.severity(metadata: [:], tags: ["CRITICAL"]), .critical)
        XCTAssertEqual(YARAVerdictPolicy.severity(metadata: ["severity": "low"], tags: ["critical"]), .low)
    }

    func test_contextFreeThreatRequiresSignatureOrCriticalBehavior() {
        XCTAssertTrue(YARAVerdictPolicy.isContextFreeThreat(
            ruleName: "fam", metadata: ["class": "signature", "severity": "HIGH"], tags: []))
        XCTAssertFalse(YARAVerdictPolicy.isContextFreeThreat(
            ruleName: "fam", metadata: ["class": "signature", "severity": "MEDIUM"], tags: []))
        XCTAssertFalse(YARAVerdictPolicy.isContextFreeThreat(
            ruleName: "macos_launch_constraints_bypass", metadata: ["severity": "HIGH"], tags: []))
        XCTAssertTrue(YARAVerdictPolicy.isContextFreeThreat(
            ruleName: "b", metadata: ["class": "behavior", "severity": "CRITICAL"], tags: []))
        // Missing severity no longer means HIGH in the extension.
        XCTAssertFalse(YARAVerdictPolicy.isContextFreeThreat(
            ruleName: "fam", metadata: ["class": "signature"], tags: []))
    }

    // MARK: - ExecutionTrustPolicy

    func test_adhocSignatureIsNotATrustedSigner() {
        let valid = ExecutionTrustPolicy.csValid
        let adhoc = ExecutionTrustPolicy.csAdhoc
        XCTAssertFalse(ExecutionTrustPolicy.hasTrustedSigner(codesigningFlags: valid | adhoc, isPlatformBinary: false, teamID: nil))
        XCTAssertFalse(ExecutionTrustPolicy.hasTrustedSigner(codesigningFlags: valid | adhoc, isPlatformBinary: false, teamID: "ABCDE12345"))
        XCTAssertFalse(ExecutionTrustPolicy.hasTrustedSigner(codesigningFlags: valid, isPlatformBinary: false, teamID: ""))
        XCTAssertFalse(ExecutionTrustPolicy.hasTrustedSigner(codesigningFlags: 0, isPlatformBinary: true, teamID: nil))
        XCTAssertFalse(ExecutionTrustPolicy.hasTrustedSigner(codesigningFlags: valid, isPlatformBinary: false, teamID: "ABCDE12345"))
        XCTAssertTrue(ExecutionTrustPolicy.hasTrustedSigner(codesigningFlags: valid, isPlatformBinary: true, teamID: nil))
    }

    func test_validatedDeveloperIDRansomwareSignalIsAlertOnly() {
        XCTAssertFalse(RansomwareTerminationPolicy.shouldTerminate(
            isBlockRecommendation: true,
            developerIDValidated: true
        ))
        XCTAssertTrue(RansomwareTerminationPolicy.shouldTerminate(
            isBlockRecommendation: true,
            developerIDValidated: false
        ), "A self-signed actor with a copied Team ID must not gain the exemption")
    }

    func test_pidReuseCannotAuthoriseProcessTermination() {
        let reviewed = ProcessInstanceIdentity(pid: 42, startSeconds: 100, startMicroseconds: 1)
        let reused = ProcessInstanceIdentity(pid: 42, startSeconds: 101, startMicroseconds: 1)
        XCTAssertTrue(RansomwareTerminationPolicy.maySignalKill(expected: reviewed, current: reviewed))
        XCTAssertFalse(RansomwareTerminationPolicy.maySignalKill(expected: reviewed, current: reused))
        XCTAssertFalse(RansomwareTerminationPolicy.maySignalKill(expected: nil, current: reviewed))
    }

    func test_highRiskLocationsCoverStagingAndPersistence() {
        let risky = [
            "/Users/a/Library/Application Support/x/agent",
            "/Users/a/Library/LaunchAgents/com.x.plist",
            "/Users/Shared/.cache/run",
            "/Users/a/.local/bin/tool",
            "/Library/Application Support/x/helper",
            "/private/tmp/x",
            "/Users/a/Downloads/tool",
            "/Applications/Some.app/Contents/MacOS/.hidden/payload",
        ]
        for path in risky { XCTAssertTrue(ExecutionTrustPolicy.isHighRiskLocation(path), path) }

        let ordinary = [
            "/Applications/Safari.app/Contents/MacOS/Safari",
            "/Users/a/Projects/App/build/App",
            "/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder",
            "/usr/bin/ssh",
        ]
        for path in ordinary { XCTAssertFalse(ExecutionTrustPolicy.isHighRiskLocation(path), path) }
    }

    func test_execScanDecision() {
        // Ad-hoc binary in /Applications: scanned (previously skipped as "signed").
        XCTAssertTrue(ExecutionTrustPolicy.shouldScanOnExec(
            path: "/Applications/Fake.app/Contents/MacOS/Fake", hasTrustedSigner: false))
        // Developer ID binary in Application Support: scanned.
        XCTAssertTrue(ExecutionTrustPolicy.shouldScanOnExec(
            path: "/Users/a/Library/Application Support/x/agent", hasTrustedSigner: true))
        // Developer ID app in /Applications: skipped.
        XCTAssertFalse(ExecutionTrustPolicy.shouldScanOnExec(
            path: "/Applications/Real.app/Contents/MacOS/Real", hasTrustedSigner: true))
        // Sealed system volume: skipped.
        XCTAssertFalse(ExecutionTrustPolicy.shouldScanOnExec(path: "/usr/bin/true", hasTrustedSigner: false))
    }

    // MARK: - ScanCandidatePolicy

    func test_headerSniffing() {
        XCTAssertEqual(ScanCandidatePolicy.kind(ofHeader: Data([0xCF, 0xFA, 0xED, 0xFE, 0x0C, 0, 0, 1])), .machO)
        XCTAssertEqual(ScanCandidatePolicy.kind(ofHeader: Data([0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 2])), .machO)
        // Java class file: same magic, huge "architecture count".
        XCTAssertEqual(ScanCandidatePolicy.kind(ofHeader: Data([0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 0x34])), .other)
        XCTAssertEqual(ScanCandidatePolicy.kind(ofHeader: Data("#!/bin/zsh\n".utf8)), .script)
        XCTAssertEqual(ScanCandidatePolicy.kind(ofHeader: Data("xar!\u{0}\u{1c}".utf8)), .installerArchive)
        XCTAssertEqual(ScanCandidatePolicy.kind(ofHeader: Data("FasdUAS 1.101.10".utf8)), .compiledAppleScript)
        XCTAssertEqual(ScanCandidatePolicy.kind(ofHeader: Data([0x50, 0x4B, 0x03, 0x04])), .archive)
        XCTAssertEqual(ScanCandidatePolicy.kind(ofHeader: Data("SQLite format 3".utf8)), .other)
        XCTAssertFalse(ScanCandidatePolicy.isExecutableContent(.archive))
        XCTAssertTrue(ScanCandidatePolicy.isExecutableContent(.machO))
    }

    // MARK: - RansomwareRenamePolicy

    func test_introducedExtensionIgnoresRoutineRenames() {
        XCTAssertEqual(RansomwareRenamePolicy.introducedExtension(
            source: "/Users/a/Documents/report.docx", destination: "/Users/a/Documents/report.docx.k7x2q"), "k7x2q")
        XCTAssertEqual(RansomwareRenamePolicy.introducedExtension(
            source: "/Users/a/Documents/report.docx", destination: "/Users/a/Documents/report.turtle"), "turtle")

        let routine: [(String, String)] = [
            ("/a/config.json.tmp", "/a/config.json"),
            ("/a/file.crdownload", "/a/file.dmg"),
            ("/a/photo.heic", "/a/photo.jpg"),
            ("/a/.index.lock", "/a/.index"),
            ("/a/doc.pages", "/a/doc.sb-4c1a-abc"),
            ("/a/notes.txt", "/a/notes.txt"),
            ("/a/report.docx", "/a/report.docx.bak"),
            (
                "/Users/test/Projects/DimensionForge/Prototypes/Boolean/.build-manifold/release/CMakeFiles/CMakeScratch/TryCompile-test/CMakeFiles/cmTC.dir/build",
                "/Users/test/Projects/DimensionForge/Prototypes/Boolean/.build-manifold/release/CMakeFiles/CMakeScratch/TryCompile-test/CMakeFiles/cmTC.dir/build.make"
            ),
            (
                "/Users/test/Projects/DimensionForge/Prototypes/Boolean/.build-manifold/release/CMakeFiles/ContinuousStart.dir/progress",
                "/Users/test/Projects/DimensionForge/Prototypes/Boolean/.build-manifold/release/CMakeFiles/ContinuousStart.dir/progress.make"
            ),
        ]
        for (source, destination) in routine {
            XCTAssertNil(RansomwareRenamePolicy.introducedExtension(source: source, destination: destination), destination)
        }
    }
}
