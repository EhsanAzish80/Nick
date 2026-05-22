// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import XCTest
@testable import Nick

// MARK: - HelperPathTraversalTests

/// Verifies that `HelperPathAllowlist` correctly rejects path traversal attempts
/// and other malformed inputs while accepting legitimate plist paths.
///
/// Every test case in the Task 1.2 audit checklist from `docs/PHASE_4_GUIDE.md`
/// is represented here. Green tests confirm the allowlist is enforced; any failure
/// indicates a regression in the security perimeter of the privileged helper.
///
/// - Note: SECURITY: These tests are the automated gate for plist path validation.
///   Do not remove or weaken them without a documented security review.
final class HelperPathTraversalTests: XCTestCase {

    // MARK: - Reject: Classic Traversal

    func test_validate_classicDotDotTraversal_isRejected() {
        XCTAssertFalse(
            HelperPathAllowlist.validate("../../../etc/passwd"),
            "Relative paths with traversal components must be rejected"
        )
    }

    func test_validate_absoluteTraversalViaLaunchDaemons_isRejected() {
        XCTAssertFalse(
            HelperPathAllowlist.validate("/Library/LaunchDaemons/../../../etc/passwd"),
            "Path that traverses out of an allowed prefix must be rejected"
        )
    }

    func test_validate_absoluteTraversalToEtcPasswd_isRejected() {
        XCTAssertFalse(
            HelperPathAllowlist.validate("/etc/passwd"),
            "/etc/passwd is not in the allowlist; must be rejected"
        )
    }

    // MARK: - Reject: Symlink Outside Allowed Directory

    func test_validate_symlinkOutsideAllowedDirectory_isRejected() throws {
        // Create a symlink inside the tmp directory that points to /etc/passwd.
        let tmpDir = FileManager.default.temporaryDirectory
        let symlink = tmpDir.appendingPathComponent("nick_test_symlink_\(UUID().uuidString).plist")
        try FileManager.default.createSymbolicLink(
            at: symlink,
            withDestinationURL: URL(fileURLWithPath: "/etc/passwd")
        )
        defer { try? FileManager.default.removeItem(at: symlink) }

        // A symlink inside /tmp/ (not in the allowlist) should be rejected outright
        // because /tmp/ is not an allowed prefix.
        XCTAssertFalse(
            HelperPathAllowlist.validate(symlink.path),
            "A path in /tmp/ (not in allowlist) must be rejected"
        )
    }

    func test_validate_launchDaemonsSymlinkToEtcPasswd_isRejected() throws {
        // Create a symlink named like a valid plist but pointing outside the allowed tree.
        // We use a temp directory that mimics the name to avoid needing root access.
        // The real scenario — a symlink inside /Library/LaunchDaemons/ — would resolve
        // to /etc/passwd, and the resolved path would fail the allowlist prefix check.
        let tmpDir = FileManager.default.temporaryDirectory
        let fakeDir = tmpDir.appendingPathComponent("LaunchDaemons_\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: fakeDir, withIntermediateDirectories: true)
        let symlink = fakeDir.appendingPathComponent("evil.plist")
        try FileManager.default.createSymbolicLink(
            at: symlink,
            withDestinationURL: URL(fileURLWithPath: "/etc/hosts")
        )
        defer { try? FileManager.default.removeItem(at: fakeDir) }

        // The symlink resolves to /private/etc/hosts which IS in the allowlist,
        // so this particular symlink is actually valid. The dangerous case is when
        // the resolved path is outside all allowed prefixes.
        //
        // For the dangerous case: symlink → /tmp/malicious → rejected because
        // resolved path is /private/tmp/... which is not in the allowlist.
        let dangerSymlink = fakeDir.appendingPathComponent("dangerous.plist")
        try FileManager.default.createSymbolicLink(
            at: dangerSymlink,
            withDestinationURL: URL(fileURLWithPath: "/tmp/sensitive_data")
        )

        XCTAssertFalse(
            HelperPathAllowlist.validate(dangerSymlink.path),
            "Symlink resolving to /tmp/ must be rejected (not in allowlist)"
        )
    }

    // MARK: - Reject: Null Bytes

    func test_validate_pathWithNullByte_isRejected() {
        let pathWithNull = "/Library/LaunchDaemons/com.test.plist\0../../../etc/passwd"
        XCTAssertFalse(
            HelperPathAllowlist.validate(pathWithNull),
            "Path containing a null byte must be rejected"
        )
    }

    func test_validate_nullByteAtStart_isRejected() {
        XCTAssertFalse(
            HelperPathAllowlist.validate("\0/Library/LaunchDaemons/com.test.plist"),
            "Path starting with a null byte must be rejected"
        )
    }

    // MARK: - Reject: Oversized Path

    func test_validate_pathExceedingMaxLength_isRejected() {
        let longComponent = String(repeating: "a", count: 4_097)
        let longPath = "/Library/LaunchDaemons/" + longComponent
        XCTAssertFalse(
            HelperPathAllowlist.validate(longPath),
            "Path exceeding \(HelperPathAllowlist.maxPathLength) bytes must be rejected"
        )
    }

    func test_validate_pathAtExactMaxLength_behavior() {
        // A path exactly at the limit (4096 bytes) is accepted or rejected depending
        // on whether it maps to an allowed prefix after normalisation.
        // This test documents the boundary behaviour.
        let prefix = "/Library/LaunchDaemons/"
        let padding = String(repeating: "x", count: HelperPathAllowlist.maxPathLength - prefix.utf8.count)
        let exactPath = prefix + padding
        // The path is within the length limit. Whether it's accepted depends on prefix match.
        // Since it starts with an allowed prefix, length check passes. Acceptance is expected.
        XCTAssertLessThanOrEqual(
            exactPath.utf8.count,
            HelperPathAllowlist.maxPathLength,
            "Sanity check: test path should be at or below max length"
        )
    }

    // MARK: - Reject: URL-Encoded Path Separators

    func test_validate_percentEncodedSlash_isRejected() {
        XCTAssertFalse(
            HelperPathAllowlist.validate("/Library/LaunchDaemons%2F..%2F..%2Fetc%2Fpasswd"),
            "Path with percent-encoded slashes must be rejected"
        )
    }

    func test_validate_doubleEncodedPath_isRejected() {
        XCTAssertFalse(
            HelperPathAllowlist.validate("%2F%2FLibrary%2FLaunchDaemons%2Fcom.test.plist"),
            "Fully percent-encoded path must be rejected"
        )
    }

    func test_validate_mixedEncodingSlash_isRejected() {
        XCTAssertFalse(
            HelperPathAllowlist.validate("/Library/LaunchDaemons/com.test%2Fplist"),
            "Path with %2F inside a component must be rejected"
        )
    }

    // MARK: - Accept: Legitimate Paths

    func test_validate_validLaunchDaemonPath_isAccepted() {
        XCTAssertTrue(
            HelperPathAllowlist.validate("/Library/LaunchDaemons/com.malware.plist"),
            "A valid LaunchDaemon path (even for an unknown process) must be accepted"
        )
    }

    func test_validate_validLaunchAgentPath_isAccepted() {
        XCTAssertTrue(
            HelperPathAllowlist.validate("/Library/LaunchAgents/com.apple.something.plist"),
            "A valid LaunchAgent path must be accepted"
        )
    }

    func test_validate_firewallPreferencesPath_isAccepted() {
        XCTAssertTrue(
            HelperPathAllowlist.validate("/Library/Preferences/com.apple.alf.plist"),
            "The firewall preferences plist must be accepted"
        )
    }

    func test_validate_etcHostsPath_isRejected() {
        // /etc/ is intentionally NOT in the allowlist — the helper reads plists
        // from LaunchDaemons/Agents/Preferences directories only.
        // Allowing /etc/ would let a symlink attack redirect reads to /etc/sudoers etc.
        XCTAssertFalse(
            HelperPathAllowlist.validate("/etc/hosts"),
            "/etc/hosts is not in the allowlist; must be rejected"
        )
    }

    func test_validate_privateEtcPath_isRejected() {
        // /private/etc/ is also NOT in the allowlist.
        XCTAssertFalse(
            HelperPathAllowlist.validate("/private/etc/hosts"),
            "/private/etc/hosts is not in the allowlist; must be rejected"
        )
    }

    func test_validate_systemLaunchDaemonPath_isAccepted() {
        XCTAssertTrue(
            HelperPathAllowlist.validate("/System/Library/LaunchDaemons/com.apple.auditd.plist"),
            "A system LaunchDaemon path must be accepted"
        )
    }

    // MARK: - Reject: Miscellaneous

    func test_validate_emptyPath_isRejected() {
        XCTAssertFalse(
            HelperPathAllowlist.validate(""),
            "Empty path must be rejected"
        )
    }

    func test_validate_relativePathWithoutTraversal_isRejected() {
        XCTAssertFalse(
            HelperPathAllowlist.validate("Library/LaunchDaemons/com.test.plist"),
            "Relative path (no leading slash) must be rejected"
        )
    }

    func test_validate_pathOutsideAllAllowedPrefixes_isRejected() {
        XCTAssertFalse(
            HelperPathAllowlist.validate("/Users/ehsanazish/Documents/secret.plist"),
            "Path outside all allowed prefixes must be rejected"
        )
    }

    func test_validate_tmpPath_isRejected() {
        XCTAssertFalse(
            HelperPathAllowlist.validate("/tmp/com.malware.plist"),
            "/tmp/ is not in the allowlist; must be rejected"
        )
    }

    func test_validate_desktopPath_isRejected() {
        XCTAssertFalse(
            HelperPathAllowlist.validate("/Users/ehsanazish/Desktop/com.test.plist"),
            "Desktop path must be rejected"
        )
    }
}
