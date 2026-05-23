// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import XCTest
@testable import Nick

// MARK: - TrustedProcessListTests

/// Unit tests for `TrustedProcessList`.
///
/// Validates that the built-in list behaves as expected, that user-configurable
/// additions/removals work correctly, and that edge cases (empty names, built-in
/// removal attempts) are handled safely.
final class TrustedProcessListTests: XCTestCase {

    // MARK: - Built-in List

    func test_isTrusted_terminalEmulator_isTrue() {
        let sut = TrustedProcessList()
        XCTAssertTrue(sut.isTrusted("Terminal"), "Terminal is in the built-in list")
        XCTAssertTrue(sut.isTrusted("iTerm2"),   "iTerm2 is in the built-in list")
        XCTAssertTrue(sut.isTrusted("Warp"),     "Warp is in the built-in list")
    }

    func test_isTrusted_developerTools_isTrue() {
        let sut = TrustedProcessList()
        XCTAssertTrue(sut.isTrusted("Xcode"),     "Xcode is in the built-in list")
        XCTAssertTrue(sut.isTrusted("swift"),     "swift is in the built-in list")
        XCTAssertTrue(sut.isTrusted("git"),       "git is in the built-in list")
        XCTAssertTrue(sut.isTrusted("brew"),      "brew is in the built-in list")
        XCTAssertTrue(sut.isTrusted("npm"),       "npm is in the built-in list")
    }

    func test_isTrusted_systemProcesses_isTrue() {
        let sut = TrustedProcessList()
        XCTAssertTrue(sut.isTrusted("sshd"),       "sshd is in the built-in list")
        XCTAssertTrue(sut.isTrusted("launchd"),    "launchd is in the built-in list")
        XCTAssertTrue(sut.isTrusted("mdworker"),   "mdworker is in the built-in list")
    }

    func test_isTrusted_unknownProcess_isFalse() {
        let sut = TrustedProcessList()
        XCTAssertFalse(sut.isTrusted("my_malware"),    "Unknown process must not be trusted by default")
        XCTAssertFalse(sut.isTrusted("coinstrike"),    "Unknown process must not be trusted by default")
        XCTAssertFalse(sut.isTrusted("cryptominer"),   "Unknown process must not be trusted by default")
    }

    func test_isTrusted_isCaseInsensitive() {
        let sut = TrustedProcessList()
        // Matching is intentionally case-insensitive so process names that differ
        // in capitalisation between macOS versions (and p_comm truncation variants)
        // are still recognised correctly.
        XCTAssertTrue(sut.isTrusted("terminal"),  "'terminal' should match 'Terminal' (case-insensitive)")
        XCTAssertTrue(sut.isTrusted("XCODE"),     "'XCODE' should match 'Xcode' (case-insensitive)")
    }

    // MARK: - User Trusted Additions

    func test_addUserTrusted_makesTrusted() {
        var sut = TrustedProcessList()
        XCTAssertFalse(sut.isTrusted("MyCorporateTool"))
        sut.addUserTrusted("MyCorporateTool")
        XCTAssertTrue(sut.isTrusted("MyCorporateTool"),
                      "Process must be trusted after addUserTrusted")
    }

    func test_addUserTrusted_idempotent() {
        var sut = TrustedProcessList()
        sut.addUserTrusted("Alfred")
        sut.addUserTrusted("Alfred")
        XCTAssertEqual(sut.userTrustedNames().count, 1,
                       "Adding the same name twice must not create duplicates")
    }

    func test_addUserTrusted_emptyString_isIgnored() {
        var sut = TrustedProcessList()
        sut.addUserTrusted("")
        XCTAssertFalse(sut.userTrusted.contains(""),
                       "Empty process names must be rejected")
        XCTAssertFalse(sut.isTrusted(""),
                       "Empty string must never be trusted")
    }

    // MARK: - User Trusted Removals

    func test_removeUserTrusted_removesTrust() {
        var sut = TrustedProcessList(userTrusted: ["Raycast"])
        XCTAssertTrue(sut.isTrusted("Raycast"))
        sut.removeUserTrusted("Raycast")
        XCTAssertFalse(sut.isTrusted("Raycast"),
                       "Process must no longer be trusted after removeUserTrusted")
    }

    func test_removeUserTrusted_builtInIsNotAffected() {
        var sut = TrustedProcessList()
        // Attempt to remove a built-in entry via removeUserTrusted
        sut.removeUserTrusted("Terminal")
        XCTAssertTrue(sut.isTrusted("Terminal"),
                      "Built-in entries cannot be removed via removeUserTrusted")
    }

    func test_removeUserTrusted_nonExistent_isNoOp() {
        var sut = TrustedProcessList()
        XCTAssertNoThrow(sut.removeUserTrusted("DoesNotExist"),
                         "Removing a non-existent entry must not throw")
    }

    // MARK: - Query Helpers

    func test_allTrustedNames_containsBuiltInAndUser() {
        var sut = TrustedProcessList()
        sut.addUserTrusted("MyApp")
        let all = sut.allTrustedNames()
        XCTAssertTrue(all.contains("Terminal"),  "allTrustedNames must contain built-in entries")
        XCTAssertTrue(all.contains("MyApp"),     "allTrustedNames must contain user entries")
    }

    func test_allTrustedNames_isSorted() {
        let sut = TrustedProcessList(userTrusted: ["Zzz", "Aaa"])
        let names = sut.allTrustedNames()
        XCTAssertEqual(names, names.sorted(), "allTrustedNames must be alphabetically sorted")
    }

    func test_userTrustedNames_excludesBuiltIn() {
        var sut = TrustedProcessList()
        sut.addUserTrusted("OnlyUserApp")
        let user = sut.userTrustedNames()
        XCTAssertTrue(user.contains("OnlyUserApp"), "userTrustedNames must include user entries")
        XCTAssertFalse(user.contains("Terminal"),   "userTrustedNames must not include built-in entries")
    }

    // MARK: - Init with userTrusted

    func test_init_withUserTrusted_isTrusted() {
        let sut = TrustedProcessList(userTrusted: ["Raycast", "Alfred"])
        XCTAssertTrue(sut.isTrusted("Raycast"), "Init with userTrusted must mark those names as trusted")
        XCTAssertTrue(sut.isTrusted("Alfred"),  "Init with userTrusted must mark those names as trusted")
    }

    func test_init_withUserTrusted_doesNotOverrideBuiltIn() {
        let sut = TrustedProcessList(userTrusted: ["CustomApp"])
        XCTAssertTrue(sut.isTrusted("Terminal"),   "Built-in entries must still be trusted when userTrusted is set")
    }
}
