// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import XCTest
@testable import Nick

final class SimpleScanResultTests: XCTestCase {

    private func match(_ path: String, rule: String = "r") -> YARAMatch {
        YARAMatch(ruleName: rule, tags: [], filePath: path, metadata: [:])
    }

    func test_cleanFileReadsAsSafe() {
        let result = SimpleScanResult.fileCheck(target: URL(fileURLWithPath: "/tmp/Tool.app"), matches: [])
        XCTAssertEqual(result.verdict, .clear)
        XCTAssertEqual(result.headline, "“Tool.app” looks safe")
    }

    func test_harmfulOutranksReviewAndListsNamesNotPaths() {
        let result = SimpleScanResult.fileCheck(
            target: URL(fileURLWithPath: "/Users/a/Downloads/", isDirectory: true),
            matches: [match("/Users/a/Downloads/bad", rule: "fam"), match("/Users/a/Downloads/odd", rule: "beh")],
            classify: { $0.ruleName == "fam" ? .threat : .suspicious }
        )
        XCTAssertEqual(result.verdict, .harmful)
        XCTAssertEqual(result.headline, "Found 1 harmful file in “Downloads”")
        XCTAssertEqual(result.flaggedNames, ["bad", "odd"])
        XCTAssertFalse(result.headline.contains("/"))
    }

    func test_safeVerdictsAreNotFlagged() {
        let result = SimpleScanResult.fileCheck(
            target: URL(fileURLWithPath: "/Applications/App.app"),
            matches: [match("/Applications/App.app/Contents/MacOS/App")],
            classify: { _ in .likelySafe }
        )
        XCTAssertEqual(result.verdict, .clear)
    }

    func test_quickCheckCopy() {
        XCTAssertEqual(SimpleScanResult.quickCheck(needsAttention: 0).headline, "All clear")
        XCTAssertEqual(SimpleScanResult.quickCheck(needsAttention: 2).headline, "2 things need your attention")
    }

    func test_fullCheckHonoursIgnoredBehaviourFindings() {
        let ignored = match("/private/tmp/ignored", rule: "macos_ptrace_antidebug")
        let result = SimpleScanResult.fullCheck(
            filesChecked: 12,
            results: [ignored],
            verdicts: [DeepScanner.matchKey(for: ignored): .suspicious],
            ignoredPaths: ["/private/tmp/ignored"]
        )
        XCTAssertEqual(result.verdict, .clear)
        XCTAssertTrue(result.detail.hasPrefix("Checked 12 files."))
    }
}
