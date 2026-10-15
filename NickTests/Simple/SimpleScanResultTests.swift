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

    func test_fileCheckRetainsReviewedHashAndThreatNameForSafeRemediation() {
        let path = "/private/tmp/eicar.com"
        let hash = String(repeating: "a", count: 64)
        let detected = YARAMatch(
            ruleName: "eicar_exact_hash",
            tags: ["signature"],
            filePath: path,
            metadata: [
                "description": "EICAR Anti-Malware Test File",
                "sha256": hash,
            ]
        )

        let result = SimpleScanResult.fileCheck(
            target: URL(fileURLWithPath: path),
            matches: [detected],
            classify: { _ in .threat }
        )

        XCTAssertEqual(result.reviewedHashes[path], hash)
        XCTAssertEqual(result.threatNames[path], "EICAR Anti-Malware Test File")
    }

    func test_scannerHashOverridesLaterFallbackHash() {
        let path = "/private/tmp/eicar.com"
        let reviewedHash = String(repeating: "b", count: 64)
        let laterHash = String(repeating: "c", count: 64)
        let detected = YARAMatch(
            ruleName: "eicar_exact_hash",
            tags: ["signature"],
            filePath: path,
            metadata: ["sha256": reviewedHash]
        )

        let result = SimpleScanResult.fileCheck(
            target: URL(fileURLWithPath: path),
            matches: [detected],
            reviewedHashes: [path: laterHash],
            classify: { _ in .threat }
        )

        XCTAssertEqual(result.reviewedHashes[path], reviewedHash)
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
