// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation

/// Plain-language results for Simple ▸ Scan.
struct SimpleScanResult: Equatable {
    enum Verdict: Equatable { case clear, review, harmful }

    let verdict: Verdict
    let headline: String
    let detail: String
    /// File names (never full paths) that need a look, most serious first.
    let flaggedNames: [String]
    /// Full paths behind `flaggedNames`, for Move to Trash / Show in Finder.
    let flaggedPaths: [String]

    /// Result of checking one chosen file or folder.
    static func fileCheck(
        target: URL,
        matches: [YARAMatch],
        classify: (YARAMatch) -> ThreatVerdict = { DeepScanner.classify(match: $0) }
    ) -> SimpleScanResult {
        let name = target.lastPathComponent
        let isFolder = target.hasDirectoryPath
        var harmful: [String] = []
        var review: [String] = []
        for match in DeepScanner.uniqueMatches(matches) {
            switch classify(match) {
            case .threat:     harmful.append(match.filePath)
            case .suspicious: review.append(match.filePath)
            default:          break
            }
        }
        let harmfulPaths = unique(harmful)
        let reviewPaths = unique(review).filter { !harmfulPaths.contains($0) }
        let flagged = harmfulPaths + reviewPaths
        let names = flagged.map { URL(fileURLWithPath: $0).lastPathComponent }

        if !harmfulPaths.isEmpty {
            return SimpleScanResult(
                verdict: .harmful,
                headline: isFolder
                    ? "Found \(count(harmfulPaths.count, "harmful file")) in “\(name)”"
                    : "“\(name)” looks harmful",
                detail: "Don’t open it. Move it to the Trash unless you’re sure where it came from.",
                flaggedNames: names, flaggedPaths: flagged
            )
        }
        if !reviewPaths.isEmpty {
            return SimpleScanResult(
                verdict: .review,
                headline: isFolder
                    ? "\(count(reviewPaths.count, "file")) in “\(name)” need\(reviewPaths.count == 1 ? "s" : "") a look"
                    : "“\(name)” needs a look",
                detail: "It can do things harmful apps also do. That’s often fine — keep it only if you trust where it came from.",
                flaggedNames: names, flaggedPaths: flagged
            )
        }
        return SimpleScanResult(
            verdict: .clear,
            headline: isFolder ? "Nothing harmful in “\(name)”" : "“\(name)” looks safe",
            detail: "Nick checked it against known threats and didn’t find anything.",
            flaggedNames: [], flaggedPaths: []
        )
    }

    /// Result of a finished Full Check (Deep Scan).
    static func fullCheck(
        filesChecked: Int,
        results: [YARAMatch],
        verdicts: [String: ThreatVerdict],
        ignoredPaths: Set<String>
    ) -> SimpleScanResult {
        var harmful: [String] = []
        var review: [String] = []
        for match in results {
            let path = DeepScanner.canonicalPath(match.filePath)
            switch verdicts[DeepScanner.matchKey(for: match)] {
            case .threat?:
                harmful.append(path)
            case .suspicious?:
                if !(ignoredPaths.contains(path) && DeepScanner.canIgnore(match: match)) { review.append(path) }
            default:
                break
            }
        }
        let harmfulPaths = unique(harmful)
        let reviewPaths = unique(review).filter { !harmfulPaths.contains($0) }
        let flagged = harmfulPaths + reviewPaths
        let checked = "Checked \(count(filesChecked, "file"))."

        if flagged.isEmpty {
            return SimpleScanResult(
                verdict: .clear, headline: "Nothing harmful found",
                detail: "\(checked) Your apps, downloads and startup items look clean.",
                flaggedNames: [], flaggedPaths: []
            )
        }
        return SimpleScanResult(
            verdict: harmfulPaths.isEmpty ? .review : .harmful,
            headline: "\(count(flagged.count, "file")) need\(flagged.count == 1 ? "s" : "") a look",
            detail: harmfulPaths.isEmpty
                ? "\(checked) These can do things harmful apps also do. Keep them only if you trust where they came from."
                : "\(checked) Move anything you don’t recognise to the Trash.",
            flaggedNames: flagged.map { URL(fileURLWithPath: $0).lastPathComponent },
            flaggedPaths: flagged
        )
    }

    /// Result of a finished Quick Check (the background system check).
    static func quickCheck(needsAttention: Int) -> SimpleScanResult {
        needsAttention == 0
            ? SimpleScanResult(
                verdict: .clear, headline: "All clear",
                detail: "Nick checked your settings, startup items, running apps and connections.",
                flaggedNames: [], flaggedPaths: [])
            : SimpleScanResult(
                verdict: .review,
                headline: "\(count(needsAttention, "thing")) need\(needsAttention == 1 ? "s" : "") your attention",
                detail: "Home explains each one and how to fix it.",
                flaggedNames: [], flaggedPaths: [])
    }

    private static func count(_ n: Int, _ noun: String) -> String {
        "\(n.formatted()) \(noun)\(n == 1 ? "" : "s")"
    }

    private static func unique(_ paths: [String]) -> [String] {
        var seen = Set<String>()
        return paths.filter { seen.insert($0).inserted }
    }
}
