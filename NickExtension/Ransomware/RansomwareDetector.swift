// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation
import os

// MARK: - RansomwareDetector

/// Combines multiple heuristics to detect active ransomware campaigns.
///
/// Signals evaluated per file-write event:
/// 1. **Canary file touched** — a decoy file planted in the user's home dirs
/// 2. **High-entropy write** — encrypted/compressed data replacing plaintext
/// 3. **Known ransomware extension** — extension added by family-specific strains
/// 4. **Ransom note filename** — README_DECRYPT, RESTORE_FILES, etc.
/// 5. **Behavioural score** — from `BehaviorTracker` (rapid renames, burst ops)
///
/// Confidence ≥ 0.8 → `.block` (kill + quarantine immediately)
/// Confidence 0.5–0.8 → `.suspend` (pause process, alert user)
/// Confidence < 0.5 → `.monitor` (continue watching)
final class RansomwareDetector {

    // MARK: - Types

    struct RansomwareAlert {
        let pid: Int32
        let processPath: String
        let indicators: [String]
        let confidence: Double

        enum Recommendation {
            case block      // high confidence — kill and quarantine now
            case suspend    // medium confidence — suspend process, prompt user
            case monitor    // low confidence — keep watching
        }
        var recommendation: Recommendation {
            switch confidence {
            case 0.8...:     return .block
            case 0.5..<0.8:  return .suspend
            default:          return .monitor
            }
        }
    }

    // MARK: - Private

    private static let logger = Logger(
        subsystem: "com.ehsanazish.nick.NickExtension",
        category: "RansomwareDetector"
    )

    private let behaviorTracker: BehaviorTracker
    let canaryManager: CanaryFileManager

    // MARK: - Init

    init(behaviorTracker: BehaviorTracker) {
        self.behaviorTracker = behaviorTracker
        self.canaryManager   = CanaryFileManager()
    }

    // MARK: - Public API

    /// Evaluates a file-write event for ransomware signals.
    ///
    /// - Parameters:
    ///   - pid: PID of the writing process.
    ///   - processPath: Executable path of the writing process.
    ///   - filePath: Path of the file being written.
    ///   - fileData: Contents written (pass `nil` if unavailable — entropy check skipped).
    /// - Returns: A `RansomwareAlert` when one or more signals fire, `nil` if clean.
    func evaluate(pid: Int32, processPath: String,
                  filePath: String, fileData: Data?) -> RansomwareAlert? {
        var indicators: [String] = []
        var confidence = 0.0

        // 1. Canary file touched
        if canaryManager.isCanary(path: filePath) {
            indicators.append("Canary file touched: \(filePath)")
            confidence += 0.6
            Self.logger.warning("Canary file touched by pid=\(pid) path=\(filePath)")
        }

        // 2. High-entropy write (encrypted content replacing plaintext)
        if let data = fileData, !data.isEmpty {
            let entropy = calculateEntropy(data: data)
            if entropy > 7.5 {
                indicators.append(String(format: "High-entropy write: %.2f bits/byte", entropy))
                confidence += 0.3
            }
        }

        // 3. Known ransomware extension
        let ext = URL(fileURLWithPath: filePath).pathExtension.lowercased()
        if !ext.isEmpty && knownRansomwareExtensions.contains(ext) {
            indicators.append("Known ransomware extension: .\(ext)")
            confidence += 0.4
        }

        // 4. Ransom note filename
        let filename = URL(fileURLWithPath: filePath).lastPathComponent.lowercased()
        if ransomNotePatterns.contains(where: { filename.contains($0) }) {
            indicators.append("Ransom note: \(filename)")
            confidence += 0.5
        }

        // 5. Behavioural analysis
        let behavior = behaviorTracker.analyze(pid: pid)
        if behavior.isSuspicious {
            indicators.append(contentsOf: behavior.indicators)
            confidence += behavior.score * 0.3
        }

        guard !indicators.isEmpty else { return nil }

        let alert = RansomwareAlert(
            pid:         pid,
            processPath: processPath,
            indicators:  indicators,
            confidence:  min(confidence, 1.0)
        )

        Self.logger.notice(
            "Ransomware alert pid=\(pid) confidence=\(alert.confidence, format: .fixed(precision: 2)) " +
            "action=\(String(describing: alert.recommendation))"
        )
        return alert
    }

    // MARK: - Entropy

    private func calculateEntropy(data: Data) -> Double {
        var freq = [UInt8: Int]()
        for byte in data { freq[byte, default: 0] += 1 }
        let len = Double(data.count)
        var entropy = 0.0
        for (_, count) in freq {
            let p = Double(count) / len
            if p > 0 { entropy -= p * log2(p) }
        }
        return entropy
    }

    // MARK: - Known Patterns

    private let knownRansomwareExtensions: Set<String> = [
        "locked", "encrypted", "crypto", "crypt", "enc",
        "locky", "cerber", "zepto", "odin", "aesir", "thor", "zzzzz",
        "micro", "xtbl", "wallet", "dharma", "onion", "wncry",
    ]

    private let ransomNotePatterns: [String] = [
        "readme", "decrypt", "restore", "recover",
        "how_to", "howto", "ransom", "help_decrypt",
        "your_files", "attention", "warning",
    ]
}

// MARK: - CanaryFileManager

/// Plants invisible decoy files in common user directories.
/// Any access to a canary is a strong ransomware signal.
final class CanaryFileManager {

    private static let logger = Logger(
        subsystem: "com.ehsanazish.nick.NickExtension",
        category: "CanaryFileManager"
    )

    private(set) var canaryPaths: Set<String> = []

    private let canaryLocations = [
        "~/Desktop",
        "~/Documents",
        "~/Downloads",
        "~/Pictures",
    ]

    // MARK: - Public API

    /// Creates hidden canary files in each location.
    /// Safe to call multiple times — skips directories where a canary already exists.
    func deployCanaries() {
        for location in canaryLocations {
            let expanded = NSString(string: location).expandingTildeInPath
            let canaryPath = "\(expanded)/.~nick_canary_\(UUID().uuidString.prefix(8)).tmp"

            // Skip if we already have a canary in this directory
            let dirAlreadyProtected = canaryPaths.contains(where: {
                ($0 as NSString).deletingLastPathComponent == expanded
            })
            guard !dirAlreadyProtected else { continue }

            let content = "NICK_CANARY_DO_NOT_MODIFY_\(Date())"
            guard (try? content.write(toFile: canaryPath, atomically: true, encoding: .utf8)) != nil
            else { continue }

            // Mark resource as hidden via URL resource values
            var url = URL(fileURLWithPath: canaryPath)
            var values = URLResourceValues()
            values.isHidden = true
            try? url.setResourceValues(values)

            canaryPaths.insert(canaryPath)
            Self.logger.info("Canary deployed: \(canaryPath)")
        }
    }

    /// Returns `true` if `path` is a managed canary file.
    func isCanary(path: String) -> Bool {
        canaryPaths.contains(path)
    }

    /// Removes all canary files from disk and clears the set.
    func removeCanaries() {
        for path in canaryPaths {
            try? FileManager.default.removeItem(atPath: path)
        }
        canaryPaths.removeAll()
        Self.logger.info("All canaries removed")
    }
}
