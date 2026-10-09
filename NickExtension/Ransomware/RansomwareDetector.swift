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
/// Confidence ≥ 0.8 plus ransomware-specific evidence → `.block`
/// (kill + quarantine immediately). Entropy or write volume alone never blocks.
/// Confidence 0.5–0.8 → `.alert` (alert user; do not freeze a process on heuristics alone)
/// Confidence < 0.5 → `.monitor` (continue watching)
final class RansomwareDetector {

    // MARK: - Types

    struct RansomwareAlert {
        struct RenameBurst {
            let newExtension: String
            let fileCount: Int
            let directoryCount: Int
            let windowSeconds: Int
        }
        let pid: Int32
        let processPath: String
        let indicators: [String]
        let confidence: Double
        /// True only when evidence is specific enough to justify terminating
        /// the writer without waiting for user review.
        let automaticBlockAllowed: Bool
        let renameBurst: RenameBurst?

        enum Recommendation {
            case block      // high confidence — kill and quarantine now
            case alert      // medium confidence — prompt user without freezing the app
            case monitor    // low confidence — keep watching
        }
        var recommendation: Recommendation {
            switch confidence {
            case 0.8... where automaticBlockAllowed: return .block
            case 0.5...:     return .alert
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

    /// Content entropy can only strengthen a ransomware-specific signal; it
    /// never creates one by itself. Use this cheap path-only check before
    /// reading file contents from the real-time event stream.
    func needsContentSample(filePath: String) -> Bool {
        if canaryManager.isCanary(path: filePath) {
            return true
        }
        let path = filePath as NSString
        let ext = path.pathExtension.lowercased()
        if !ext.isEmpty && knownRansomwareExtensions.contains(ext) {
            return true
        }
        return Self.isLikelyRansomNote(path.lastPathComponent)
    }

    /// Evaluates a file-write event for ransomware signals.
    ///
    /// - Parameters:
    ///   - pid: PID of the writing process.
    ///   - processPath: Executable path of the writing process.
    ///   - filePath: Path of the file being written.
    ///   - fileData: Contents written (pass `nil` if unavailable — entropy check skipped).
    /// - Returns: A `RansomwareAlert` when one or more signals fire, `nil` if clean.
    func evaluate(pid: Int32, processPath: String,
                  filePath: String, fileData: Data?,
                  actorIsPlatformBinary: Bool = false,
                  actorHasTrustedSigner: Bool = false) -> RansomwareAlert? {
        var indicators: [String] = []
        var confidence = 0.0
        var hasRansomwareSpecificIndicator = false
        var canaryTouched = false
        var familyExtensionObserved = false
        var ransomNoteObserved = false

        // 1. Canary file touched. Apple platform processes (iCloud Drive's
        //    file provider, Spotlight, backup) legitimately rewrite files in
        //    synced folders and must never trigger an automatic block.
        if !actorIsPlatformBinary, canaryManager.isCanary(path: filePath) {
            indicators.append("Canary file touched: \(filePath)")
            confidence += 0.6
            hasRansomwareSpecificIndicator = true
            canaryTouched = true
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
        let path = filePath as NSString
        let ext = path.pathExtension.lowercased()
        if !ext.isEmpty && knownRansomwareExtensions.contains(ext) {
            indicators.append("Known ransomware extension: .\(ext)")
            confidence += 0.4
            hasRansomwareSpecificIndicator = true
            familyExtensionObserved = true
        }

        // 4. Ransom note filename
        let filename = path.lastPathComponent.lowercased()
        if Self.isLikelyRansomNote(filename) {
            indicators.append("Ransom note: \(filename)")
            confidence += 0.5
            hasRansomwareSpecificIndicator = true
            ransomNoteObserved = true
        }

        // 5. Behavioural analysis
        let behavior = behaviorTracker.analyze(pid: pid)
        if behavior.isSuspicious {
            indicators.append(contentsOf: behavior.indicators)
            confidence += behavior.score * 0.3
        }

        // Entropy and write bursts are common for browsers, databases, build
        // tools, and chat applications. They may raise confidence for a
        // ransomware-specific observation, but must never create an alert by
        // themselves.
        guard hasRansomwareSpecificIndicator else { return nil }

        let alert = RansomwareAlert(
            pid:         pid,
            processPath: processPath,
            indicators:  indicators,
            confidence:  min(confidence, 1.0),
            // Sync clients (Dropbox, OneDrive, Google Drive) are identity-signed
            // and legitimately rewrite synced canaries; they get a prompt, not
            // an automatic kill.
            automaticBlockAllowed: !actorHasTrustedSigner && (canaryTouched
                || (behavior.isSuspicious && (familyExtensionObserved || ransomNoteObserved))),
            renameBurst: nil
        )

        Self.logger.notice(
            "Ransomware alert pid=\(pid) confidence=\(alert.confidence, format: .fixed(precision: 2)) action=\(String(describing: alert.recommendation))"
        )
        return alert
    }

    /// Evaluates a completed rename.
    ///
    /// Rename-based ransomware writes ciphertext and then renames the file to
    /// a new extension; it may never modify a file under a ransomware-specific
    /// name, so `evaluate` alone never fired for it. A burst of renames that
    /// introduce the same uncommon extension across several files is
    /// ransomware-specific evidence on its own.
    func evaluateRename(
        pid: Int32,
        processPath: String,
        source: String,
        destination: String,
        actorIsPlatformBinary: Bool,
        actorHasTrustedSigner: Bool = false,
        ignoreBrowserDownloadDestination: Bool = false
    ) -> RansomwareAlert? {
        guard !actorIsPlatformBinary else { return nil }
        guard !ignoreBrowserDownloadDestination else { return nil }
        var indicators: [String] = []
        var confidence = 0.0
        var canaryTouched = false
        var strongEvidence = false

        if canaryManager.isCanary(path: source) {
            indicators.append("Canary file renamed: \(source)")
            confidence += 0.6
            canaryTouched = true
        }

        let destinationExtension = (destination as NSString).pathExtension.lowercased()
        if !destinationExtension.isEmpty, knownRansomwareExtensions.contains(destinationExtension) {
            indicators.append("Known ransomware extension: .\(destinationExtension)")
            confidence += 0.4
            strongEvidence = true
        }

        let observedBurst = behaviorTracker.extensionChangeBurst(pid: pid)
        if let burst = observedBurst,
           burst.fileCount >= Self.extensionBurstThreshold {
            indicators.append(
                "Mass extension change to .\(burst.newExtension): \(burst.fileCount) files in \(burst.directoryCount) folder(s)"
            )
            confidence += burst.fileCount >= Self.extensionBurstThreshold * 3 ? 0.6 : 0.5
            strongEvidence = strongEvidence || burst.directoryCount >= 2
        }

        guard canaryTouched || !indicators.isEmpty else { return nil }
        let alert = RansomwareAlert(
            pid: pid,
            processPath: processPath,
            indicators: indicators,
            confidence: min(confidence, 1.0),
            // A rename burst alone prompts the user; combined with a canary or a
            // known family extension it justifies stopping the writer.
            automaticBlockAllowed: !actorHasTrustedSigner
                && (canaryTouched || (strongEvidence && confidence >= 0.9)),
            renameBurst: observedBurst.map {
                .init(newExtension: $0.newExtension, fileCount: $0.fileCount,
                      directoryCount: $0.directoryCount, windowSeconds: 10)
            }
        )
        Self.logger.notice(
            "Ransomware rename alert pid=\(pid) confidence=\(alert.confidence, format: .fixed(precision: 2)) action=\(String(describing: alert.recommendation))"
        )
        return alert
    }

    /// Files renamed to one new extension within the burst window before the
    /// pattern counts as mass encryption.
    static let extensionBurstThreshold = 8

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

    /// Family extensions. Modern families mostly use per-victim random
    /// extensions, which the extension-burst heuristic covers; these add
    /// confidence when a known one appears.
    private let knownRansomwareExtensions: Set<String> = [
        // macOS families
        "turtle", "lockbit", "encrypted_by_lockbit",
        // Distinctive cross-platform family extensions. Generic words that
        // real applications use as file formats (e.g. "encrypted", "hive",
        // "wallet") are deliberately excluded: an extension match alone
        // raises an alert on file close.
        "locky", "cerber", "zepto", "odin", "aesir", "zzzzz",
        "xtbl", "dharma", "wncry", "wnry", "ryk", "akira", "rhysida",
    ]

    /// Ransom-note matching must be deliberately narrow. Common words such as
    /// "readme", "recovery", "warning", and "ransomware" occur constantly in
    /// developer projects and normal applications; substring matching them
    /// caused event storms while Xcode was compiling Nick itself.
    static func isLikelyRansomNote(_ filename: String) -> Bool {
        RansomwareNotePolicy.matches(filename: filename)
    }
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

    private let homeDirectories: [URL]
    private let installationToken: String
    private let protectedFolderNames = ["Desktop", "Documents", "Downloads", "Pictures"]

    init(
        homeDirectories: [URL] = UserHomeDirectoryResolver.humanHomeDirectories(),
        tokenURL: URL = URL(fileURLWithPath: "/Library/Application Support/com.ehsanazish.nick/state/canary-token")
    ) {
        self.homeDirectories = homeDirectories
        self.installationToken = Self.loadOrCreateInstallationToken(at: tokenURL)
    }

    // MARK: - Public API

    /// Creates hidden canary files in each location.
    /// Safe to call multiple times — skips directories where a canary already exists.
    func deployCanaries() {
        for homeDirectory in homeDirectories {
            for folderName in protectedFolderNames {
                let directory = homeDirectory.appendingPathComponent(folderName, isDirectory: true)
                guard FileManager.default.fileExists(atPath: directory.path) else { continue }

                // Adopt canaries from an earlier extension process. The
                // in-memory set is rebuilt on every launch, but the files are
                // deliberately persistent. Legacy dot-file canaries stay
                // registered alongside the document canary.
                let existingNames = (try? FileManager.default.contentsOfDirectory(atPath: directory.path)) ?? []
                for name in existingNames where isManagedCanaryName(name) {
                    canaryPaths.insert(directory.appendingPathComponent(name).path)
                }
                guard !existingNames.contains(where: isManagedDocumentCanaryName) else { continue }

                // Ransomware typically skips dot-files and only encrypts known
                // document and image extensions, so the canary is a visible
                // name with a targeted extension, hidden from Finder by flag.
                let ext = folderName == "Pictures" ? "jpg" : "docx"
                let canaryPath = directory
                    .appendingPathComponent(".\(installationToken)-\(UUID().uuidString.prefix(8)).\(ext)")
                    .path

                let content = "NICK_CANARY_DO_NOT_MODIFY_\(Date())"
                guard (try? content.write(toFile: canaryPath, atomically: true, encoding: .utf8)) != nil
                else { continue }

                // Mark resource as hidden via URL resource values.
                var url = URL(fileURLWithPath: canaryPath)
                var values = URLResourceValues()
                values.isHidden = true
                try? url.setResourceValues(values)

                canaryPaths.insert(canaryPath)
                Self.logger.info("Canary deployed: \(canaryPath)")
            }
        }
    }

    /// Returns `true` if `path` is a managed canary file.
    func isCanary(path: String) -> Bool {
        if canaryPaths.contains(path) {
            return true
        }
        return isManagedCanaryName((path as NSString).lastPathComponent)
    }

    static let documentCanaryPrefix = "Nick Canary - do not modify "

    static func isDocumentCanaryName(_ name: String) -> Bool {
        name.hasPrefix(documentCanaryPrefix)
    }

    static func isCanaryName(_ name: String) -> Bool {
        isDocumentCanaryName(name) || (name.hasPrefix(".~nick_canary_") && name.hasSuffix(".tmp"))
    }

    private func isManagedDocumentCanaryName(_ name: String) -> Bool {
        name.hasPrefix(".\(installationToken)-")
            && ["docx", "jpg"].contains((name as NSString).pathExtension.lowercased())
    }

    private func isManagedCanaryName(_ name: String) -> Bool {
        isManagedDocumentCanaryName(name) || Self.isCanaryName(name)
    }

    private static func loadOrCreateInstallationToken(at url: URL) -> String {
        if let existing = try? String(contentsOf: url, encoding: .utf8)
            .trimmingCharacters(in: .whitespacesAndNewlines),
           existing.count == 24 {
            return existing
        }
        let token = UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased().prefix(24)
        do {
            try FileManager.default.createDirectory(
                at: url.deletingLastPathComponent(),
                withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o700]
            )
            try Data(token.utf8).write(to: url, options: .atomic)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
        } catch {
            Self.logger.error("Could not persist randomized canary token: \(error.localizedDescription, privacy: .public)")
        }
        return String(token)
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
