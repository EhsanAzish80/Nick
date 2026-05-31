// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation
import os

// MARK: - USBScanner

/// Scans external/removable volumes for malware when they are mounted.
///
/// **Detection flow:**
/// 1. `ES_EVENT_TYPE_NOTIFY_MOUNT` fires when a volume is mounted.
/// 2. `USBScanner.handleMount(volumePath:)` checks whether the volume is
///    external (path starts with `/Volumes/` and isn't the boot volume).
/// 3. A background utility-priority scan enumerates the volume, skipping
///    directories, symlinks, and files larger than `scanSizeLimit`.
/// 4. Any file that produces a threat result from `FileScanner.scan` is
///    reported via `onThreatFound`.
///
/// **Integration:**
/// ```swift
/// usbScanner = USBScanner(fileScanner: fileScanner)
/// usbScanner.onThreatFound = { [weak self] threat in
///     if let data = try? JSONEncoder().encode(threat) {
///         self?.xpcServer?.sendUSBThreatToApp(data)
///     }
/// }
/// ```
final class USBScanner {

    // MARK: - Configuration

    /// Files larger than this limit are skipped during background volume scans.
    static let scanSizeLimit: Int = 100 * 1_024 * 1_024  // 100 MB

    // MARK: - Public

    /// Called on a background queue whenever a threat is found on an external volume.
    var onThreatFound: ((USBThreat) -> Void)?

    // MARK: - Private

    private static let logger = Logger(
        subsystem: "com.ehsanazish.nick.NickExtension",
        category: "USBScanner"
    )

    private let fileScanner: FileScanner

    /// Tracks mounted external volumes to enable quick containment checks.
    private var mountedVolumes: Set<String> = []
    private let lock = NSLock()

    // MARK: - Init

    init(fileScanner: FileScanner) {
        self.fileScanner = fileScanner
    }

    // MARK: - Mount Event Handler

    /// Called from `EventHandler` on every `ES_EVENT_TYPE_NOTIFY_MOUNT` event.
    ///
    /// If the volume is external, a background scan is started immediately.
    /// Safe to call from the ES callback queue — the scan itself is dispatched
    /// asynchronously and the mount point string is captured by value.
    func handleMount(volumePath: String) {
        guard isExternalVolumePath(volumePath) else { return }

        lock.withLock { mountedVolumes.insert(volumePath) }
        Self.logger.notice("External volume mounted — starting background scan: \(volumePath)")

        DispatchQueue.global(qos: .utility).async { [weak self] in
            self?.scanVolume(path: volumePath)
        }
    }

    /// Returns `true` if `filePath` is on a mounted external volume.
    ///
    /// Used by `EventHandler` to apply extra scrutiny to files being opened or
    /// executed from removable media.
    func isExternalVolume(_ path: String) -> Bool {
        lock.withLock {
            mountedVolumes.contains(where: { path.hasPrefix($0) })
        }
    }

    // MARK: - Private Helpers

    private func scanVolume(path: String) {
        let fm = FileManager.default
        guard let enumerator = fm.enumerator(
            at: URL(fileURLWithPath: path),
            includingPropertiesForKeys: [.isRegularFileKey, .fileSizeKey, .isSymbolicLinkKey],
            options: [.skipsHiddenFiles]
        ) else {
            Self.logger.warning("Cannot enumerate volume: \(path)")
            return
        }

        var scannedCount = 0
        var threatsFound = 0

        for case let fileURL as URL in enumerator {
            guard let rv = try? fileURL.resourceValues(forKeys: [.isRegularFileKey,
                                                                  .fileSizeKey,
                                                                  .isSymbolicLinkKey]),
                  rv.isRegularFile == true,
                  rv.isSymbolicLink != true
            else { continue }

            // Skip oversized files
            let fileSize = rv.fileSize ?? 0
            guard fileSize <= Self.scanSizeLimit else { continue }

            let filePath = fileURL.path
            let result = fileScanner.scan(filePath: filePath)
            scannedCount += 1

            if result.isThreat {
                threatsFound += 1
                let threat = USBThreat(
                    id:           UUID(),
                    timestamp:    Date(),
                    volumePath:   path,
                    filePath:     filePath,
                    threatName:   result.threatName,
                    threatFamily: result.threatFamily,
                    sha256:       result.hash.isEmpty ? nil : result.hash
                )
                Self.logger.warning(
                    "USB threat found: \(result.threatName ?? "unknown") at \(filePath)"
                )
                onThreatFound?(threat)
            }
        }

        Self.logger.info(
            "USB scan complete — \(path): \(scannedCount) file(s) scanned, \(threatsFound) threat(s)"
        )
    }

    /// Returns `true` for paths under `/Volumes/` that are not the boot disk.
    ///
    /// This heuristic avoids scanning Time Machine, network shares that mount at
    /// `/Volumes/`, or the boot volume itself.
    private func isExternalVolumePath(_ path: String) -> Bool {
        guard path.hasPrefix("/Volumes/") else { return false }
        // Exclude boot disk aliases (typically "/Volumes/Macintosh HD" → "/"
        // but may also appear under /Volumes/)
        let name = String(path.dropFirst("/Volumes/".count))
            .components(separatedBy: "/").first ?? ""
        let exclude: Set<String> = ["Macintosh HD", "Macintosh HD - Data", ""]
        return !exclude.contains(name)
    }
}
