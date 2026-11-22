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
    static let maximumFilesPerMount = 50_000

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
    func handleMount(volumePath: String, diagnosticID: UInt64? = nil) {
        USBMountDiagnostics.shared.update(diagnosticID, stage: "handler-entered")
        guard isExternalVolumePath(volumePath, diagnosticID: diagnosticID) else { return }

        lock.withLock { _ = mountedVolumes.insert(volumePath) }
        Self.logger.notice("External volume mounted — starting background scan: \(volumePath)")

        USBMountDiagnostics.shared.update(diagnosticID, stage: "queued")
        DispatchQueue.global(qos: .utility).async { [weak self] in
            guard let self else {
                USBMountDiagnostics.shared.update(diagnosticID, stage: "scanner-deallocated", finished: true)
                return
            }
            USBMountDiagnostics.shared.update(diagnosticID, stage: "worker-entered")
            self.scanVolume(path: volumePath, diagnosticID: diagnosticID)
        }
    }

    func handleUnmount(volumePath: String) {
        lock.withLock { _ = mountedVolumes.remove(volumePath) }
        Self.logger.info("Volume unmounted — cancelling scan: \(volumePath)")
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

    private func scanVolume(path: String, diagnosticID: UInt64?) {
        USBMountDiagnostics.shared.update(diagnosticID, stage: "enumerator-requested")
        let fm = FileManager.default
        // Hidden files are included: removable-media payloads usually hide.
        // Only content that can run is hashed and YARA-scanned, so a photo or
        // video drive no longer costs hundreds of gigabytes of reads.
        guard let enumerator = fm.enumerator(
            at: URL(fileURLWithPath: path),
            includingPropertiesForKeys: [.isRegularFileKey, .fileSizeKey, .isSymbolicLinkKey,
                                         .isDirectoryKey, .isExecutableKey],
            options: []
        ) else {
            USBMountDiagnostics.shared.update(diagnosticID, stage: "enumerator-unavailable", finished: true)
            Self.logger.warning("Cannot enumerate volume: \(path)")
            return
        }

        USBMountDiagnostics.shared.update(diagnosticID, stage: "enumerator-ready")
        var scannedCount = 0
        var enumeratedCount = 0
        let diagnosticRun = ScanWorkDiagnostics.shared.usbStarted()
        var endReason = "enumeration-ended" // No error handler: not proof of complete traversal.
        USBMountDiagnostics.shared.update(diagnosticID, stage: "scan-started", fields: ["usbRunID": diagnosticRun.map { $0 as Any } ?? NSNull()])
        defer {
            ScanWorkDiagnostics.shared.usbProgress(diagnosticRun, enumerated: enumeratedCount, scanned: scannedCount, finished: true)
            USBMountDiagnostics.shared.update(diagnosticID, stage: "scan-ended", finished: true,
                fields: ["endReason": endReason, "enumerated": enumeratedCount, "scanned": scannedCount])
        }
        var threatsFound = 0

        for case let fileURL as URL in enumerator {
            enumeratedCount += 1
            if enumeratedCount % 256 == 0 {
                ScanWorkDiagnostics.shared.usbProgress(diagnosticRun, enumerated: enumeratedCount, scanned: scannedCount)
            }
            let stillMounted = isMounted(volumePath: path)
            guard stillMounted, scannedCount < Self.maximumFilesPerMount else {
                endReason = stillMounted ? "scanned-file-cap" : "unmounted"
                Self.logger.info("USB scan stopped or reached its file limit: \(path)")
                break
            }
            guard let rv = try? fileURL.resourceValues(forKeys: [.isRegularFileKey,
                                                                  .fileSizeKey,
                                                                  .isSymbolicLinkKey,
                                                                  .isDirectoryKey,
                                                                  .isExecutableKey])
            else { continue }
            if rv.isDirectory == true {
                if Self.skippedDirectoryNames.contains(fileURL.lastPathComponent) {
                    enumerator.skipDescendants()
                }
                continue
            }
            guard rv.isRegularFile == true, rv.isSymbolicLink != true else { continue }

            // Skip oversized and empty files
            let fileSize = rv.fileSize ?? 0
            guard fileSize > 0, fileSize <= Self.scanSizeLimit else { continue }

            let filePath = fileURL.path
            guard Self.isScanCandidate(path: filePath, isExecutable: rv.isExecutable == true) else { continue }
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

    /// Volume bookkeeping directories that never hold user payloads.
    private static let skippedDirectoryNames: Set<String> = [
        ".Spotlight-V100", ".fseventsd", ".Trashes", ".DocumentRevisions-V100", ".TemporaryItems",
    ]

    /// Extensions that carry executable or installable content even when the
    /// header alone is ambiguous (for example disk images and archives).
    private static let riskyExtensions: Set<String> = [
        "app", "command", "sh", "zsh", "py", "scpt", "applescript", "terminal", "workflow",
        "pkg", "mpkg", "dmg", "iso", "zip", "jar", "exe", "dll", "bat", "cmd", "ps1", "vbs", "js", "lnk",
        "docm", "xlsm", "pptm",
    ]

    static func isScanCandidate(path: String, isExecutable: Bool) -> Bool {
        if isExecutable { return true }
        let ext = (path as NSString).pathExtension.lowercased()
        if riskyExtensions.contains(ext) { return true }
        // Reading 16 bytes is cheap compared with hashing every media file.
        guard ext.isEmpty || !mediaExtensions.contains(ext) else { return false }
        return ScanCandidatePolicy.isExecutableContent(ScanCandidatePolicy.kind(atPath: path))
    }

    private static let mediaExtensions: Set<String> = [
        "jpg", "jpeg", "png", "heic", "heif", "gif", "tif", "tiff", "raw", "cr2", "cr3", "nef", "arw", "dng",
        "mp4", "mov", "m4v", "avi", "mkv", "mts", "mp3", "m4a", "wav", "aif", "aiff", "flac",
        "pdf", "txt", "csv", "json", "xml", "html", "docx", "xlsx", "pptx", "pages", "numbers", "key",
    ]

    private func isMounted(volumePath: String) -> Bool {
        lock.withLock { mountedVolumes.contains(volumePath) }
    }

    /// Returns `true` only for a local removable/ejectable volume. Network
    /// shares often mount under `/Volumes` too and must not trigger a full scan.
    private func isExternalVolumePath(_ path: String, diagnosticID: UInt64?) -> Bool {
        guard path.hasPrefix("/Volumes/") else {
            USBMountDiagnostics.shared.update(diagnosticID, stage: "rejected-path-prefix", finished: true)
            return false
        }
        let keys: Set<URLResourceKey> = [
            .volumeIsLocalKey, .volumeIsRemovableKey, .volumeIsEjectableKey
        ]
        USBMountDiagnostics.shared.update(diagnosticID, stage: "metadata-requested")
        let values: URLResourceValues
        do {
            values = try URL(fileURLWithPath: path).resourceValues(forKeys: keys)
        } catch {
            let nsError = error as NSError
            USBMountDiagnostics.shared.update(diagnosticID, stage: "rejected-metadata-error", finished: true,
                fields: ["errorDomain": String(nsError.domain.prefix(80)), "errorCode": nsError.code])
            return false
        }
        let metadata: [String: Any] = [
            "volumeIsLocal": values.volumeIsLocal.map { $0 as Any } ?? NSNull(),
            "volumeIsRemovable": values.volumeIsRemovable.map { $0 as Any } ?? NSNull(),
            "volumeIsEjectable": values.volumeIsEjectable.map { $0 as Any } ?? NSNull()]
        USBMountDiagnostics.shared.update(diagnosticID, stage: "metadata-returned", fields: metadata)
        guard values.volumeIsLocal == true,
              values.volumeIsRemovable == true || values.volumeIsEjectable == true else {
            USBMountDiagnostics.shared.update(diagnosticID, stage: "rejected-volume-properties", finished: true)
            return false
        }
        let name = String(path.dropFirst("/Volumes/".count))
            .components(separatedBy: "/").first ?? ""
        let exclude: Set<String> = ["Macintosh HD", "Macintosh HD - Data", ""]
        guard !exclude.contains(name) else {
            USBMountDiagnostics.shared.update(diagnosticID, stage: "rejected-boot-alias", finished: true)
            return false
        }
        USBMountDiagnostics.shared.update(diagnosticID, stage: "eligible")
        return true
    }
}
