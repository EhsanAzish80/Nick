// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation
import os

// MARK: - EmailAttachmentMonitor

/// Phase 6.5 — Email attachment threat detection.
///
/// When `ES_EVENT_TYPE_NOTIFY_CLOSE` fires, `EventHandler` calls
/// `source(forPath:)`. If the file is inside a known mail-app directory this
/// returns the source name (e.g. "Apple Mail"), signalling that a deep-scan
/// result should carry email-source attribution in the UI.
///
/// `isDangerousExtension(_:)` flags executable and macro-enabled file types
/// even when the signature database has no match, providing zero-day coverage
/// for dangerous attachment types commonly weaponised in email campaigns.
final class EmailAttachmentMonitor: @unchecked Sendable {

    // MARK: - Types

    /// Attribution for a suspicious email attachment event.
    struct AttachmentEvent: Sendable {
        /// Absolute path to the file that was written.
        let filePath: String
        /// Mail client that owns the directory (e.g. "Apple Mail").
        let source: String
        /// Whether the file extension alone is considered high-risk.
        let isDangerousExtension: Bool
        let timestamp: Date
    }

    // MARK: - Private

    /// Mail-app directories and their human-readable source names.
    /// Paths are relative to `NSHomeDirectory()` and matched via `contains`.
    private let emailPaths: [(path: String, source: String)] = [
        ("Library/Mail/",                                           "Apple Mail"),
        ("Library/Group Containers/UBF8T346G9.Office/Outlook/",    "Outlook"),
        ("Library/Containers/com.microsoft.Outlook/",              "Outlook"),
        ("Library/Containers/com.apple.mail/",                     "Apple Mail"),
    ]

    /// File extensions that should always be treated as high-risk when
    /// arriving via email, even without a signature-database match.
    private let dangerousExtensions: Set<String> = [
        // Windows executables (frequently mailed as malware)
        "exe", "scr", "bat", "cmd", "pif", "com",
        // Script files
        "js", "jse", "vbs", "vbe", "wsf", "wsh", "ps1",
        // macOS executables and installers
        "app", "command", "action", "dmg", "pkg", "mpkg",
        // Macro-enabled Office documents
        "docm", "xlsm", "pptm", "dotm", "xlam",
    ]

    private static let logger = Logger(
        subsystem: "com.ehsanazish.nick",
        category: "EmailAttachmentMonitor"
    )

    // MARK: - Public API

    /// Returns the mail-client name if `filePath` is inside a mail-app
    /// directory, or `nil` if it is not an email-sourced file.
    func source(forPath filePath: String) -> String? {
        for (path, source) in emailPaths {
            if filePath.contains(path) { return source }
        }
        return nil
    }

    /// Returns `true` if the file extension is inherently dangerous when
    /// delivered via email, regardless of signature-database status.
    func isDangerousExtension(_ filePath: String) -> Bool {
        let ext = (filePath as NSString).pathExtension.lowercased()
        return dangerousExtensions.contains(ext)
    }

    /// Convenience method called from `ES_EVENT_TYPE_NOTIFY_CLOSE` handler.
    ///
    /// - Returns: An `AttachmentEvent` when the file is from a mail client,
    ///   `nil` otherwise.
    func evaluate(filePath: String) -> AttachmentEvent? {
        guard let source = source(forPath: filePath) else { return nil }
        let dangerous = isDangerousExtension(filePath)
        Self.logger.info("Email attachment detected from \(source): \(filePath.lastPathComponent)")
        return AttachmentEvent(
            filePath: filePath,
            source: source,
            isDangerousExtension: dangerous,
            timestamp: Date()
        )
    }
}

// MARK: - String Helper

private extension String {
    var lastPathComponent: String { (self as NSString).lastPathComponent }
}
