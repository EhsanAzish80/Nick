// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation
import os

// MARK: - PrivacyGuard

/// Translates `ES_EVENT_TYPE_NOTIFY_TCC_MODIFY` events into `PrivacyAlert` values.
///
/// **What it monitors:**
/// TCC (Transparency, Consent, and Control) is macOS's privacy gate for camera,
/// microphone, full-disk access, accessibility, and more. Malware routinely
/// manipulates or silently triggers TCC grants to access sensitive resources.
/// `PrivacyGuard` alerts on any change to a sensitive TCC service — even if the
/// change was initiated by a legitimate prompt — so Nick can surface it to the user.
///
/// **Usage:**
/// ```swift
/// let guard = PrivacyGuard()
/// // In EventHandler.handle(message:) for ES_EVENT_TYPE_NOTIFY_TCC_MODIFY:
/// if let alert = guard.handleTCCChange(service: …, appBundleID: …,
///                                      appPath: …, accessGranted: …) {
///     xpcServer?.sendPrivacyAlertToApp(data)
/// }
/// ```
final class PrivacyGuard {

    // MARK: - Private State

    private static let logger = Logger(
        subsystem: "com.ehsanazish.nick.NickExtension",
        category: "PrivacyGuard"
    )

    /// TCC service strings we consider sensitive enough to surface in the UI.
    private let sensitiveServices: Set<String> = [
        "kTCCServiceCamera",
        "kTCCServiceMicrophone",
        "kTCCServiceScreenCapture",
        "kTCCServiceAccessibility",
        "kTCCServiceSystemPolicyAllFiles",
        "kTCCServiceAddressBook",
        "kTCCServiceCalendar",
        "kTCCServiceReminders",
        "kTCCServicePhotos",
        "kTCCServiceMediaLibrary",
        "kTCCServiceLocation",
        "kTCCServiceListenEvent",
        "kTCCServicePostEvent",
        "kTCCServiceScreenRecognition",
    ]

    /// Human-readable mapping for UI display.
    private let serviceNames: [String: String] = [
        "kTCCServiceCamera":              "Camera",
        "kTCCServiceMicrophone":          "Microphone",
        "kTCCServiceScreenCapture":       "Screen Recording",
        "kTCCServiceAccessibility":       "Accessibility",
        "kTCCServiceSystemPolicyAllFiles": "Full Disk Access",
        "kTCCServiceAddressBook":         "Contacts",
        "kTCCServiceCalendar":            "Calendar",
        "kTCCServiceReminders":           "Reminders",
        "kTCCServicePhotos":              "Photos",
        "kTCCServiceMediaLibrary":        "Media & Apple Music",
        "kTCCServiceLocation":            "Location",
        "kTCCServiceListenEvent":         "Input Monitoring",
        "kTCCServicePostEvent":           "Accessibility (Post Events)",
        "kTCCServiceScreenRecognition":   "Screen Recognition",
    ]

    // MARK: - Public API

    /// Processes a TCC permission change and returns a `PrivacyAlert` if the
    /// changed service is considered sensitive.
    ///
    /// - Parameters:
    ///   - service:       The raw TCC service string (e.g., `"kTCCServiceCamera"`).
    ///   - appBundleID:   Bundle identifier or signing ID of the app.
    ///   - appPath:       Absolute path to the app binary.
    ///   - accessGranted: `true` if the permission was granted; `false` if revoked.
    /// - Returns: A `PrivacyAlert` to push to the container app, or `nil` if the
    ///   service is not in the sensitive set.
    func handleTCCChange(service: String,
                         appBundleID: String,
                         appPath: String,
                         accessGranted: Bool) -> PrivacyAlert? {
        guard sensitiveServices.contains(service) else { return nil }

        let friendly = serviceNames[service] ?? service
        Self.logger.notice(
            "TCC change: \(friendly) \(accessGranted ? "granted to" : "revoked from") \(appBundleID)"
        )

        return PrivacyAlert(
            id:           UUID(),
            timestamp:    Date(),
            service:      friendly,
            appBundleID:  appBundleID,
            appPath:      appPath,
            changeType:   accessGranted ? .granted : .revoked
        )
    }
}
