// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import UserNotifications
import AppKit
import os

// MARK: - NotificationManager

/// Manages system notification delivery for `ThreatAlert` events.
///
/// Registers a `THREAT_ALERT` category with a "View in Nick" foreground action
/// so users can navigate directly to the dashboard from a notification banner.
///
/// **Usage:**
/// ```swift
/// // At app startup:
/// NotificationManager.shared.setup()
///
/// // When a new alert fires:
/// await NotificationManager.shared.send(for: alert)
/// ```
///
/// **Filtering rules:**
/// - `.info` severity alerts are always suppressed (trusted-app activity).
/// - Alerts below the user's configured threshold (`notificationThresholdRaw`) are suppressed.
@MainActor
final class NotificationManager: NSObject, UNUserNotificationCenterDelegate {

    // MARK: - Singleton

    /// Shared instance — created once and retained for the app lifetime.
    static let shared = NotificationManager()

    // MARK: - Private

    private static let log = Logger(
        subsystem: "com.ehsanazish.nick",
        category: "NotificationManager"
    )

    private override init() {
        super.init()
    }

    // MARK: - Setup

    /// Registers notification categories and requests user permission.
    ///
    /// Safe to call multiple times — category registration and delegate
    /// assignment are both idempotent.
    func setup() {
        let viewAction = UNNotificationAction(
            identifier: "VIEW_ALERT",
            title: "View in Nick",
            options: [.foreground]
        )
        let alertCategory = UNNotificationCategory(
            identifier: "THREAT_ALERT",
            actions: [viewAction],
            intentIdentifiers: [],
            options: []
        )
        let center = UNUserNotificationCenter.current()
        center.setNotificationCategories([alertCategory])
        center.delegate = self

        Task {
            let settings = await center.notificationSettings()
            switch settings.authorizationStatus {
            case .denied:
                Self.log.info("Notification permission denied — skipping request, alerts will be silent")
            case .notDetermined:
                do {
                    let granted = try await center.requestAuthorization(options: [.alert, .sound])
                    Self.log.info("Notification permission: \(granted ? "granted" : "denied")")
                } catch {
                    Self.log.warning("Notification authorisation request failed: \(error.localizedDescription)")
                }
            default:
                Self.log.debug("Notification permission already set: \(settings.authorizationStatus.rawValue)")
            }
        }
    }

    // MARK: - Delivery

    /// Posts a system notification banner for the given alert.
    ///
    /// - Parameter alert: The correlated threat alert to notify about.
    ///
    /// Silently returns when `alert.severity == .info` (trusted-app activity) or
    /// when the alert's severity is below the user-configured threshold.
    func send(for alert: ThreatAlert) async {
        guard alert.severity != .info else { return }

        let thresholdRaw = UserDefaults.standard.integer(forKey: "notificationThresholdRaw")
        let threshold = SignalSeverity(rawValue: thresholdRaw) ?? .high
        guard alert.severity >= threshold else {
            Self.log.debug("Alert '\(alert.title)' below threshold (\(threshold.displayName)) — suppressed")
            return
        }

        let content = UNMutableNotificationContent()
        content.title = "Nick — \(alert.severity.displayName) Alert"
        content.body = alert.title
        content.sound = alert.severity >= .high ? .defaultCritical : .default
        content.categoryIdentifier = "THREAT_ALERT"
        content.userInfo = ["alertID": alert.id.uuidString]

        let request = UNNotificationRequest(
            identifier: alert.id.uuidString,
            content: content,
            trigger: nil
        )

        do {
            try await UNUserNotificationCenter.current().add(request)
            Self.log.info("Notification delivered for '\(alert.title)'")
        } catch {
            Self.log.error("Failed to deliver notification: \(error.localizedDescription)")
        }
    }

    // MARK: - UNUserNotificationCenterDelegate

    nonisolated func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        didReceive response: UNNotificationResponse,
        withCompletionHandler completionHandler: @escaping @Sendable () -> Void
    ) {
        let userInfo = response.notification.request.content.userInfo
        let alertIDString = userInfo["alertID"] as? String
        let alertID = alertIDString.flatMap { UUID(uuidString: $0) }

        if response.actionIdentifier == "VIEW_ALERT" ||
           response.actionIdentifier == UNNotificationDefaultActionIdentifier {
            Task { @MainActor in
                NSApp.activate(ignoringOtherApps: true)
                var notificationUserInfo: [AnyHashable: Any] = [:]
                if let id = alertID {
                    notificationUserInfo["alertID"] = id
                }
                NotificationCenter.default.post(
                    name: .nickNavigateToAlert,
                    object: nil,
                    userInfo: notificationUserInfo.isEmpty ? nil : notificationUserInfo
                )
            }
        }
        completionHandler()
    }

    nonisolated func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        willPresent notification: UNNotification,
        withCompletionHandler completionHandler: @escaping @Sendable (UNNotificationPresentationOptions) -> Void
    ) {
        // Show banner and play sound even when Nick is the frontmost app.
        completionHandler([.banner, .sound])
    }
}

// MARK: - Notification.Name

extension Notification.Name {
    /// Posted when the user taps a Nick notification and wants to navigate to an alert.
    ///
    /// `userInfo["alertID"]` contains a `UUID` when the notification was for a specific alert.
    static let nickNavigateToAlert = Notification.Name("com.ehsanazish.nick.navigateToAlert")

    /// Posted when a file or folder should be scanned via the YARA engine.
    ///
    /// `object` is a `URL` pointing to the file or directory to scan.
    /// Emitted by `NickServicesProvider` (Finder right-click) and by
    /// `DashboardView.openFileScanPanel()` (manual button).
    static let nickScanFileRequest = Notification.Name("com.ehsanazish.nick.scanFileRequest")
}
