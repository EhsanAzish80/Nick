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

    /// Registers notification categories, sets the delegate, and kicks off a
    /// permission request. Safe to call multiple times — idempotent.
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
        // requestPermission() is NOT called here — no window is open at launch and
        // macOS will silently discard the dialog for a .accessory-policy app with no
        // active foreground window. Permission is requested by WelcomeView (new users)
        // or by MainWindowView's .task modifier (returning users).
    }

    /// Requests notification permission and returns whether it was granted.
    ///
    /// - `.notDetermined`: shows the macOS system prompt.
    /// - `.denied`: logs a warning; returns `false` (caller should surface in-app guidance).
    /// - `.authorized` / `.provisional` / `.ephemeral`: returns `true` immediately.
    @discardableResult
    func requestPermission() async -> Bool {
        let center = UNUserNotificationCenter.current()
        let settings = await center.notificationSettings()

        switch settings.authorizationStatus {
        case .notDetermined:
            do {
                let granted = try await center.requestAuthorization(options: [.alert, .sound, .badge])
                if granted {
                    Self.log.info("Notification permission granted")
                } else {
                    Self.log.warning("Notification permission denied by user")
                }
                return granted
            } catch {
                Self.log.error("Notification permission request failed: \(error.localizedDescription)")
                return false
            }
        case .denied:
            Self.log.warning("Notifications denied — user must enable in System Settings")
            return false
        case .authorized, .provisional, .ephemeral:
            return true
        @unknown default:
            return false
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

        // macOS does not throw from add() when permission is denied — it silently
        // discards the notification. Check authorization first and bail early with
        // a clear log so the root cause is visible in the console.
        let settings = await UNUserNotificationCenter.current().notificationSettings()
        let authStatus = settings.authorizationStatus
        Self.log.info("Notification settings — auth:\(authStatus.rawValue) alertStyle:\(settings.alertStyle.rawValue) sound:\(settings.soundSetting.rawValue) badge:\(settings.badgeSetting.rawValue) (alertStyle: 0=none 1=banner 2=alert)")
        guard authStatus == .authorized || authStatus == .provisional else {
            Self.log.warning("Notifications not authorized (status=\(authStatus.rawValue)) — skipping delivery for '\(alert.title)'")
            return
        }
        guard settings.alertStyle != .none else {
            Self.log.warning("Nick's notification style is 'None' in System Settings — no banner will appear. Fix: System Settings → Notifications → Nick → set to Banners or Alerts")
            return
        }

        let thresholdRaw = UserDefaults.standard.integer(forKey: "notificationThresholdRaw")
        let threshold = SignalSeverity(rawValue: thresholdRaw) ?? .high
        guard alert.severity >= threshold else {
            Self.log.debug("Alert '\(alert.title)' below threshold (\(threshold.displayName)) — suppressed")
            return
        }

        let content = UNMutableNotificationContent()
        content.title = "Nick — \(alert.severity.displayName) Alert"
        content.body = alert.title
        content.sound = .default
        content.interruptionLevel = .timeSensitive   // breaks through Focus / DND
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
        _: UNUserNotificationCenter,
        didReceive response: UNNotificationResponse,
        withCompletionHandler completionHandler: @escaping @Sendable () -> Void
    ) {
        let userInfo = response.notification.request.content.userInfo
        let alertIDString = userInfo["alertID"] as? String
        let alertID = alertIDString.flatMap { UUID(uuidString: $0) }

        if response.actionIdentifier == "VIEW_ALERT" ||
           response.actionIdentifier == UNNotificationDefaultActionIdentifier {
            Task { @MainActor in
                NSApp.setActivationPolicy(.regular)
                if let window = NSApp.windows.first(where: { $0.title == "Nick" || $0.title == "Overview" }) {
                    window.makeKeyAndOrderFront(nil)
                }
                NSApp.activate()
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
        _: UNUserNotificationCenter,
        willPresent notification: UNNotification,
        withCompletionHandler completionHandler: @escaping @Sendable (UNNotificationPresentationOptions) -> Void
    ) {
        let log = Logger(subsystem: "com.ehsanazish.nick", category: "NotificationManager")
        log.info("willPresent called — forcing banner for '\(notification.request.content.body, privacy: .public)'")
        // Show banner, play sound, and update badge even when Nick is the frontmost app.
        completionHandler([.banner, .sound, .badge])
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
