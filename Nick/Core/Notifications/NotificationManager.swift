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

    enum DeliveryLevel: String, Equatable { case interrupt, inform, silent }

    // MARK: - Singleton

    /// Shared instance — created once and retained for the app lifetime.
    static let shared = NotificationManager()
    var notificationThreshold: SignalSeverity = .high

    // MARK: - Private

    private static let log = Logger(
        subsystem: "com.ehsanazish.nick",
        category: "NotificationManager"
    )

    private override init() {
        super.init()
    }

    private var deliveredCount: UInt64 = 0
    private let deliveryStartedAt = Date()
    private struct PendingDigest {
        var count: Int
        let deadline: Date
    }

    private var pendingDigests: [String: PendingDigest] = [:]

    var notificationsDeliveredPerActiveHour: Double {
        Double(deliveredCount) / max(Date().timeIntervalSince(deliveryStartedAt) / 3600, 1.0 / 3600)
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
        let updateAction = UNNotificationAction(
            identifier: "VIEW_UPDATE",
            title: "View Update",
            options: [.foreground]
        )
        let updateCategory = UNNotificationCategory(
            identifier: "UPDATE_AVAILABLE",
            actions: [updateAction],
            intentIdentifiers: [],
            options: []
        )
        let center = UNUserNotificationCenter.current()
        center.setNotificationCategories([alertCategory, updateCategory])
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

    func sendProtectionUnavailable() async {
        let settings = await UNUserNotificationCenter.current().notificationSettings()
        guard settings.authorizationStatus == .authorized || settings.authorizationStatus == .provisional,
              settings.alertStyle != .none else { return }
        let content = UNMutableNotificationContent()
        content.title = "Nick protection is unavailable"
        content.body = "Endpoint Security stopped responding. Activity during this gap may not be observed."
        content.sound = .default
        content.interruptionLevel = .timeSensitive
        content.categoryIdentifier = "THREAT_ALERT"
        let request = UNNotificationRequest(
            identifier: "nick-protection-unavailable",
            content: content,
            trigger: nil
        )
        do {
            try await UNUserNotificationCenter.current().add(request)
            deliveredCount += 1
        } catch {
            Self.log.error("Failed to deliver protection-unavailable notification: \(error.localizedDescription)")
        }
    }

    // MARK: - Delivery

    /// Posts a system notification banner for the given alert.
    ///
    /// - Parameter alert: The correlated threat alert to notify about.
    ///
    /// Silently returns when `alert.severity == .info` (trusted-app activity) or
    /// when the alert's severity is below the user-configured threshold.
    @discardableResult
    func send(for alert: ThreatAlert) async -> Bool {
        let presentation = Self.presentation(for: alert)
        guard presentation.deliveryLevel != .silent else { return false }

        // macOS does not throw from add() when permission is denied — it silently
        // discards the notification. Check authorization first and bail early with
        // a clear log so the root cause is visible in the console.
        let settings = await UNUserNotificationCenter.current().notificationSettings()
        let authStatus = settings.authorizationStatus
        Self.log.info("Notification settings — auth:\(authStatus.rawValue) alertStyle:\(settings.alertStyle.rawValue) sound:\(settings.soundSetting.rawValue) badge:\(settings.badgeSetting.rawValue) (alertStyle: 0=none 1=banner 2=alert)")
        guard authStatus == .authorized || authStatus == .provisional else {
            Self.log.warning("Notifications not authorized (status=\(authStatus.rawValue)) — skipping delivery for '\(alert.title)'")
            return false
        }
        guard settings.alertStyle != .none else {
            Self.log.warning("Nick's notification style is 'None' in System Settings — no banner will appear. Fix: System Settings → Notifications → Nick → set to Banners or Alerts")
            return false
        }

        let threshold = notificationThreshold
        guard presentation.requiresVisibleDelivery || alert.severity >= threshold else {
            Self.log.debug("Alert '\(alert.title)' below threshold (\(threshold.displayName)) — suppressed")
            return false
        }

        let content = UNMutableNotificationContent()
        content.title = presentation.title ?? "Nick — \(alert.severity.displayName) Alert"
        if presentation.deliveryLevel == .inform {
            let now = Date()
            let existing = pendingDigests[presentation.threadIdentifier]
            let digest = existing.map { $0.deadline > now
                ? PendingDigest(count: $0.count + 1, deadline: $0.deadline)
                : PendingDigest(count: 1, deadline: now.addingTimeInterval(600))
            } ?? PendingDigest(count: 1, deadline: now.addingTimeInterval(600))
            pendingDigests[presentation.threadIdentifier] = digest
            let count = digest.count
            content.body = count == 1 ? (presentation.body ?? alert.title) : "\(count) updates from this app"
        } else if let body = presentation.body {
            content.body = body
        } else if let tamper = alert.contributingSignals.first(where: {
            $0.metadata["reason"] == "endpoint_tamper_observed"
        }) {
            content.body = Self.tamperNotificationBody(alert: alert, signal: tamper)
        } else {
            content.body = alert.title
        }
        content.sound = presentation.deliveryLevel == .interrupt ? .default : nil
        content.interruptionLevel = presentation.deliveryLevel == .interrupt ? .timeSensitive : .passive
        content.categoryIdentifier = presentation.categoryIdentifier
        content.userInfo = ["alertID": alert.id.uuidString]
        content.threadIdentifier = presentation.threadIdentifier

        let request = UNNotificationRequest(
            identifier: presentation.deliveryLevel == .inform
                ? "nick-digest-\(presentation.threadIdentifier)" : alert.id.uuidString,
            content: content,
            trigger: presentation.deliveryLevel == .inform
                ? UNTimeIntervalNotificationTrigger(
                    timeInterval: max(
                        1,
                        pendingDigests[presentation.threadIdentifier]?.deadline.timeIntervalSinceNow ?? 600
                    ),
                    repeats: false
                ) : nil
        )

        do {
            try await UNUserNotificationCenter.current().add(request)
            deliveredCount += 1
            Self.log.info("Notification delivered for '\(alert.title)'")
            return true
        } catch {
            Self.log.error("Failed to deliver notification: \(error.localizedDescription)")
            return false
        }
    }

    struct Presentation: Equatable {
        let requiresVisibleDelivery: Bool
        let isDocumentedUninstall: Bool
        let title: String?
        let body: String?
        let categoryIdentifier: String
        let deliveryLevel: DeliveryLevel
        let threadIdentifier: String
    }

    static func presentation(for alert: ThreatAlert) -> Presentation {
        let isDocumentedUninstall = alert.contributingSignals.contains {
            $0.metadata["rule"] == "nick_documented_uninstall"
        }
        if isDocumentedUninstall {
            return Presentation(
                requiresVisibleDelivery: true,
                isDocumentedUninstall: true,
                title: "Nick is being moved to the Trash",
                body: "Use Nick Uninstaller later if you also want to remove protection components and generated data.",
                categoryIdentifier: "NICK_UNINSTALL",
                deliveryLevel: .inform,
                threadIdentifier: "nick"
            )
        }

        let isCaptureActivation = alert.contributingSignals.contains {
            $0.source == .avCapture && $0.metadata["reason"] == "capture_device_active"
        }
        let signals = alert.contributingSignals
        let explicit = signals.compactMap { $0.metadata["deliveryLevel"] }.first
        let reasonSet = Set(signals.compactMap { $0.metadata["reason"] ?? $0.metadata["rule"] })
        let neverDowngrade = signals.contains { $0.source == .yara } || !reasonSet.isDisjoint(with: [
            "curl_pipe_shell", "wget_pipe_shell", "hidden_password_prompt",
            "credential_store_access", "yara_match", "exact_hash_match"
        ]) || signals.contains { signal in
            (signal.metadata["reason"] == "endpoint_tamper_observed"
                && signal.metadata["responsibleAppSigning"] != "Apple platform")
                || signal.metadata["remediationStatus"].map {
                    ["blocked", "quarantined", "quarantine-failed"].contains($0)
                } == true
        }
        let deliveryLevel: DeliveryLevel
        if neverDowngrade { deliveryLevel = .interrupt }
        else if explicit == "silent" { deliveryLevel = .silent }
        else if explicit == "interrupt" { deliveryLevel = .interrupt }
        else if alert.severity >= .high { deliveryLevel = .interrupt }
        else if alert.severity == .info { deliveryLevel = .silent }
        else { deliveryLevel = .inform }
        let thread = signals.compactMap {
            $0.metadata["responsibleAppBundleID"] ?? $0.metadata["responsibleAppName"]
        }.first ?? "nick"
        return Presentation(
            requiresVisibleDelivery: deliveryLevel != .silent,
            isDocumentedUninstall: false,
            title: isCaptureActivation ? alert.title : nil,
            body: isCaptureActivation ? alert.description : nil,
            categoryIdentifier: "THREAT_ALERT",
            deliveryLevel: deliveryLevel,
            threadIdentifier: thread
        )
    }

    static func tamperNotificationBody(alert: ThreatAlert, signal: ThreatSignal) -> String {
        let operation = UserFacingAlertBuilder.userFacingTamperOperation(
            signal.metadata["tamperOperation"]
        )
        let actor = signal.processInfo?.name.isEmpty == false
            ? signal.processInfo!.name
            : (signal.processInfo?.path as NSString?)?.lastPathComponent ?? "unknown actor"
        let count = alert.occurrenceCount
        let unit = count == 1 ? "time" : "times"
        return "\(operation.capitalized) by \(actor) — attempted \(count) \(unit)"
    }

    func sendUpdateAvailable(version: String) async {
        let settings = await UNUserNotificationCenter.current().notificationSettings()
        guard settings.authorizationStatus == .authorized ||
              settings.authorizationStatus == .provisional else {
            Self.log.info("Update reminder skipped because notifications are not authorized")
            return
        }
        let content = UNMutableNotificationContent()
        content.title = "Nick \(version) is available"
        content.body = "Click to review and install the update."
        content.categoryIdentifier = "UPDATE_AVAILABLE"
        content.userInfo = ["updateVersion": version]
        let request = UNNotificationRequest(
            identifier: "nick-update-\(version)", content: content, trigger: nil
        )
        do {
            try await UNUserNotificationCenter.current().add(request)
        } catch {
            Self.log.error("Failed to deliver update reminder: \(error.localizedDescription)")
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

        if response.notification.request.content.categoryIdentifier == "UPDATE_AVAILABLE" {
            Task { @MainActor in
                NSApp.setActivationPolicy(.regular)
                NSApp.activate()
                _ = (NSApp.delegate as? AppDelegate)?.checkForUpdates()
            }
            completionHandler()
            return
        }

        if response.actionIdentifier == "VIEW_ALERT" ||
           response.actionIdentifier == UNNotificationDefaultActionIdentifier {
            Task { @MainActor in
                NSApp.setActivationPolicy(.regular)
                if let window = NSApp.nickMainWindow {
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

    /// Posted by the Sparkle delegate with a user-facing update-check result.
    /// `object` contains the status text displayed in Settings.
    static let nickUpdateCheckStatus = Notification.Name("com.ehsanazish.nick.updateCheckStatus")
}
