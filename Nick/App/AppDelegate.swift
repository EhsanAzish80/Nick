// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import AppKit
import Darwin
import NetworkExtension
import Observation
import OSLog
import ServiceManagement
import Sparkle
import SystemExtensions

// MARK: - AppDelegate

/// Application delegate that owns the NSStatusItem and the SecurityEngine.
///
/// `@MainActor` is required because SecurityEngine is a `@MainActor @Observable` class.
/// All NSApplicationDelegate callbacks are always invoked on the main thread, so this is safe.
@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {

    // MARK: - Shared State

    /// Single SecurityEngine instance shared across all scenes. This must stay
    /// lazy: uninstall maintenance mode starts the app delegate but must never
    /// construct scanners, monitors, or persistence stores.
    lazy var engine = SecurityEngine()

    /// XPC client that bridges the container app to NickExtension.
    lazy var xpcClient = ExtensionXPCClient()
    lazy var networkProtection = NetworkProtectionManager()

    // MARK: - Private

    private var statusItem: NSStatusItem?
    private let mainWindowDelegate = MainWindowDelegate()
    private var coordinator: MonitorCoordinator?
    private var endpointExtensionManager: ExtensionManager?
    private var updaterController: SPUStandardUpdaterController?
    private var uninstallPreparationInProgress = false
    private let uninstallLogger = Logger(
        subsystem: "com.ehsanazish.nick",
        category: "Uninstall"
    )
    /// Set to `true` before calling `NSApp.terminate` from an explicit user action
    /// (right-click → Quit Nick) so `applicationShouldTerminate` allows the quit
    /// even when the main window is hidden.
    private var forceQuit = false

    private var isRunningTests: Bool {
        let environment = ProcessInfo.processInfo.environment
        return environment["XCTestConfigurationFilePath"] != nil
            || environment["XCTestBundlePath"] != nil
            || environment["XCInjectBundleInto"] != nil
            || environment["DYLD_INSERT_LIBRARIES"]?.contains("XCTest") == true
            || NSClassFromString("XCTestCase") != nil
            || Bundle.allBundles.contains { $0.bundlePath.hasSuffix(".xctest") }
            || CommandLine.arguments.contains("-ApplePersistenceIgnoreState")
    }

    /// Injected by `MainWindowView.onAppear`. Calls SwiftUI's `openSettings` environment
    /// action so the status-bar "Settings..." menu item opens the Settings scene through
    /// the official path instead of the private `showSettingsWindow:` selector.
    var openSettingsAction: (() -> Void)?

    /// Injected by `MainWindowView.onAppear`. Calls SwiftUI's `openWindow(id:"main")`
    /// action so the status-bar click can ask SwiftUI to (re)create the window when it
    /// has been fully closed rather than just hidden.
    var openMainWindowAction: (() -> Void)?

    // MARK: - NSApplicationDelegate

    func applicationDidFinishLaunching(_: Notification) {
        traceUninstall("Nick launched with arguments: \(CommandLine.arguments.joined(separator: " "))")
        if CommandLine.arguments.contains("--prepare-uninstall") {
            traceUninstall("Maintenance mode detected in applicationDidFinishLaunching")
            prepareForUninstall(
                markerPath: uninstallArgumentValue(after: "--result")
            )
            return
        }

        // XCTest launches the real application executable as its test host. Starting
        // the production scanners here would enumerate the whole Mac, connect to the
        // installed system extensions, and mutate persistent state while unit tests
        // are running. Keep the test host inert; individual tests construct only the
        // services they exercise.
        if isRunningTests {
            return
        }

        DistributedNotificationCenter.default().addObserver(
            self,
            selector: #selector(handleUninstallPreparationRequest(_:)),
            name: .nickPrepareForUninstall,
            object: nil
        )

        // Register defaults so first-run behaviour matches configured behaviour.
        // Must run before any code that reads these keys.
        UserDefaults.standard.register(defaults: [
            "notificationThresholdRaw": SignalSeverity.high.rawValue,
            "deepScanIntervalSeconds": 300
        ])
        // Earlier builds allowed a full process/network/persistence sweep every
        // 30–60 seconds. Endpoint Security now supplies real-time coverage, so
        // migrate those high-impact defaults to a five-minute background sweep.
        if !UserDefaults.standard.bool(forKey: "performanceSweepIntervalMigratedV1") {
            if UserDefaults.standard.integer(forKey: "deepScanIntervalSeconds") < 300 {
                UserDefaults.standard.set(300, forKey: "deepScanIntervalSeconds")
            }
            UserDefaults.standard.set(true, forKey: "performanceSweepIntervalMigratedV1")
        }
        updaterController = SPUStandardUpdaterController(
            startingUpdater: true,
            updaterDelegate: nil,
            userDriverDelegate: nil
        )
        setupStatusItem()
        Task { @MainActor in
            let endpointManager = ExtensionManager()
            endpointExtensionManager = endpointManager
            endpointManager.ensureBundledVersionIsActive()
            // A healthy older Network Filter is not sufficient after an app
            // update. Submit a replacement request once per bundled build so
            // macOS runs the provider shipped with this version of Nick.
            await NetworkFilterInstaller.shared.ensureBundledVersionIsActive()
            await networkProtection.refresh()
            xpcClient.connect()
            let coord = MonitorCoordinator(engine: engine, correlator: ThreatCorrelator())
            coordinator = coord
            // The coordinator's first tick performs the initial full scan.
            // Starting another scan here duplicates process signature validation
            // and can saturate a CPU core during launch.
            coord.startRealTimePipeline()
            NotificationManager.shared.setup()
            NSApp.servicesProvider = NickServicesProvider()
            NSUpdateDynamicServices()
            configureMainWindowDelegate()
            checkPendingFinderScan()
            checkScheduledDeepScan()
        }
        NotificationCenter.default.addObserver(
            self,
            selector: #selector(applicationWillBecomeActive),
            name: NSApplication.willBecomeActiveNotification,
            object: nil
        )
    }

    /// Runs only when the bundled uninstaller launches Nick with
    /// `--prepare-uninstall`. These APIs must execute from Nick's own bundle:
    /// NetworkExtension preferences and ServiceManagement registrations are
    /// scoped to the app that created them.
    @objc private func handleUninstallPreparationRequest(_ notification: Notification) {
        uninstallLogger.notice("Received uninstall preparation request")
        prepareForUninstall(markerPath: Self.uninstallResultURL.path)
    }

    private func prepareForUninstall(markerPath requestedMarkerPath: String?) {
        guard !uninstallPreparationInProgress else {
            uninstallLogger.notice("Ignoring duplicate uninstall preparation request")
            traceUninstall("Ignored duplicate preparation request")
            return
        }
        uninstallPreparationInProgress = true
        NSApp.setActivationPolicy(.prohibited)

        let markerPath = requestedMarkerPath
            ?? Self.uninstallResultURL.path
        uninstallLogger.notice("Preparing Nick for removal")
        traceUninstall("Preparation started; result path: \(markerPath)")

        Task {
            var failures: [String] = []
            var restartRequired = false

            do {
                traceUninstall("Loading Network Filter preferences")
                let manager = NEFilterManager.shared()
                try await manager.loadFromPreferences()
                traceUninstall("Network Filter preferences loaded; removing configuration")
                try await manager.removeFromPreferences()
                traceUninstall("Network Filter configuration removed")
            } catch {
                traceUninstall("Network Filter cleanup error: \(error.localizedDescription)")
                // "configuration not found" is harmless during an idempotent retry.
                let nsError = error as NSError
                if nsError.code != NEFilterManagerError.configurationInvalid.rawValue {
                    failures.append("Network Filter: \(error.localizedDescription)")
                }
            }

            for identifier in [
                "com.ehsanazish.nick.NickNetFilter",
                NickExtensionConstants.extensionBundleID
            ] {
                do {
                    traceUninstall("Requesting system extension removal: \(identifier)")
                    let result = try await SystemExtensionRemovalRequest.deactivate(
                        identifier: identifier
                    )
                    switch result {
                    case .completed:
                        traceUninstall("System extension removed: \(identifier)")
                    case .willCompleteAfterReboot:
                        traceUninstall("System extension removal will complete after restart: \(identifier)")
                        restartRequired = true
                    @unknown default:
                        traceUninstall("System extension removal returned an unknown result: \(identifier)")
                    }
                } catch {
                    let nsError = error as NSError
                    if nsError.domain == OSSystemExtensionErrorDomain,
                       nsError.code == OSSystemExtensionError.Code.extensionNotFound.rawValue {
                        traceUninstall("System extension was already absent: \(identifier)")
                    } else {
                        traceUninstall(
                            "System extension cleanup error \(identifier): \(error.localizedDescription)"
                        )
                        failures.append(
                            "System Extension \(identifier): \(error.localizedDescription)"
                        )
                    }
                }
            }

            let loginItem = SMAppService.mainApp
            traceUninstall("Launch at Login status: \(String(describing: loginItem.status))")
            if loginItem.status != .notRegistered {
                do {
                    traceUninstall("Unregistering Launch at Login")
                    try await loginItem.unregister()
                    traceUninstall("Launch at Login unregistered")
                } catch {
                    let nsError = error as NSError
                    // Launch-at-login registration is owned by the containing
                    // app. SMAppService may reject unregistering from Nick's
                    // headless maintenance launch even when the same user
                    // authorized removal. Deleting Nick makes the registration
                    // non-launchable, so this cleanup is always best-effort and
                    // must never stop the administrator-authorized purge.
                    traceUninstall(
                        "Launch at Login cleanup deferred to app removal: "
                            + "\(nsError.domain) \(nsError.code) "
                            + error.localizedDescription
                    )
                }
            }

            let helperPlistURL = Bundle.main.bundleURL
                .appendingPathComponent("Contents/Library/LaunchDaemons")
                .appendingPathComponent("com.ehsanazish.nick.helper.plist")
            if FileManager.default.fileExists(atPath: helperPlistURL.path) {
                let helper = SMAppService.daemon(
                    plistName: "com.ehsanazish.nick.helper.plist"
                )
                traceUninstall("Privileged helper status: \(String(describing: helper.status))")
                if helper.status != .notRegistered {
                    do {
                        traceUninstall("Unregistering privileged helper")
                        try await helper.unregister()
                        traceUninstall("Privileged helper unregistered")
                    } catch {
                        let nsError = error as NSError
                        traceUninstall(
                            "Privileged helper cleanup error \(nsError.domain) " +
                            "\(nsError.code): \(error.localizedDescription)"
                        )
                        failures.append("Privileged helper: \(error.localizedDescription)")
                    }
                }
            } else {
                // Current Nick builds do not embed an SMAppService LaunchDaemon
                // definition. A helper left by an older build is removed by the
                // administrator-authorized purge below; asking SMAppService to
                // unregister a nonexistent bundled definition returns EINVAL.
                traceUninstall("No bundled helper definition; deferring legacy helper cleanup to authorized purge")
            }

            let result: [String: Any] = [
                "completed": failures.isEmpty,
                "failures": failures,
                "restartRequired": restartRequired,
                "timestamp": ISO8601DateFormatter().string(from: Date())
            ]
            if let data = try? JSONSerialization.data(withJSONObject: result, options: [.prettyPrinted]) {
                do {
                    try data.write(to: URL(fileURLWithPath: markerPath), options: .atomic)
                    uninstallLogger.notice("Wrote uninstall result")
                    traceUninstall("Removal result written; failures: \(failures.count)")
                } catch {
                    uninstallLogger.error("Could not write uninstall result: \(error.localizedDescription, privacy: .public)")
                    traceUninstall("Could not write removal result: \(error.localizedDescription)")
                }
            } else {
                traceUninstall("Could not serialize removal result")
            }

            traceUninstall("Maintenance mode is terminating Nick")
            forceQuit = true
            NSApp.terminate(nil)
        }
    }

    private static var uninstallResultURL: URL {
        URL(
            fileURLWithPath: "/private/tmp",
            isDirectory: true
        ).appendingPathComponent(
            "com.ehsanazish.nick.uninstall-result-\(getuid()).json"
        )
    }

    static func isIgnorableLaunchAtLoginRemovalError(_ error: NSError) -> Bool {
        error.domain == NSPOSIXErrorDomain
            && (error.code == Int(EPERM) || error.code == Int(EACCES))
    }

    private static var uninstallTraceURL: URL {
        URL(fileURLWithPath: "/private/tmp", isDirectory: true)
            .appendingPathComponent("com.ehsanazish.nick.uninstall-trace-\(getuid()).log")
    }

    private func traceUninstall(_ message: String) {
        let line = "\(ISO8601DateFormatter().string(from: Date())) [Nick] \(message)\n"
        print("[Nick Uninstall] \(message)")
        let data = Data(line.utf8)
        if !FileManager.default.fileExists(atPath: Self.uninstallTraceURL.path) {
            FileManager.default.createFile(
                atPath: Self.uninstallTraceURL.path,
                contents: data
            )
            return
        }
        guard let handle = try? FileHandle(forWritingTo: Self.uninstallTraceURL) else { return }
        defer { try? handle.close() }
        do {
            try handle.seekToEnd()
            try handle.write(contentsOf: data)
        } catch {
            print("[Nick Uninstall] Could not append trace: \(error.localizedDescription)")
        }
    }

    private func uninstallArgumentValue(after flag: String) -> String? {
        guard let index = CommandLine.arguments.firstIndex(of: flag) else { return nil }
        let valueIndex = CommandLine.arguments.index(after: index)
        guard valueIndex < CommandLine.arguments.endIndex else { return nil }
        return CommandLine.arguments[valueIndex]
    }

    /// Keep Nick alive in the background when the last window closes.
    /// The app only quits via the right-click menu or ⌘Q while the window is visible.
    func applicationShouldTerminateAfterLastWindowClosed(_: NSApplication) -> Bool {
        return false
    }

    /// Allow termination only when (a) the user explicitly chose Quit from the
    /// right-click menu (`forceQuit == true`), or (b) the main window is currently
    /// visible (i.e. ⌘Q is meaningful to the user).
    func applicationShouldTerminate(_: NSApplication) -> NSApplication.TerminateReply {
        // XCTest owns the lifecycle of its host process. Never apply Nick's
        // menu-bar "stay alive while hidden" policy to a test host, otherwise
        // xcodebuild waits forever after the final test has completed.
        if isRunningTests { return .terminateNow }
        if forceQuit { return .terminateNow }
        // canBecomeMain is unreliable during .accessory→.regular transitions; filter by
        // class instead. Prefer the titled "Nick" window over any other non-panel window.
        let mainWindow = NSApp.windows.first(where: { !$0.isSheet && !($0 is NSPanel) && $0.title == "Nick" })
                      ?? NSApp.windows.first(where: { !$0.isSheet && !($0 is NSPanel) })
        let windowVisible = mainWindow?.isVisible ?? false
        return windowVisible ? .terminateNow : .terminateCancel
    }

    /// Re-opening (e.g., dock icon click when LSUIElement is temporarily .regular) should surface the window.
    func applicationShouldHandleReopen(_: NSApplication, hasVisibleWindows _: Bool) -> Bool {
        openMainWindow()
        return true
    }

    // MARK: - Status Item Setup

    private func setupStatusItem() {
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
        guard let button = statusItem?.button else { return }
        button.image = NSImage(systemSymbolName: "shield.fill", accessibilityDescription: "Nick")
        button.sendAction(on: [.leftMouseUp, .rightMouseUp])
        button.action = #selector(handleStatusItemClick(_:))
        button.target = self
        observeMenuBarAttentionState()
    }

    private func observeMenuBarAttentionState() {
        withObservationTracking {
            updateStatusItemAppearance()
        } onChange: { [weak self] in
            Task { @MainActor [weak self] in
                self?.observeMenuBarAttentionState()
            }
        }
    }

    private func updateStatusItemAppearance() {
        guard let button = statusItem?.button else { return }
        let state = engine.hasCompletedFirstScan
            ? engine.menuBarAttentionState
            : MenuBarAttentionState.review

        switch state {
        case .protected:
            button.contentTintColor = .systemGreen
            button.toolTip = "Nick: Protected"
            button.image?.accessibilityDescription = "Nick is protected"
        case .review:
            button.contentTintColor = .systemOrange
            button.toolTip = "Nick: Review needed"
            button.image?.accessibilityDescription = "Nick needs your review"
        case .urgent:
            button.contentTintColor = .systemRed
            button.toolTip = "Nick: Immediate attention needed"
            button.image?.accessibilityDescription = "Nick needs immediate attention"
        }
    }

    @objc private func handleStatusItemClick(_: NSStatusBarButton) {
        guard let event = NSApp.currentEvent else { return }
        if event.type == .rightMouseUp {
            showContextMenu()
        } else {
            toggleMainWindow()
        }
    }

    private func showContextMenu() {
        let menu = NSMenu()

        let openItem = NSMenuItem(title: "Open Nick", action: #selector(openMainWindow), keyEquivalent: "")
        openItem.target = self
        menu.addItem(openItem)

        menu.addItem(.separator())

        let updateItem = NSMenuItem(title: "Check for Updates…", action: #selector(checkForUpdates), keyEquivalent: "")
        updateItem.target = self
        menu.addItem(updateItem)

        menu.addItem(.separator())

        let quitItem = NSMenuItem(
            title:         "Quit Nick",
            action:        #selector(forceQuitApp),
            keyEquivalent: "q"
        )
        quitItem.keyEquivalentModifierMask = .command
        quitItem.target = self
        menu.addItem(quitItem)

        // Assign menu so performClick shows it, then clear so left-click uses the action handler.
        statusItem?.menu = menu
        statusItem?.button?.performClick(nil)
        statusItem?.menu = nil
    }

    /// Toggles the main window: hides it when it is visible and key, shows it otherwise.
    /// Checks `isKeyWindow` so clicking the icon while Nick is in the background brings
    /// the window forward rather than hiding it.
    @objc private func toggleMainWindow() {
        // canBecomeMain is unreliable during .accessory→.regular transitions. Use the
        // title-priority search used everywhere else, so an open Settings window is never
        // mistakenly ordered out instead of the main "Nick" window.
        let mainWindow = NSApp.windows.first(where: { !$0.isSheet && !($0 is NSPanel) && $0.title == "Nick" })
                      ?? NSApp.windows.first(where: { !$0.isSheet && !($0 is NSPanel) })
        if let window = mainWindow, window.isVisible && window.isKeyWindow {
            window.orderOut(nil)
            NSApp.setActivationPolicy(.accessory)
        } else {
            openMainWindow()
        }
    }

    /// Attaches `mainWindowDelegate` to the main window.
    ///
    /// SwiftUI sets its own internal delegate on the NSWindow before `applicationDidFinishLaunching`
    /// returns, so we must wait ~0.5 s and then unconditionally replace it. The `MainWindowDelegate`
    /// only overrides `windowShouldClose`; all other delegate methods are unimplemented and fall
    /// through to AppKit's default behaviour, so SwiftUI scene management is not affected.
    private func configureMainWindowDelegate() {
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) { [weak self] in
            guard let self else { return }
            if let window = NSApp.windows.first(where: { !$0.isSheet && !($0 is NSPanel) }) {
                window.delegate = self.mainWindowDelegate
            }
        }
    }

    @objc func openMainWindow() {
        // Step 1 — policy + activate IMMEDIATELY, while the menu-bar click event is
        // still the current event. macOS grants activate() requests from user-event
        // context far more reliably than from a deferred block where the event is gone.
        NSApp.setActivationPolicy(.regular)
        NSApp.activate()

        // Step 2 — if SwiftUI gave us an openWindow action use it; this handles the
        // rare case where SwiftUI fully released the NSWindow (e.g. after a scene reset).
        openMainWindowAction?()

        // Step 3 — defer window ordering.  canBecomeMain returns false while the app
        // is still resolving the .accessory → .regular transition, so filter by class
        // instead of canBecomeMain to reliably locate the window.
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.1) { [weak self] in
            guard let self else { return }
            let window = NSApp.windows.first(where: { !$0.isSheet && !($0 is NSPanel) })
            if let window {
                window.delegate = self.mainWindowDelegate
                window.makeKeyAndOrderFront(nil) // raise + key focus
                window.orderFrontRegardless()    // force above any other app's windows
                NSApp.activate()                 // re-activate after ordering so the OS
                                                 // delivers keyboard focus to this window
            }
        }
    }

    /// Opens the SwiftUI Settings scene via the `openSettings` environment action injected
    /// by `MainWindowView.onAppear`.
    @objc private func openSettings() {
        // If the action hasn't been injected yet (Settings tapped before the main window
        // ever appeared), open the main window so onAppear fires and registers it.
        // Do NOT recurse — that creates an open/hide loop. The user can click Settings
        // again once the main window is visible.
        guard let action = openSettingsAction else {
            openMainWindow()
            return
        }

        NSApp.setActivationPolicy(.regular)
        NSApp.activate()
        action()

        // The Settings NSWindow is created lazily by SwiftUI — give it a tick to appear,
        // then force it to the front exactly as openMainWindow does.
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.15) {
            let settingsWindow = NSApp.windows.first(where: {
                !$0.isSheet && !($0 is NSPanel) && $0.title != "Nick"
            })
            settingsWindow?.makeKeyAndOrderFront(nil)
            settingsWindow?.orderFrontRegardless()
            NSApp.activate()
        }
    }

    /// Bypasses the `applicationShouldTerminate` window-visibility gate and quits immediately.
    /// Used exclusively by the right-click → "Quit Nick" menu item.
    @objc private func forceQuitApp() {
        forceQuit = true
        NSApp.terminate(nil)
    }

    @objc func checkForUpdates() {
        updaterController?.checkForUpdates(nil)
    }

    // MARK: - Finder Sync Integration

    /// Checks App Group UserDefaults for a pending "Scan with Nick" URL posted by
    /// the NickFinderSync extension and launches a deep scan on that path.
    @objc func applicationWillBecomeActive() {
        checkPendingFinderScan()
        Task { await networkProtection.refresh() }
    }

    private func checkPendingFinderScan() {
        let sharedDefaults = UserDefaults(suiteName: "group.com.ehsanazish.nick")
        guard let urlString = sharedDefaults?.string(forKey: "pendingFinderScanURL"),
              !urlString.isEmpty else { return }
        sharedDefaults?.removeObject(forKey: "pendingFinderScanURL")
        sharedDefaults?.synchronize()
        guard let url = URL(string: urlString) else { return }
        Task { @MainActor [weak self] in
            guard let self else { return }
            openMainWindow()
            // Small delay so the window and ScannerDetailView are in the view hierarchy
            // before the notification fires, ensuring the observer is registered.
            try? await Task.sleep(nanoseconds: 300_000_000)
            NotificationCenter.default.post(name: .nickScanFileRequest, object: url)
        }
    }

    // MARK: - Scheduled Deep Scan

    /// Called on launch to fire a background deep scan if enough time has elapsed
    /// since the last one, based on the user's scheduled interval preference.
    ///
    /// Interval values: 0 = disabled, 1 = daily (86400s), 2 = weekly (604800s), 3 = monthly (2592000s).
    private func checkScheduledDeepScan() {
        let intervalChoice = UserDefaults.standard.integer(forKey: "scheduledDeepScanInterval")
        guard intervalChoice > 0 else { return }

        let intervalSeconds: TimeInterval
        switch intervalChoice {
        case 1: intervalSeconds = 86_400      // daily
        case 2: intervalSeconds = 604_800     // weekly
        case 3: intervalSeconds = 2_592_000   // monthly (~30 days)
        default: return
        }

        let lastScanDate = UserDefaults.standard.object(forKey: "nickLastScheduledDeepScanDate") as? Date
        let elapsed = lastScanDate.map { Date().timeIntervalSince($0) } ?? .infinity

        guard elapsed >= intervalSeconds else { return }

        UserDefaults.standard.set(Date(), forKey: "nickLastScheduledDeepScanDate")
        Task.detached(priority: .background) { [weak self] in
            await self?.engine.runFullScan()
        }
    }
}

private final class SystemExtensionRemovalRequest: NSObject,
    OSSystemExtensionRequestDelegate
{
    private var continuation:
        CheckedContinuation<OSSystemExtensionRequest.Result, Error>?

    static func deactivate(
        identifier: String
    ) async throws -> OSSystemExtensionRequest.Result {
        let operation = SystemExtensionRemovalRequest()
        let result = try await withCheckedThrowingContinuation { continuation in
            operation.continuation = continuation
            let request = OSSystemExtensionRequest.deactivationRequest(
                forExtensionWithIdentifier: identifier,
                queue: .main
            )
            request.delegate = operation
            OSSystemExtensionManager.shared.submitRequest(request)
        }
        // OSSystemExtensionRequest.delegate is not an ownership boundary. Keep
        // this delegate alive until macOS delivers its terminal callback.
        withExtendedLifetime(operation) {}
        return result
    }

    func request(
        _: OSSystemExtensionRequest,
        actionForReplacingExtension _: OSSystemExtensionProperties,
        withExtension _: OSSystemExtensionProperties
    ) -> OSSystemExtensionRequest.ReplacementAction {
        .cancel
    }

    func requestNeedsUserApproval(_: OSSystemExtensionRequest) {}

    func request(
        _: OSSystemExtensionRequest,
        didFinishWithResult result: OSSystemExtensionRequest.Result
    ) {
        continuation?.resume(returning: result)
        continuation = nil
    }

    func request(
        _: OSSystemExtensionRequest,
        didFailWithError error: Error
    ) {
        continuation?.resume(throwing: error)
        continuation = nil
    }
}

private extension Notification.Name {
    static let nickPrepareForUninstall = Notification.Name(
        "com.ehsanazish.nick.prepareForUninstall"
    )
}

// MARK: - MainWindowDelegate

/// Intercepts the red close button so it hides the window instead of destroying it.
///
/// Returning `false` from `windowShouldClose` prevents the window from being closed.
/// `orderOut` hides it, and dropping back to `.accessory` removes Nick from the Dock.
/// The window is brought back by clicking the menu bar icon (or ⌘Q to quit fully).
@MainActor
final class MainWindowDelegate: NSObject, NSWindowDelegate {
    func windowShouldClose(_ sender: NSWindow) -> Bool {
        sender.orderOut(nil)
        NSApp.setActivationPolicy(.accessory)
        return false
    }
}
