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
    private var updateBadgeVisible = false
    private let updateLogger = Logger(
        subsystem: "com.ehsanazish.nick",
        category: "Updates"
    )
    private let incidentStoreLogger = Logger(
        subsystem: "com.ehsanazish.nick",
        category: "IncidentStore"
    )
    private var receivedUpdateCheckResult = false
    /// Sparkle must be allowed to terminate Nick after the user accepts an
    /// update, even when Nick's main window is hidden. Otherwise the installer
    /// waits forever for the menu-bar app to exit.
    private var sparkleInstallationInProgress = false
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
        traceUninstall("Nick launched; maintenance mode: \(CommandLine.arguments.contains("--prepare-uninstall"))")
        if CommandLine.arguments.contains("--prepare-uninstall") {
            traceUninstall("Maintenance mode detected in applicationDidFinishLaunching")
            prepareForUninstall()
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
            updaterDelegate: self,
            userDriverDelegate: self
        )
        setupStatusItem()
        Task { @MainActor [weak self] in
            guard let self else { return }
            let endpointManager = ExtensionManager()
            endpointExtensionManager = endpointManager
            await endpointManager.ensureBundledVersionIsActive()
            xpcClient.findingHandler = { [weak self] finding in
                guard let self else { return }
                _ = await self.engine.ingestLiveFinding(
                    finding.signal,
                    score: finding.score,
                    recommendedAction: finding.recommendedAction
                )
            }
            networkProtection.findingHandler = { [weak self] finding in
                guard let self else { return }
                _ = await self.engine.ingestLiveFinding(
                    finding.signal,
                    score: finding.score,
                    recommendedAction: finding.recommendedAction
                )
            }
            let legacyPayload = engine.prepareLegacyIncidentMigration()
            xpcClient.connect(legacyIncidentPayload: legacyPayload) { [weak self] record, _ in
                guard let self else { return }
                if let record {
                    do {
                        try self.engine.installPrivilegedIncidentStore(
                            payload: record.payload,
                            persistence: { [weak self] payload in
                                self?.xpcClient.persistIncidentStore(payload)
                            },
                            authorizer: { [weak self] id, action in
                                guard let self else { return false }
                                return await self.xpcClient.authoriseIncidentVerdict(id: id, action: action)
                            },
                            removeLegacyState: true
                        )
                    } catch {
                        self.incidentStoreLogger.error(
                            "Could not load root-owned incident store: \(error.localizedDescription)"
                        )
                    }
                }
                Task { @MainActor [weak self] in
                    guard let self else { return }
                    let legacySettings = self.engine.prepareLegacySecuritySettingsMigration()
                    if let privilegedSettings = await self.xpcClient.bootstrapSecuritySettings(
                        legacyPayload: legacySettings
                    ) {
                        do {
                            try self.engine.installPrivilegedSecuritySettings(
                                payload: privilegedSettings,
                                persistence: { [weak self] payload in
                                    self?.xpcClient.persistSecuritySettings(payload)
                                }
                            )
                        } catch {
                            self.incidentStoreLogger.error(
                                "Could not load root-owned security settings: \(error.localizedDescription)"
                            )
                        }
                    }
                    self.startMonitoringAfterIncidentStoreBootstrap()
                }
            }

            // Network Filter replacement/configuration is independent of the
            // Endpoint Security XPC bootstrap. A system-extension request can
            // remain pending while macOS waits for approval or provider health;
            // it must never delay loading or migrating the incident store.
            Task { @MainActor [weak self] in
                guard let self else { return }
                await NetworkFilterInstaller.shared.ensureBundledVersionIsActive()
                await self.networkProtection.refresh()
            }
        }
        NotificationCenter.default.addObserver(
            self,
            selector: #selector(applicationWillBecomeActive),
            name: NSApplication.willBecomeActiveNotification,
            object: nil
        )
    }

    @MainActor
    private func startMonitoringAfterIncidentStoreBootstrap() {
        guard coordinator == nil else { return }
        let coord = MonitorCoordinator(engine: engine)
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

    /// Runs only when the bundled uninstaller launches Nick with
    /// `--prepare-uninstall`. These APIs must execute from Nick's own bundle:
    /// NetworkExtension preferences and ServiceManagement registrations are
    /// scoped to the app that created them.
    private func prepareForUninstall() {
        guard !uninstallPreparationInProgress else {
            uninstallLogger.notice("Ignoring duplicate uninstall preparation request")
            traceUninstall("Ignored duplicate preparation request")
            return
        }
        uninstallPreparationInProgress = true
        NSApp.setActivationPolicy(.prohibited)

        // Never let a command-line argument choose a privileged app's write
        // destination. The bundled uninstaller and Nick independently derive
        // the same per-user, fixed receipt path.
        let markerPath = Self.uninstallResultURL.path
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
        let windowVisible = NSApp.nickMainWindow?.isVisible ?? false
        return Self.terminationReply(
            isRunningTests: isRunningTests,
            forceQuit: forceQuit,
            sparkleInstallationInProgress: sparkleInstallationInProgress,
            windowVisible: windowVisible
        )
    }

    static func terminationReply(
        isRunningTests: Bool,
        forceQuit: Bool,
        sparkleInstallationInProgress: Bool,
        windowVisible: Bool
    ) -> NSApplication.TerminateReply {
        if isRunningTests || forceQuit || sparkleInstallationInProgress {
            return .terminateNow
        }
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
        button.image = statusImage(color: .systemOrange, description: "Nick is starting")
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
            button.image = statusImage(color: .systemGreen, description: "Nick is protected", showsUpdateBadge: updateBadgeVisible)
            button.toolTip = updateBadgeVisible ? "Nick: Update available" : "Nick: Protected"
        case .review:
            button.image = statusImage(color: .systemOrange, description: "Nick needs your review", showsUpdateBadge: updateBadgeVisible)
            button.toolTip = updateBadgeVisible ? "Nick: Review needed · Update available" : "Nick: Review needed"
        case .urgent:
            button.image = statusImage(color: .systemRed, description: "Nick needs immediate attention", showsUpdateBadge: updateBadgeVisible)
            button.toolTip = updateBadgeVisible ? "Nick: Immediate attention needed · Update available" : "Nick: Immediate attention needed"
        }
    }

    private func statusImage(
        color: NSColor,
        description: String,
        showsUpdateBadge: Bool = false
    ) -> NSImage? {
        let configuration = NSImage.SymbolConfiguration(paletteColors: [color])
        guard let symbol = NSImage(
            systemSymbolName: "shield.fill",
            accessibilityDescription: description
        )?.withSymbolConfiguration(configuration) else { return nil }

        // NSStatusItem may reinterpret an SF Symbol as a monochrome template even
        // after `isTemplate` is cleared. Rasterizing the configured symbol keeps
        // the health colour visible in both light and dark menu bars.
        let size = NSSize(width: 18, height: 18)
        let image = NSImage(size: size, flipped: false) { rect in
            symbol.draw(in: rect)
            if showsUpdateBadge {
                let badgeRect = NSRect(x: 12, y: 11, width: 6, height: 6)
                NSColor.controlBackgroundColor.setFill()
                NSBezierPath(ovalIn: badgeRect.insetBy(dx: -1, dy: -1)).fill()
                NSColor.systemBlue.setFill()
                NSBezierPath(ovalIn: badgeRect).fill()
            }
            return true
        }
        image.isTemplate = false
        image.accessibilityDescription = description
        return image
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

    /// One click shows Nick in front; the next click hides it again.
    /// Hides only when the window is on screen and Nick is the active app, so a
    /// click while Nick is behind other apps brings it forward instead.
    @objc private func toggleMainWindow() {
        if let window = NSApp.nickMainWindow,
           window.isVisible, !window.isMiniaturized, NSApp.isActive {
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
            if let window = NSApp.nickMainWindow {
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

        // Show the existing window right away, still inside the click's event.
        if let window = NSApp.nickMainWindow {
            if window.isMiniaturized { window.deminiaturize(nil) }
            window.delegate = mainWindowDelegate
            window.makeKeyAndOrderFront(nil)
            window.orderFrontRegardless()
        }

        // Step 2 — if SwiftUI gave us an openWindow action use it; this handles the
        // rare case where SwiftUI fully released the NSWindow (e.g. after a scene reset).
        openMainWindowAction?()

        // Step 3 — defer window ordering.  canBecomeMain returns false while the app
        // is still resolving the .accessory → .regular transition, so filter by class
        // instead of canBecomeMain to reliably locate the window.
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.1) { [weak self] in
            guard let self else { return }
            if let window = NSApp.nickMainWindow {
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
                MainWindowLocator.isSettingsIdentifier($0.identifier?.rawValue)
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

    @discardableResult
    @objc func checkForUpdates() -> Bool {
        guard let updaterController else {
            updateLogger.error("Manual update check requested before Sparkle initialized")
            postUpdateCheckStatus("Update service is not ready. Please try again.")
            return false
        }
        receivedUpdateCheckResult = false
        updateLogger.info("Starting manual update check; canCheck=\(updaterController.updater.canCheckForUpdates)")
        updaterController.updater.checkForUpdates()
        return true
    }

    private func postUpdateCheckStatus(_ status: String) {
        UserDefaults.standard.set(Date().timeIntervalSince1970, forKey: "nickUpdateLastCheckTime")
        UserDefaults.standard.set(status, forKey: "nickUpdateLastCheckResult")
        NotificationCenter.default.post(name: .nickUpdateCheckStatus, object: status)
    }

    private func setUpdateBadge(visible: Bool) {
        updateBadgeVisible = visible
        updateStatusItemAppearance()
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

// MARK: - Sparkle diagnostics

extension AppDelegate: SPUUpdaterDelegate {
    func updater(_: SPUUpdater, willInstallUpdate item: SUAppcastItem) {
        sparkleInstallationInProgress = true
        updateLogger.info("Sparkle will install update build=\(item.versionString, privacy: .public); allowing application termination")
    }

    func feedURLString(for updater: SPUUpdater) -> String? {
#if DEBUG
        let value = Bundle.main.object(forInfoDictionaryKey: "NickDebugUpdateFeedURL") as? String
        let trimmed = value?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        if let url = URL(string: trimmed), url.scheme == "https" {
            return trimmed
        }
#endif
        return nil
    }

    func updater(_ updater: SPUUpdater, didFindValidUpdate item: SUAppcastItem) {
        receivedUpdateCheckResult = true
        UserDefaults.standard.set(true, forKey: "nickUpdateAvailable")
        UserDefaults.standard.set(item.displayVersionString, forKey: "nickUpdateAvailableVersion")
        updateLogger.info("Sparkle found update version=\(item.displayVersionString, privacy: .public) build=\(item.versionString, privacy: .public)")
        postUpdateCheckStatus("Nick \(item.displayVersionString) is available.")
    }

    func updaterDidNotFindUpdate(_ updater: SPUUpdater, error: Error) {
        receivedUpdateCheckResult = true
        UserDefaults.standard.set(false, forKey: "nickUpdateAvailable")
        UserDefaults.standard.removeObject(forKey: "nickUpdateAvailableVersion")
        setUpdateBadge(visible: false)
        updateLogger.info("Sparkle found no update: \(error.localizedDescription, privacy: .public)")
        postUpdateCheckStatus("Nick is up to date.")
    }

    func updater(
        _ updater: SPUUpdater,
        didFinishUpdateCycleFor updateCheck: SPUUpdateCheck,
        error: Error?
    ) {
        sparkleInstallationInProgress = false
        if let error {
            if receivedUpdateCheckResult {
                updateLogger.info("Sparkle update cycle completed with a handled result: \(error.localizedDescription, privacy: .public)")
            } else {
                updateLogger.error("Sparkle update cycle failed: \(error.localizedDescription, privacy: .public)")
                postUpdateCheckStatus("Update check failed: \(error.localizedDescription)")
            }
        } else {
            updateLogger.info("Sparkle update cycle finished successfully")
            if !receivedUpdateCheckResult {
                postUpdateCheckStatus("Update check completed.")
            }
        }
        receivedUpdateCheckResult = false
    }
}

extension AppDelegate: @preconcurrency SPUStandardUserDriverDelegate {
    var supportsGentleScheduledUpdateReminders: Bool { true }

    func standardUserDriverShouldHandleShowingScheduledUpdate(
        _ update: SUAppcastItem,
        andInImmediateFocus immediateFocus: Bool
    ) -> Bool {
        immediateFocus
    }

    func standardUserDriverWillHandleShowingUpdate(
        _ handleShowingUpdate: Bool,
        forUpdate update: SUAppcastItem,
        state: SPUUserUpdateState
    ) {
        guard !state.userInitiated, !handleShowingUpdate else { return }
        setUpdateBadge(visible: true)
        Task {
            await NotificationManager.shared.sendUpdateAvailable(
                version: update.displayVersionString
            )
        }
    }

    func standardUserDriverDidReceiveUserAttention(forUpdate update: SUAppcastItem) {
        setUpdateBadge(visible: false)
    }

    func standardUserDriverWillFinishUpdateSession() {
        setUpdateBadge(visible: false)
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
