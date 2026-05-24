// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import AppKit
import SwiftData

// MARK: - AppDelegate

/// Application delegate that owns the NSStatusItem and the SecurityEngine.
///
/// `@MainActor` is required because SecurityEngine is a `@MainActor @Observable` class.
/// All NSApplicationDelegate callbacks are always invoked on the main thread, so this is safe.
@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {

    // MARK: - Shared State

    /// Single SecurityEngine instance shared across all scenes.
    let engine = SecurityEngine()

    // MARK: - Private

    private var statusItem: NSStatusItem?
    private let mainWindowDelegate = MainWindowDelegate()
    private var coordinator: MonitorCoordinator?
    /// Set to `true` before calling `NSApp.terminate` from an explicit user action
    /// (right-click → Quit Nick) so `applicationShouldTerminate` allows the quit
    /// even when the main window is hidden.
    private var forceQuit = false

    /// Injected by `MainWindowView.onAppear`. Calls SwiftUI's `openSettings` environment
    /// action so the status-bar "Settings..." menu item opens the Settings scene through
    /// the official path instead of the private `showSettingsWindow:` selector.
    var openSettingsAction: (() -> Void)?

    /// Injected by `MainWindowView.onAppear`. Calls SwiftUI's `openWindow(id:"main")`
    /// action so the status-bar click can ask SwiftUI to (re)create the window when it
    /// has been fully closed rather than just hidden.
    var openMainWindowAction: (() -> Void)?

    // MARK: - NSApplicationDelegate

    func applicationDidFinishLaunching(_ notification: Notification) {
        // Register defaults so first-run behaviour matches configured behaviour.
        // Must run before any code that reads these keys.
        UserDefaults.standard.register(defaults: [
            "notificationThresholdRaw": SignalSeverity.high.rawValue,
            "deepScanIntervalSeconds": 60
        ])
        setupStatusItem()
        // Prune stale threat log entries (> 90 days) on every launch.
        Task.detached(priority: .background) {
            if let container = try? ModelContainer(for: ThreatLogEntry.self, migrationPlan: ThreatLogMigrationPlan.self) {
                let threatLogger = ThreatLogger(container: container)
                await threatLogger.pruneOlderThan(days: 90)
            }
        }
        Task { @MainActor in
            engine.runFullScan()
            let coord = MonitorCoordinator(engine: engine, correlator: ThreatCorrelator())
            coordinator = coord
            coord.startRealTimePipeline()
            NotificationManager.shared.setup()
            NSApp.servicesProvider = NickServicesProvider()
            NSUpdateDynamicServices()
            configureMainWindowDelegate()
        }
    }

    /// Keep Nick alive in the background when the last window closes.
    /// The app only quits via the right-click menu or ⌘Q while the window is visible.
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        return false
    }

    /// Allow termination only when (a) the user explicitly chose Quit from the
    /// right-click menu (`forceQuit == true`), or (b) the main window is currently
    /// visible (i.e. ⌘Q is meaningful to the user).
    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        if forceQuit { return .terminateNow }
        // canBecomeMain is unreliable during .accessory→.regular transitions; filter by
        // class instead. Prefer the titled "Nick" window over any other non-panel window.
        let mainWindow = NSApp.windows.first(where: { !$0.isSheet && !($0 is NSPanel) && $0.title == "Nick" })
                      ?? NSApp.windows.first(where: { !$0.isSheet && !($0 is NSPanel) })
        let windowVisible = mainWindow?.isVisible ?? false
        return windowVisible ? .terminateNow : .terminateCancel
    }

    /// Re-opening (e.g., dock icon click when LSUIElement is temporarily .regular) should surface the window.
    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows: Bool) -> Bool {
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
    }

    @objc private func handleStatusItemClick(_ sender: NSStatusBarButton) {
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
