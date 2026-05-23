// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import AppKit

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
    /// Set to `true` before calling `NSApp.terminate` from an explicit user action
    /// (right-click → Quit Nick) so `applicationShouldTerminate` allows the quit
    /// even when the main window is hidden.
    private var forceQuit = false

    /// Injected by `MainWindowView.onAppear`. Calls SwiftUI's `openSettings` environment
    /// action so the status-bar "Settings..." menu item opens the Settings scene through
    /// the official path instead of the private `showSettingsWindow:` selector.
    var openSettingsAction: (() -> Void)?

    // MARK: - NSApplicationDelegate

    func applicationDidFinishLaunching(_ notification: Notification) {
        setupStatusItem()
        Task { @MainActor in
            engine.runFullScan()
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
        let windowVisible = NSApp.windows.first(where: { !$0.isSheet && $0.canBecomeMain })?.isVisible ?? false
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

        // SwiftUI's SettingsLink sends showSettingsWindow: up the responder chain.
        // Replicating that here keeps the Settings scene as the single source of truth.
        let settingsItem = NSMenuItem(
            title:         "Settings...",
            action:        #selector(openSettings),
            keyEquivalent: ","
        )
        settingsItem.keyEquivalentModifierMask = .command
        settingsItem.target = self
        menu.addItem(settingsItem)

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
        if let window = NSApp.windows.first(where: { !$0.isSheet && $0.canBecomeMain }),
           window.isVisible && window.isKeyWindow {
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
            if let window = NSApp.windows.first(where: { !$0.isSheet && $0.canBecomeMain }) {
                window.delegate = self.mainWindowDelegate
            }
        }
    }

    @objc func openMainWindow() {
        // Flip policy first — makes the app eligible to become frontmost and appear in Dock.
        NSApp.setActivationPolicy(.regular)

        // Give the policy change ~0.1 s to propagate through the window server before
        // issuing activation calls. Re-query the window inside the block so we always
        // act on the live NSWindow reference (avoids silent no-ops from stale weak refs).
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.1) { [weak self] in
            guard let self else { return }
            if let window = NSApp.windows.first(where: { !$0.isSheet && $0.canBecomeMain }) {
                window.delegate = self.mainWindowDelegate
                window.makeKeyAndOrderFront(nil) // raise + acquire key focus
                window.orderFrontRegardless()    // force to front even if another app
                                                 // still owns the front position
            }
            NSApp.activate()                     // steal frontmost status from current app
        }
    }

    /// Opens the SwiftUI Settings scene via the `openSettings` environment action injected
    /// by `MainWindowView.onAppear`. Falls back to the sendAction path only if the action
    /// has not been set yet (e.g., Settings tapped before the main window first appeared).
    @objc private func openSettings() {
        if let action = openSettingsAction {
            action()
        } else {
            // Fallback: fires only on very first launch before MainWindowView has appeared.
            // SwiftUI will log a deprecation warning but Settings will still open.
            NSApp.sendAction(Selector(("showSettingsWindow:")), to: nil, from: nil)
        }
        NSApp.setActivationPolicy(.regular)
        NSApp.activate()
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
