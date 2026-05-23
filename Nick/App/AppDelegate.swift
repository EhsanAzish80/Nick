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

        // SwiftUI Settings scene responds to this semi-private selector.
        let settingsItem = NSMenuItem(
            title:         "Settings...",
            action:        Selector(("showSettingsWindow:")),
            keyEquivalent: ","
        )
        settingsItem.keyEquivalentModifierMask = .command
        menu.addItem(settingsItem)

        menu.addItem(.separator())

        let quitItem = NSMenuItem(
            title:         "Quit Nick",
            action:        #selector(NSApplication.terminate(_:)),
            keyEquivalent: "q"
        )
        quitItem.keyEquivalentModifierMask = .command
        menu.addItem(quitItem)

        // Assign menu so performClick shows it, then clear so left-click uses the action handler.
        statusItem?.menu = menu
        statusItem?.button?.performClick(nil)
        statusItem?.menu = nil
    }

    /// Toggles the main window: hides if visible, shows if hidden. Used by the status item left-click.
    @objc private func toggleMainWindow() {
        if let window = NSApp.windows.first(where: { !$0.isSheet && $0.canBecomeMain }),
           window.isVisible {
            window.orderOut(nil)
            NSApp.setActivationPolicy(.accessory)
        } else {
            openMainWindow()
        }
    }

    /// Attaches the window delegate so the red close button hides instead of destroying the window.
    /// Safe to call multiple times — only sets the delegate if it isn't already assigned.
    private func configureMainWindowDelegate() {
        guard let window = NSApp.windows.first(where: { !$0.isSheet && $0.canBecomeMain }),
              window.delegate == nil else { return }
        window.delegate = mainWindowDelegate
    }

    @objc func openMainWindow() {
        NSApp.setActivationPolicy(.regular)
        NSApp.activate(ignoringOtherApps: true)
        // SwiftUI creates the NSWindow for a Window scene at launch (hidden).
        if let window = NSApp.windows.first(where: { !$0.isSheet && $0.canBecomeMain }) {
            window.makeKeyAndOrderFront(nil)
            // Ensure the delegate is attached even if the window was created after launch.
            if window.delegate == nil {
                window.delegate = mainWindowDelegate
            }
        }
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
