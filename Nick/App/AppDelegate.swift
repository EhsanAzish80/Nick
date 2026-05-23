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

    // MARK: - NSApplicationDelegate

    func applicationDidFinishLaunching(_ notification: Notification) {
        setupStatusItem()
        Task { @MainActor in
            engine.runFullScan()
            NotificationManager.shared.setup()
            NSApp.servicesProvider = NickServicesProvider()
            NSUpdateDynamicServices()
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
            openMainWindow()
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

    @objc func openMainWindow() {
        NSApp.setActivationPolicy(.regular)
        NSApp.activate(ignoringOtherApps: true)
        // SwiftUI creates the NSWindow for a Window scene at launch (hidden).
        if let window = NSApp.windows.first(where: { !$0.isSheet && $0.canBecomeMain }) {
            window.makeKeyAndOrderFront(nil)
        }
    }
}
