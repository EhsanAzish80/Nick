// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import AppKit
import SwiftUI

// MARK: - NickApp

/// Menu bar application entry point.
///
/// Nick runs as a menu bar application (`LSUIElement = YES`). The main window is
/// a full `NavigationSplitView` accessed by clicking the status item. All setup
/// (engine start, NSStatusItem, services) is handled by `AppDelegate`.
@main
struct NickApp: App {

    @NSApplicationDelegateAdaptor(AppDelegate.self) var appDelegate

    var body: some Scene {
        // Main application window — opened by clicking the menu bar icon.
        Window("Nick", id: "main") {
            MainWindowView()
                .environment(appDelegate.engine)
                .preferredColorScheme(.dark)
        }
        .windowStyle(.titleBar)
        .windowToolbarStyle(.unified)
        .defaultSize(width: 900, height: 620)
        .defaultPosition(.center)

        Settings {
            SettingsView()
                .environment(appDelegate.engine)
                .preferredColorScheme(.dark)
        }
    }
}
