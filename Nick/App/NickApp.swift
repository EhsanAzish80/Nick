// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import AppKit
import SwiftUI

// MARK: - AppAppearance

enum AppAppearance: String, CaseIterable {
    case system = "System"
    case light  = "Light"
    case dark   = "Dark"
}

// MARK: - NickApp

/// Menu bar application entry point.
///
/// Nick runs as a menu bar application (`LSUIElement = YES`). The main window is
/// a full `NavigationSplitView` accessed by clicking the status item. All setup
/// (engine start, NSStatusItem, services) is handled by `AppDelegate`.
@main
struct NickApp: App {

    @NSApplicationDelegateAdaptor(AppDelegate.self) var appDelegate

    private var isUninstallMaintenanceMode: Bool {
        CommandLine.arguments.contains("--prepare-uninstall")
    }

    var body: some Scene {
        // The scenes always exist because SceneBuilder cannot branch, but their
        // view closures avoid touching SecurityEngine in maintenance mode.
        Window("Nick", id: "main") {
            if isUninstallMaintenanceMode {
                EmptyView()
            } else {
                MainWindowView()
                    .environment(appDelegate.engine)
                    .environment(appDelegate.xpcClient)
                    .environment(appDelegate.networkProtection)
                    .frame(minWidth: 760, minHeight: 520)
            }
        }
        .windowStyle(.titleBar)
        .windowToolbarStyle(.unified)
        .defaultSize(
            width: isUninstallMaintenanceMode ? 1 : 900,
            height: isUninstallMaintenanceMode ? 1 : 620
        )
        .defaultPosition(.center)
        .windowResizability(.contentMinSize)

        Settings {
            if isUninstallMaintenanceMode {
                EmptyView()
            } else {
                SettingsView()
                    .environment(appDelegate.engine)
                    .environment(appDelegate.xpcClient)
                    .environment(appDelegate.networkProtection)
            }
        }
    }
}
