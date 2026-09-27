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

    init() {
        // Must run before any view reads `@AppStorage(InterfaceMode.storageKey)`.
        InterfaceModeMigration.migrateIfNeeded()
    }

    private var isRunningTests: Bool {
        let environment = ProcessInfo.processInfo.environment
        return environment["XCTestConfigurationFilePath"] != nil
            || environment["XCTestBundlePath"] != nil
            || environment["XCInjectBundleInto"] != nil
            || environment["DYLD_INSERT_LIBRARIES"]?.contains("XCTest") == true
            || CommandLine.arguments.contains("-ApplePersistenceIgnoreState")
    }

    private var isUninstallMaintenanceMode: Bool {
        CommandLine.arguments.contains("--prepare-uninstall")
    }

    var body: some Scene {
        // The scenes always exist because SceneBuilder cannot branch, but their
        // view closures avoid touching SecurityEngine in maintenance mode.
        Window("Nick", id: "main") {
            if isUninstallMaintenanceMode || isRunningTests {
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
            width: isUninstallMaintenanceMode || isRunningTests ? 1 : 900,
            height: isUninstallMaintenanceMode || isRunningTests ? 1 : 620
        )
        .defaultPosition(.center)
        .windowResizability(.contentMinSize)
        .commands {
            InterfaceModeCommands()
            ScanCommands(engine: appDelegate.engine)
        }

        Settings {
            if isUninstallMaintenanceMode || isRunningTests {
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

// MARK: - InterfaceModeCommands

/// View ▸ Advanced Mode (⇧⌘A).
struct InterfaceModeCommands: Commands {
    @AppStorage(InterfaceMode.storageKey) private var interfaceMode: InterfaceMode = .simple

    var body: some Commands {
        CommandGroup(after: .sidebar) {
            Toggle("Advanced Mode", isOn: Binding(
                get: { interfaceMode == .advanced },
                set: { interfaceMode = $0 ? .advanced : .simple }
            ))
            .keyboardShortcut("a", modifiers: [.command, .shift])
        }
    }
}

// MARK: - ScanCommands

/// Scan ▸ Run Full Scan (⌘R), available in Simple and Advanced.
struct ScanCommands: Commands {
    let engine: SecurityEngine

    var body: some Commands {
        CommandMenu("Scan") {
            Button("Run Full Scan") { engine.runFullScan() }
                .keyboardShortcut("r", modifiers: .command)
                .disabled(engine.isScanning)
        }
    }
}
