// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import AppKit

// MARK: - Main window lookup

extension NSApplication {

    /// The SwiftUI `Window("Nick", id: "main")` window.
    ///
    /// Don't match on the title: `navigationTitle` renames the window to the
    /// current page ("Home", "Overview", …). Don't take the first non-panel
    /// window either: the menu bar icon's `NSStatusBarWindow` and the Settings
    /// window are in `windows` too, and picking one of those is why a menu bar
    /// click used to show the Dock icon without bringing the window forward.
    var nickMainWindow: NSWindow? {
        let candidates = windows.filter(MainWindowLocator.isCandidate)
        return candidates.first { MainWindowLocator.isMainIdentifier($0.identifier?.rawValue) }
            ?? candidates.first
    }
}

enum MainWindowLocator {

    /// SwiftUI names the window after the scene id ("main", "main-AppWindow-1").
    static func isMainIdentifier(_ identifier: String?) -> Bool {
        guard let identifier else { return false }
        return identifier == "main" || identifier.hasPrefix("main-")
    }

    static func isSettingsIdentifier(_ identifier: String?) -> Bool {
        identifier?.localizedCaseInsensitiveContains("settings") ?? false
    }

    @MainActor
    static func isCandidate(_ window: NSWindow) -> Bool {
        !window.isSheet
            && !(window is NSPanel)
            && !String(describing: type(of: window)).contains("StatusBar")
            && !isSettingsIdentifier(window.identifier?.rawValue)
    }
}
