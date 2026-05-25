// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Cocoa
import FinderSync

// MARK: - NickFinderSyncExtension

/// Finder Sync Extension that adds "Scan with Nick" to the Finder right-click menu.
///
/// Watches /, ~/Downloads, ~/Desktop, and /Applications. When the user selects
/// "Scan with Nick" on any file/folder, the file URL is posted via App Group
/// UserDefaults and the main Nick app is opened to process it.
///
/// **App Group:** group.com.ehsanazish.nick
/// **Bundle ID:** com.ehsanazish.nick.findersync
///
/// Setup required in Xcode:
/// 1. Add NickFinderSync as a new Finder Sync Extension target
/// 2. Set Bundle Identifier to com.ehsanazish.nick.findersync
/// 3. Add App Groups capability with group.com.ehsanazish.nick to both targets
/// 4. Embed the extension in the main Nick app
final class NickFinderSyncExtension: FIFinderSync {

    // MARK: - Constants

    private static let appGroupID = "group.com.ehsanazish.nick"
    private static let pendingScanKey = "pendingFinderScanURL"

    // MARK: - Init

    override init() {
        super.init()

        let watchedDirectories: [URL] = [
            URL(fileURLWithPath: "/"),
            FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Downloads"),
            FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Desktop"),
            URL(fileURLWithPath: "/Applications")
        ]
        FIFinderSyncController.default().directoryURLs = Set(watchedDirectories)
    }

    // MARK: - FIFinderSync

    override var toolbarItemName: String { "Nick" }
    override var toolbarItemToolTip: String { "Scan this item with Nick" }
    override var toolbarItemImage: NSImage { NSImage(systemSymbolName: "shield", accessibilityDescription: nil) ?? NSImage() }

    override func menu(for menuKind: FIMenuKind) -> NSMenu {
        let menu = NSMenu(title: "")
        let item = NSMenuItem(
            title: "Scan with Nick",
            action: #selector(scanSelectedItems(_:)),
            keyEquivalent: ""
        )
        item.target = self
        menu.addItem(item)
        return menu
    }

    @objc private func scanSelectedItems(_ sender: AnyObject?) {
        guard let items = FIFinderSyncController.default().selectedItemURLs(),
              let first = items.first else { return }

        // Post URL to main app via App Group UserDefaults.
        let sharedDefaults = UserDefaults(suiteName: Self.appGroupID)
        sharedDefaults?.set(first.absoluteString, forKey: Self.pendingScanKey)
        sharedDefaults?.synchronize()

        // Open Nick main app.
        if let appURL = NSWorkspace.shared.urlForApplication(withBundleIdentifier: "com.ehsanazish.nick") {
            NSWorkspace.shared.open(appURL)
        }
    }
}
