// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Cocoa
import FinderSync

// MARK: - NickFinderSync main entry point

/// Finder Sync Extension principal class.
/// Registered in the extension's Info.plist as NSExtensionPrincipalClass.
@NSApplicationMain
class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        let controller = FIFinderSyncController.default()
        if !controller.isSyncingEnabled {
            NSLog("NickFinderSync: Finder Sync is not enabled for this extension.")
        }
    }
}
