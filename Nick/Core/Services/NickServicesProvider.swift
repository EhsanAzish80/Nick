// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import AppKit
import Foundation

// MARK: - NickServicesProvider

/// Registers Nick as a macOS Services provider so Finder's contextual menu and the
/// system Services menu expose a "Scan with Nick" item for selected files and folders.
///
/// Register once at startup:
/// ```swift
/// NSApp.servicesProvider = NickServicesProvider()
/// NSUpdateDynamicServices()
/// ```
///
/// The `NSServices` array in `Nick/Info.plist` declares the menu item name and
/// maps it to the `scanWithNick` selector below.
final class NickServicesProvider: NSObject {

    /// Services entry point called by AppKit when the user selects "Scan with Nick"
    /// from Finder's contextual menu or the global Services menu.
    ///
    /// Reads file URLs from the pasteboard and posts a `.nickScanFileRequest`
    /// notification for each URL. `DashboardView` observes this notification and
    /// opens the YARA scan sheet automatically.
    ///
    /// - Parameters:
    ///   - pboard: The pasteboard containing the selected file(s).
    ///   - userData: Optional user data string declared in `Info.plist` (unused).
    ///   - error: Output parameter for an error message if the service fails.
    @objc func scanWithNick(_ pboard: NSPasteboard,
                            userData: String,
                            error: AutoreleasingUnsafeMutablePointer<NSString?>) {
        // Prefer NSURL objects (modern path); fall back to NSFilenamesPboardType.
        let urls: [URL]
        if let items = pboard.readObjects(forClasses: [NSURL.self], options: nil) as? [URL],
           !items.isEmpty {
            urls = items
        } else if let names = pboard.propertyList(
            forType: NSPasteboard.PasteboardType(rawValue: "NSFilenamesPboardType")
        ) as? [String] {
            urls = names.map { URL(fileURLWithPath: $0) }
        } else {
            error.pointee = "Nick: no file URLs found on the pasteboard." as NSString
            return
        }

        DispatchQueue.main.async {
            // Scan only the first URL to avoid opening multiple sheets simultaneously.
            if let url = urls.first {
                NotificationCenter.default.post(name: .nickScanFileRequest, object: url)
            }
        }
    }
}
