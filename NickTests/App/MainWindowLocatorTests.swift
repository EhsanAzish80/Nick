// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import AppKit
import XCTest
@testable import Nick

final class MainWindowLocatorTests: XCTestCase {
    func test_matchesTheMainSceneIdentifier() {
        XCTAssertTrue(MainWindowLocator.isMainIdentifier("main"))
        XCTAssertTrue(MainWindowLocator.isMainIdentifier("main-AppWindow-1"))
        XCTAssertFalse(MainWindowLocator.isMainIdentifier("mainly"))
        XCTAssertFalse(MainWindowLocator.isMainIdentifier(nil))
    }

    func test_recognisesTheSettingsWindow() {
        XCTAssertTrue(MainWindowLocator.isSettingsIdentifier("com_apple_SwiftUI_Settings_window"))
        XCTAssertFalse(MainWindowLocator.isSettingsIdentifier("main-AppWindow-1"))
    }

    @MainActor
    func test_hiddenWindowReopensThroughMenuBarEntryPoint() async {
        await withMainWindow { window, delegate in
            window.orderOut(nil)
            XCTAssertFalse(window.isVisible)
            var sceneRequests = 0
            delegate.openMainWindowAction = { sceneRequests += 1 }
            delegate.openMainWindow()
            XCTAssertTrue(window.isVisible)
            XCTAssertEqual(sceneRequests, 1)
        }
    }

    @MainActor
    func test_dockReopenShowsHiddenWindow() async {
        await withMainWindow { window, delegate in
            window.orderOut(nil)
            XCTAssertTrue(delegate.applicationShouldHandleReopen(NSApp, hasVisibleWindows: false))
            XCTAssertTrue(window.isVisible)
        }
    }

    @MainActor
    func test_notificationReopensMinimizedWindowAndPreservesAlertID() async {
        await withMainWindow { window, delegate in
            window.makeKeyAndOrderFront(nil)
            window.miniaturize(nil)
            try? await Task.sleep(for: .milliseconds(150))
            XCTAssertTrue(window.isMiniaturized)
            let center = NotificationCenter()
            let alertID = UUID()
            let navigated = expectation(description: "Alert navigation after window activation")
            let token = center.addObserver(forName: .nickNavigateToAlert, object: nil, queue: nil) { note in
                let receivedAlertID = note.userInfo?["alertID"] as? UUID
                MainActor.assumeIsolated {
                    XCTAssertFalse(window.isMiniaturized)
                    XCTAssertTrue(window.isVisible)
                    XCTAssertEqual(receivedAlertID, alertID)
                    navigated.fulfill()
                }
            }
            defer { center.removeObserver(token) }
            var sceneRequests = 0
            delegate.openMainWindowAction = { sceneRequests += 1 }
            delegate.openAlert(alertID, notificationCenter: center)
            XCTAssertEqual(sceneRequests, 1)
            await fulfillment(of: [navigated], timeout: 1)
        }
    }

    @MainActor
    private func withMainWindow(_ check: @MainActor (NSWindow, AppDelegate) async -> Void) async {
        // The inert XCTest app host owns this window, not the installed Nick app.
        let existing = NSApp.nickMainWindow
        let window = existing ?? NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 320, height: 200),
            styleMask: [.titled, .closable, .miniaturizable], backing: .buffered, defer: false
        )
        if existing == nil { window.identifier = NSUserInterfaceItemIdentifier("main") }
        let visible = window.isVisible
        let minimized = window.isMiniaturized
        let previousDelegate = window.delegate
        let policy = NSApp.activationPolicy()
        let delegate = AppDelegate()
        await check(window, delegate)
        // Allow the existing 100 ms window-ordering callback to finish before cleanup.
        try? await Task.sleep(for: .milliseconds(150))
        delegate.openMainWindowAction = nil
        window.delegate = previousDelegate
        if minimized { window.miniaturize(nil) }
        else if visible { window.makeKeyAndOrderFront(nil) }
        else { window.orderOut(nil) }
        if existing == nil { window.close() }
        NSApp.setActivationPolicy(policy)
    }

}
