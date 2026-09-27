// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

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
}
