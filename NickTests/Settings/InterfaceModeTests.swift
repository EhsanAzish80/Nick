// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import XCTest
@testable import Nick

final class InterfaceModeTests: XCTestCase {

    private var defaults: UserDefaults!
    private var suiteName: String!

    override func setUp() {
        super.setUp()
        suiteName = "InterfaceModeTests-\(UUID().uuidString)"
        defaults = UserDefaults(suiteName: suiteName)
    }

    override func tearDown() {
        defaults.removePersistentDomain(forName: suiteName)
        super.tearDown()
    }

    func test_freshInstallStartsSimple() {
        InterfaceModeMigration.migrateIfNeeded(defaults: defaults)
        XCTAssertEqual(defaults.string(forKey: InterfaceMode.storageKey), InterfaceMode.simple.rawValue)
    }

    func test_userWhoTurnedOffSimpleAlertsKeepsAdvanced() {
        defaults.set(false, forKey: InterfaceModeMigration.legacySimpleAlertsKey)
        InterfaceModeMigration.migrateIfNeeded(defaults: defaults)
        XCTAssertEqual(defaults.string(forKey: InterfaceMode.storageKey), InterfaceMode.advanced.rawValue)
        XCTAssertNil(defaults.object(forKey: InterfaceModeMigration.legacySimpleAlertsKey))
    }

    func test_userWithSimpleAlertsOnStartsSimple() {
        defaults.set(true, forKey: InterfaceModeMigration.legacySimpleAlertsKey)
        InterfaceModeMigration.migrateIfNeeded(defaults: defaults)
        XCTAssertEqual(defaults.string(forKey: InterfaceMode.storageKey), InterfaceMode.simple.rawValue)
    }

    func test_existingChoiceIsNeverOverwritten() {
        defaults.set(InterfaceMode.advanced.rawValue, forKey: InterfaceMode.storageKey)
        defaults.set(true, forKey: InterfaceModeMigration.legacySimpleAlertsKey)
        InterfaceModeMigration.migrateIfNeeded(defaults: defaults)
        XCTAssertEqual(defaults.string(forKey: InterfaceMode.storageKey), InterfaceMode.advanced.rawValue)
        XCTAssertNil(defaults.object(forKey: InterfaceModeMigration.legacySimpleAlertsKey))
    }

    func test_toggleFlipsMode() {
        XCTAssertEqual(InterfaceMode.simple.toggled, .advanced)
        XCTAssertEqual(InterfaceMode.advanced.toggled, .simple)
    }
}

final class InterfaceModeRoutingTests: XCTestCase {

    func test_advancedToSimpleKeepsEquivalentPage() {
        XCTAssertEqual(InterfaceModeRouting.simpleSection(for: .overview), .home)
        XCTAssertEqual(InterfaceModeRouting.simpleSection(for: .smartScan), .scan)
        XCTAssertEqual(InterfaceModeRouting.simpleSection(for: .scan), .scan)
        XCTAssertEqual(InterfaceModeRouting.simpleSection(for: .alerts), .activity)
        XCTAssertEqual(InterfaceModeRouting.simpleSection(for: .quarantine), .activity)
        XCTAssertEqual(InterfaceModeRouting.simpleSection(for: .settings), .settings)
        XCTAssertEqual(InterfaceModeRouting.simpleSection(for: .processes), .home)
        XCTAssertEqual(InterfaceModeRouting.simpleSection(for: nil), .home)
    }

    func test_simpleToAdvancedKeepsEquivalentPage() {
        XCTAssertEqual(InterfaceModeRouting.advancedSection(for: .home), .overview)
        XCTAssertEqual(InterfaceModeRouting.advancedSection(for: .scan), .smartScan)
        XCTAssertEqual(InterfaceModeRouting.advancedSection(for: .activity), .alerts)
        XCTAssertEqual(InterfaceModeRouting.advancedSection(for: .protection), .settings)
        XCTAssertEqual(InterfaceModeRouting.advancedSection(for: .settings), .settings)
    }

    func test_simpleSidebarHasFourItemsPlusSettings() {
        XCTAssertEqual(SimpleSection.primary, [.home, .scan, .activity, .protection])
        XCTAssertEqual(SimpleSection.allCases.count, 5)
    }
}
