// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation

// MARK: - InterfaceMode

/// App-wide presentation mode.
///
/// **Simple** is the default: plain language, four destinations, no technical
/// data at first glance. **Advanced** is the full power-user interface with
/// every section. The mode only changes presentation — detection, the
/// extensions, XPC, and the engine behave identically in both.
enum InterfaceMode: String, CaseIterable, Identifiable, Sendable {
    case simple
    case advanced

    /// `UserDefaults` / `@AppStorage` key. Read it only through this constant.
    static let storageKey = "interfaceMode"

    var id: String { rawValue }

    var title: String {
        switch self {
        case .simple:   "Simple"
        case .advanced: "Advanced"
        }
    }

    var toggled: InterfaceMode { self == .simple ? .advanced : .simple }
}

// MARK: - Migration

enum InterfaceModeMigration {

    /// The per-feature alert setting that `InterfaceMode` replaces.
    static let legacySimpleAlertsKey = "simpleAlertMode"

    /// Runs once, before any view reads the mode.
    ///
    /// - New installs start in Simple.
    /// - Existing users who had turned simple alerts **off** keep the
    ///   technical presentation they chose, so they start in Advanced.
    /// - The legacy key is removed afterwards.
    static func migrateIfNeeded(defaults: UserDefaults = .standard) {
        guard defaults.object(forKey: InterfaceMode.storageKey) == nil else {
            defaults.removeObject(forKey: legacySimpleAlertsKey)
            return
        }
        let preferredTechnicalAlerts =
            defaults.object(forKey: legacySimpleAlertsKey) != nil
            && defaults.bool(forKey: legacySimpleAlertsKey) == false
        let mode: InterfaceMode = preferredTechnicalAlerts ? .advanced : .simple
        defaults.set(mode.rawValue, forKey: InterfaceMode.storageKey)
        defaults.removeObject(forKey: legacySimpleAlertsKey)
    }
}
