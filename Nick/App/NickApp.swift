// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import SwiftUI

// MARK: - NickApp

/// Menu bar application entry point.
///
/// Nick runs as a menu bar only application (`LSUIElement = YES` in `Info.plist`).
/// The main window is presented via `MenuBarExtra` with the `.window` style so it
/// pops up directly below the status item without appearing in the Dock or the
/// ⌘-Tab switcher.
@main
struct NickApp: App {

    @State private var engine: SecurityEngine

    init() {
        let eng = SecurityEngine()
        _engine = State(initialValue: eng)
        // All NSApp interactions are deferred until the main actor is live —
        // NSApp is not fully initialised during the SwiftUI @main struct init().
        Task { @MainActor in
            eng.runFullScan()
            NotificationManager.shared.setup()
            // Register as a macOS Services provider (Finder right-click "Scan with Nick").
            NSApp.servicesProvider = NickServicesProvider()
            NSUpdateDynamicServices()
        }
    }

    var body: some Scene {
        MenuBarExtra {
            DashboardView()
                .environment(engine)
                .preferredColorScheme(.dark)
                .frame(width: NickLayout.windowWidth, height: NickLayout.windowHeight)
        } label: {
            MenuBarLabel(engine: engine)
        }
        .menuBarExtraStyle(.window)

        Settings {
            SettingsView()
                .environment(engine)
        }
    }
}

// MARK: - MenuBarLabel

/// Status item icon and badge displayed in the menu bar.
private struct MenuBarLabel: View {

    let engine: SecurityEngine

    var body: some View {
        HStack(spacing: 4) {
            Image(systemName: statusImageName)
                .symbolRenderingMode(.palette)
                .foregroundStyle(statusColor, .secondary)
            if !engine.alerts.filter({ $0.severity >= .high }).isEmpty {
                Text("\(engine.alerts.filter({ $0.severity >= .high }).count)")
                    .font(.system(size: 10, weight: .bold, design: .rounded))
                    .foregroundStyle(.red)
            }
        }
    }

    private var statusImageName: String {
        guard !engine.alerts.isEmpty else { return "shield.fill" }
        let max = engine.alerts.map(\.severity).max() ?? .info
        switch max {
        case .info:     return "shield.fill"
        case .low:      return "shield.fill"
        case .medium:   return "shield.lefthalf.filled"
        case .high:     return "shield.slash.fill"
        case .critical: return "exclamationmark.shield.fill"
        }
    }

    private var statusColor: Color {
        guard !engine.alerts.isEmpty else { return .green }
        let max = engine.alerts.map(\.severity).max() ?? .info
        switch max {
        case .info, .low:           return .green
        case .medium:               return .yellow
        case .high, .critical:      return .red
        }
    }
}
