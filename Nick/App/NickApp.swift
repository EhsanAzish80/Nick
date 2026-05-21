import SwiftUI

@main
struct NickApp: App {

    // MARK: - Core Services
    @StateObject private var correlator    = ThreatCorrelator()
    @StateObject private var processMonitor = ProcessMonitor()
    @StateObject private var persistenceWatcher = PersistenceWatcher()
    @StateObject private var networkAnalyzer = NetworkAnalyzer()
    @StateObject private var auditor       = SystemAuditor()

    var body: some Scene {
        // Menu bar item — no Dock icon (LSUIElement = YES in Info.plist)
        MenuBarExtra("Nick", systemImage: "shield.fill") {
            DashboardView()
                .environmentObject(correlator)
                .environmentObject(auditor)
        }
        .menuBarExtraStyle(.window)

        Settings {
            // TODO: NickSettingsView()
            Text("Settings")
                .padding()
        }
    }

    init() {
        // Wire monitors to the correlator
        Task { @MainActor in
            processMonitor.correlator    = correlator
            persistenceWatcher.correlator = correlator
            networkAnalyzer.correlator   = correlator
        }
    }
}
