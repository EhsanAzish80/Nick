import Foundation

/// Watches all known macOS persistence locations for additions or changes.
@MainActor
final class PersistenceWatcher: ObservableObject {

    @Published private(set) var isRunning = false
    @Published private(set) var watchedPaths: [String] = []

    weak var correlator: ThreatCorrelator?

    private static let persistencePaths: [String] = [
        "/Library/LaunchDaemons",
        "/Library/LaunchAgents",
        NSString("~/Library/LaunchAgents").expandingTildeInPath,
        "/Library/StartupItems",
        "/System/Library/LaunchDaemons",
        "/System/Library/LaunchAgents"
    ]

    // MARK: - Lifecycle

    func start() {
        guard !isRunning else { return }
        watchedPaths = Self.persistencePaths
        isRunning = true
        // TODO: Wire up FSEventStream for each path
    }

    func stop() {
        isRunning = false
        // TODO: Invalidate FSEventStream
    }

    // MARK: - Event handling (stub)

    private func handleChange(at path: String) {
        let signal = ThreatSignal(
            source: .persistenceWatch,
            severity: .high,
            title: "Persistence location changed",
            detail: "Change detected at \(path)",
            resource: path
        )
        correlator?.ingest(signal)
    }
}
