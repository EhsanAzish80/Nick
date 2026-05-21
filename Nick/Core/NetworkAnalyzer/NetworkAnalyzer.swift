import Foundation
import Network

/// Monitors active network connections and flags suspicious activity.
@MainActor
final class NetworkAnalyzer: ObservableObject {

    @Published private(set) var isRunning = false
    @Published private(set) var activeConnections: [ConnectionInfo] = []

    weak var correlator: ThreatCorrelator?

    // MARK: - Lifecycle

    func start() {
        guard !isRunning else { return }
        isRunning = true
        // TODO: Enumerate connections via sysctl NET_RT_DUMP2 / netstat equivalent
    }

    func stop() {
        isRunning = false
    }

    // MARK: - Detection stubs

    /// Flags shell processes (bash, zsh, sh, python) with outbound connections.
    private func detectReverseShell(connection: ConnectionInfo) {
        let shellNames = ["bash", "zsh", "sh", "python3", "python", "ruby", "perl"]
        guard shellNames.contains(connection.processName) else { return }
        let signal = ThreatSignal(
            source: .networkAnalysis,
            severity: .critical,
            title: "Possible reverse shell",
            detail: "\(connection.processName) (PID \(connection.pid)) has outbound connection to \(connection.remoteAddress)",
            pid: connection.pid,
            resource: connection.remoteAddress
        )
        correlator?.ingest(signal)
    }
}

// MARK: - Supporting Types

struct ConnectionInfo: Identifiable, Sendable {
    let id: UUID
    let pid: Int32
    let processName: String
    let localAddress: String
    let remoteAddress: String
    let state: String
}
