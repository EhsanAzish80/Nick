import Foundation

/// Monitors running processes for anomalous behaviour.
@MainActor
final class ProcessMonitor: ObservableObject {

    @Published private(set) var isRunning = false

    weak var correlator: ThreatCorrelator?

    // MARK: - Lifecycle

    func start() {
        guard !isRunning else { return }
        isRunning = true
        // TODO: Begin polling via proc_listallpids / sysctl kinfo_proc
    }

    func stop() {
        isRunning = false
    }

    // MARK: - Detection stubs

    /// Detects unsigned or ad-hoc signed binaries.
    private func checkCodeSigning(pid: Int32, path: String) {
        // TODO: Use SecCodeCopyGuestWithAttributes / SecStaticCodeCheckValidity
    }

    /// Flags processes running from suspicious directories.
    private func checkSuspiciousPath(pid: Int32, path: String) {
        let suspicious = ["/tmp", "/var/tmp", "/private/tmp"]
        guard suspicious.contains(where: { path.hasPrefix($0) }) else { return }
        let signal = ThreatSignal(
            source: .processAudit,
            severity: .medium,
            title: "Process in suspicious location",
            detail: "PID \(pid) running from \(path)",
            pid: pid,
            resource: path
        )
        correlator?.ingest(signal)
    }
}
