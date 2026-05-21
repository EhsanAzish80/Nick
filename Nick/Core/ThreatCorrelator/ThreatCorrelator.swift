import Foundation

/// Combines signals from all monitors and produces a correlated threat score.
@MainActor
final class ThreatCorrelator: ObservableObject {

    // MARK: - Published State
    @Published private(set) var signals: [ThreatSignal] = []
    @Published private(set) var overallScore: Double = 0.0   // 0.0 – 1.0

    // MARK: - Ingest

    /// Accepts a new signal from any monitor and recalculates the overall score.
    func ingest(_ signal: ThreatSignal) {
        signals.append(signal)
        recalculate()
    }

    // MARK: - Scoring (stub — CoreML integration in v0.9)

    private func recalculate() {
        guard !signals.isEmpty else { overallScore = 0; return }
        let sum = signals.reduce(0.0) { $0 + Double($1.severity.rawValue) }
        let maxPossible = Double(ThreatSeverity.critical.rawValue) * Double(signals.count)
        overallScore = sum / maxPossible
    }

    // MARK: - Helpers

    func signals(for source: MonitorType) -> [ThreatSignal] {
        signals.filter { $0.source == source }
    }

    func clear() {
        signals.removeAll()
        overallScore = 0
    }
}
