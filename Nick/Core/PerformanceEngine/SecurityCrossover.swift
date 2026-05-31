// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation

/// Bridges performance scan results with active security threats.
final class SecurityCrossover: Sendable {

    struct CrossoverAlert: Sendable {
        let threatAlert: ThreatAlert
        let relatedJunkItems: [JunkItem]
        let totalWasteBytes: Int64
        let recommendation: String
    }

    private let performanceMonitor: PerformanceMonitor
    private let securityEngine: SecurityEngine

    init(performanceMonitor: PerformanceMonitor, securityEngine: SecurityEngine) {
        self.performanceMonitor = performanceMonitor
        self.securityEngine = securityEngine
    }

    /// Returns a crossover alert if the threat's contributing signals mention a process path
    /// that matches any junk items found during the last scan.
    @MainActor
    func crossReference(threat: ThreatAlert) -> CrossoverAlert? {
        // Extract process paths from contributing signal contexts
        let processPath = threat.contributingSignals
            .compactMap { $0.processInfo?.path }
            .first ?? ""
        guard !processPath.isEmpty else { return nil }

        let related = performanceMonitor.findItemsForProcess(processPath: processPath)
        guard !related.isEmpty else { return nil }

        let waste = related.reduce(0) { $0 + $1.size }
        let gb = String(format: "%.1f", Double(waste) / 1_000_000_000)
        let recommendation = "The flagged process has \(related.count) associated junk item(s) totalling \(gb) GB. Consider cleaning them after resolving the threat."

        return CrossoverAlert(
            threatAlert: threat,
            relatedJunkItems: related,
            totalWasteBytes: waste,
            recommendation: recommendation
        )
    }
}
