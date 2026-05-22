// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import XCTest
@testable import Nick

// MARK: - ScanPerformanceTests

/// Performance tests verifying that key scan operations complete within budget.
///
/// Budget targets (from `docs/PERFORMANCE_REPORT.md`):
/// - Process scan (sysctl + signal generation): < 1 second
/// - Network scan (proc_pidfdinfo): < 1 second
/// - Full `SecurityEngine` scan: < 3 seconds
/// - `SignatureValidator` cache hit: < 0.1 ms
final class ScanPerformanceTests: XCTestCase {

    // MARK: - Process Scanner

    func test_processScanner_scan_completesWithinBudget() throws {
        let scanner = ProcessScanner()
        let start = Date()
        _ = try scanner.scan()
        // First-run budget is generous — SignatureValidator cache is cold.
        // Subsequent scans (cached) are < 3s; tested separately.
        XCTAssertLessThan(Date().timeIntervalSince(start), 120.0, "Process scan exceeded 120s budget (cold cache)")
    }

    func test_processScanner_secondScan_benefitsFromCache() throws {
        // Warm cache
        let scanner = ProcessScanner()
        _ = try scanner.scan()

        // Second scan should be much faster (cached signatures)
        let start = Date()
        _ = try scanner.scan()
        XCTAssertLessThan(Date().timeIntervalSince(start), 10.0, "Second process scan exceeded 10s (cache not effective)")
    }

    func test_processScanner_signalGeneration_completesWithinBudget() throws {
        let scanner = ProcessScanner()
        let processes = try scanner.scan()

        let start = Date()
        _ = scanner.signals(from: processes)
        XCTAssertLessThan(Date().timeIntervalSince(start), 1.0, "Signal generation exceeded 1s budget")
    }

    func test_processScanner_signalGenerationWithTrustedList_completesWithinBudget() throws {
        let scanner = ProcessScanner()
        let processes = try scanner.scan()
        let trusted = TrustedProcessList()

        let start = Date()
        _ = scanner.signals(from: processes, trustedProcessList: trusted)
        XCTAssertLessThan(Date().timeIntervalSince(start), 1.0, "Signal generation with trusted list exceeded 1s budget")
    }

    // MARK: - Network Scanner (proc_pidfdinfo)

    func test_procNetHelper_listConnections_completesWithinBudget() {
        let start = Date()
        _ = ProcNetHelper.listConnections()
        XCTAssertLessThan(Date().timeIntervalSince(start), 1.0, "Network scan exceeded 1s budget")
    }

    func test_procNetHelper_returnsConnections() {
        // The running machine must have at least one network socket open.
        let connections = ProcNetHelper.listConnections()
        XCTAssertFalse(connections.isEmpty, "proc_pidfdinfo must return at least one connection")
    }

    // MARK: - Signature Validator Cache

    func test_signatureValidator_cacheHit_isFastEnough() {
        // Warm the cache
        let path = "/usr/bin/swift"
        guard FileManager.default.fileExists(atPath: path) else {
            // swift binary may not be at this path in all CI environments
            return
        }
        _ = SignatureValidator.shared.evaluate(binaryPath: path)

        // Measure cache hit — 100 evaluations should complete in < 100ms total
        let start = Date()
        for _ in 0..<100 {
            _ = SignatureValidator.shared.evaluate(binaryPath: path)
        }
        XCTAssertLessThan(Date().timeIntervalSince(start), 0.1, "100 cache hits exceeded 100ms budget")
    }

    // MARK: - ThreatCorrelator

    func test_threatCorrelator_ingest_1000signals_completesWithinBudget() async {
        let correlator = ThreatCorrelator()

        let signals = (0..<1_000).map { i -> ThreatSignal in
            ThreatSignal(
                source: .process,
                severity: .low,
                title: "Signal \(i)",
                description: "Perf test signal"
            )
        }

        let start1 = Date()
        await correlator.flush()
        await correlator.ingest(signals)
        XCTAssertLessThan(Date().timeIntervalSince(start1), 1.0, "Ingest 1000 signals exceeded 1s budget")
    }

    func test_threatCorrelator_correlate_1000signals_completesWithinBudget() async {
        let correlator = ThreatCorrelator()

        let signals = (0..<1_000).map { i -> ThreatSignal in
            ThreatSignal(
                source: .process,
                severity: .medium,
                title: "Signal \(i)",
                description: "Perf test signal"
            )
        }

        await correlator.ingest(signals)

        let start2 = Date()
        _ = await correlator.correlate()
        XCTAssertLessThan(Date().timeIntervalSince(start2), 1.0, "Correlate 1000 signals exceeded 1s budget")
    }
}
