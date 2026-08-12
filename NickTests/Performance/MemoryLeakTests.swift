// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import XCTest
@testable import Nick

// MARK: - MemoryLeakTests

/// Tests that verify Nick's data structures do not grow unboundedly over repeated cycles.
///
/// These are stress tests, not true Instruments-based leak detectors. They verify that
/// the application-level safeguards (signal buffer caps, cache TTL, trusted list) prevent
/// pathological memory growth under sustained workloads.
///
/// For true leak detection, run Instruments > Leaks after 30 minutes of continuous
/// monitoring as documented in `docs/PERFORMANCE_REPORT.md`.
final class MemoryLeakTests: XCTestCase {

    // MARK: - ThreatCorrelator Signal Buffer

    func test_threatCorrelator_signalBuffer_doesNotExceedMaxBufferSize() async {
        let correlator = ThreatCorrelator()
        let cap = ThreatCorrelator.maxBufferSize

        // Flood with 3× the cap
        let flood = (0..<(cap * 3)).map { i -> ThreatSignal in
            ThreatSignal(
                source: .process,
                severity: .low,
                title: "Flood \(i)",
                description: "Memory leak test"
            )
        }

        await correlator.ingest(flood)
        let count = await correlator.bufferedSignalCount
        XCTAssertLessThanOrEqual(count, cap,
            "Signal buffer must not exceed maxBufferSize (\(cap)) after a flood")
    }

    func test_threatCorrelator_signalBuffer_retainsHighSeverityOverLow() async {
        let correlator = ThreatCorrelator()
        let cap = ThreatCorrelator.maxBufferSize

        // Fill with low-severity signals
        let lowSignals = (0..<cap).map { i -> ThreatSignal in
            ThreatSignal(
                source: .process,
                severity: .low,
                title: "Low \(i)",
                description: "Low severity flood"
            )
        }
        await correlator.ingest(lowSignals)

        // Now inject high-severity signals
        let highSignals = (0..<10).map { i -> ThreatSignal in
            ThreatSignal(
                source: .process,
                severity: .high,
                title: "High \(i)",
                description: "High severity signal"
            )
        }
        await correlator.ingest(highSignals)

        // Correlate to see if high-severity signals are still reachable
        let alerts = await correlator.correlate()
        // The multi-monitor rule fires if there are >= 3 medium-or-above signals.
        // We have 10 high-severity signals so it should fire.
        XCTAssertFalse(alerts.isEmpty,
            "High-severity signals must survive buffer cap enforcement")
    }

    // MARK: - SignatureValidator Cache

    func test_signatureValidator_repeatedEvaluations_doNotAllocateUnboundedly() {
        let validator = SignatureValidator.shared
        validator.clearCache()

        let path = "/bin/ls"
        // Evaluate the same path 1000 times — should all hit the cache after the first.
        for _ in 0..<1_000 {
            _ = validator.evaluate(binaryPath: path)
        }

        // The cache should have exactly 1 entry for /bin/ls
        XCTAssertEqual(validator.cacheCount, 1,
            "Repeated evaluations of the same path must not create multiple cache entries")
    }

    // MARK: - TrustedProcessList

    func test_trustedProcessList_repeatedAdds_noUnboundedGrowth() {
        var list = TrustedProcessList()
        // Add 10,000 of the same name — Set deduplicates, so count stays 1.
        for _ in 0..<10_000 {
            list.addUserTrusted("DuplicateApp")
        }
        XCTAssertEqual(list.userTrusted.count, 1,
            "Repeated adds of the same process name must not grow the trusted set")
    }

    func test_trustedProcessList_addAndRemove_noGrowth() {
        var list = TrustedProcessList()
        for i in 0..<1_000 {
            list.addUserTrusted("Proc\(i)")
            list.removeUserTrusted("Proc\(i)")
        }
        XCTAssertEqual(list.userTrusted.count, 0,
            "Add/remove cycles must leave the trusted set empty")
    }

    // MARK: - ProcessScanner

    func test_processScanner_repeatedScans_signalCountDoesNotGrow() async throws {
        let processes = try await Task.detached(priority: .utility) {
            try ProcessScanner().scan()
        }.value
        let scanner = ProcessScanner()

        var previousCount = -1
        for _ in 0..<5 {
            let signals = scanner.signals(from: processes)
            if previousCount >= 0 {
                XCTAssertEqual(signals.count, previousCount,
                    "Repeated signal generation from the same process list must return the same count")
            }
            previousCount = signals.count
        }
    }
}
