// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import XCTest
import SwiftData
@testable import Nick

// MARK: - ThreatLoggerTests

/// Unit tests for `ThreatLogger`, `ThreatLogEntry`, and export functionality.
///
/// All tests use an in-memory `ModelContainer` — no files are written to disk.
final class ThreatLoggerTests: XCTestCase {

    private var container: ModelContainer!
    private var logger: ThreatLogger!

    override func setUp() async throws {
        try await super.setUp()
        let config = ModelConfiguration(isStoredInMemoryOnly: true)
        container = try ModelContainer(for: ThreatLogEntry.self, configurations: config)
        logger = ThreatLogger(container: container)
    }

    override func tearDown() async throws {
        container = nil
        logger = nil
        try await super.tearDown()
    }

    // MARK: - ThreatLogEntry init

    func test_logEntry_initFromAlert_populatesFields() {
        let alert = makeAlert(score: 0.85, severity: .high, title: "Test Alert")
        let entry = ThreatLogEntry(from: alert, explanation: "Explanation text")
        XCTAssertEqual(entry.id, alert.id)
        XCTAssertEqual(entry.alertTitle, alert.title)
        XCTAssertEqual(entry.score, alert.score)
        XCTAssertEqual(entry.severity, alert.severity.displayName.lowercased())
        XCTAssertEqual(entry.explanation, "Explanation text")
        XCTAssertFalse(entry.resolved)
    }

    func test_logEntry_initFromAlert_withSignals_extractsContext() {
        let alert = makeAlertWithSignals(score: 0.9, severity: .critical)
        let entry = ThreatLogEntry(from: alert)
        XCTAssertNotNil(entry.processName)
        XCTAssertNotNil(entry.remoteAddress)
        XCTAssertEqual(entry.contributingSignalIDs.count, 1)
        XCTAssertEqual(entry.contributingSignalSummaries.count, 1)
    }

    // MARK: - CRUD

    func test_log_persistsEntry() async {
        let alert = makeAlert(score: 0.7, severity: .high, title: "Persisted Alert")
        await logger.log(alert: alert, explanation: nil)

        let results = await logger.query(severity: nil, dateRange: nil, resolved: nil)
        XCTAssertEqual(results.count, 1)
        XCTAssertEqual(results.first?.alertTitle, "Persisted Alert")
    }

    func test_log_idempotent_doesNotDuplicate() async {
        let alert = makeAlert(score: 0.7, severity: .high, title: "Idempotent Alert")
        await logger.log(alert: alert, explanation: nil)
        await logger.log(alert: alert, explanation: "Updated explanation")

        let results = await logger.query(severity: nil, dateRange: nil, resolved: nil)
        XCTAssertEqual(results.count, 1)
        XCTAssertEqual(results.first?.explanation, "Updated explanation")
    }

    func test_markResolved_updatesEntry() async {
        let alert = makeAlert(score: 0.6, severity: .medium, title: "Resolvable Alert")
        await logger.log(alert: alert, explanation: nil)

        await logger.markResolved(entryID: alert.id, note: "False positive — safe app")

        let results = await logger.query(severity: nil, dateRange: nil, resolved: true)
        XCTAssertEqual(results.count, 1)
        XCTAssertEqual(results.first?.resolvedNote, "False positive — safe app")
    }

    // MARK: - Query Filters

    func test_query_filterBySeverity_returnsOnlyMatching() async {
        await logger.log(alert: makeAlert(score: 0.9, severity: .critical, title: "Crit"), explanation: nil)
        await logger.log(alert: makeAlert(score: 0.6, severity: .high, title: "High"), explanation: nil)
        await logger.log(alert: makeAlert(score: 0.4, severity: .medium, title: "Med"), explanation: nil)

        let criticals = await logger.query(severity: .critical, dateRange: nil, resolved: nil)
        XCTAssertEqual(criticals.count, 1)
        XCTAssertEqual(criticals.first?.alertTitle, "Crit")
    }

    func test_query_filterByResolved_returnsOnlyUnresolved() async {
        let a1 = makeAlert(score: 0.7, severity: .high, title: "Alert 1")
        let a2 = makeAlert(score: 0.8, severity: .high, title: "Alert 2")
        await logger.log(alert: a1, explanation: nil)
        await logger.log(alert: a2, explanation: nil)
        await logger.markResolved(entryID: a1.id, note: nil)

        let unresolved = await logger.query(severity: nil, dateRange: nil, resolved: false)
        XCTAssertEqual(unresolved.count, 1)
        XCTAssertEqual(unresolved.first?.alertTitle, "Alert 2")
    }

    func test_query_filterByDateRange_excludesOldEntries() async {
        // Log one old alert (manually set timestamp by creating entry directly)
        let ctx = ModelContext(container)
        let old = ThreatLogEntry(
            id: UUID(),
            timestamp: Date(timeIntervalSinceNow: -200 * 86_400),
            content: ThreatLogContent(
                alertTitle: "Old Alert",
                alertDescription: "old",
                score: 0.5,
                severity: "medium"
            )
        )
        ctx.insert(old)
        try? ctx.save()

        await logger.log(alert: makeAlert(score: 0.5, severity: .medium, title: "New Alert"), explanation: nil)

        let range = Date(timeIntervalSinceNow: -1)...Date()
        let recent = await logger.query(severity: nil, dateRange: range, resolved: nil)
        XCTAssertEqual(recent.count, 1)
        XCTAssertEqual(recent.first?.alertTitle, "New Alert")
    }

    // MARK: - Export

    func test_exportJSON_producesValidJSON() async throws {
        await logger.log(alert: makeAlert(score: 0.8, severity: .high, title: "Export Test"), explanation: "Some explanation")
        let entries = await logger.query(severity: nil, dateRange: nil, resolved: nil)

        let data = try logger.exportJSON(entries: entries)
        XCTAssertFalse(data.isEmpty)

        // Must be valid JSON array
        let json = try JSONSerialization.jsonObject(with: data)
        XCTAssertTrue(json is [Any])
    }

    func test_exportCSV_containsHeaderAndRow() async throws {
        await logger.log(alert: makeAlert(score: 0.75, severity: .high, title: "CSV Alert"), explanation: nil)
        let entries = await logger.query(severity: nil, dateRange: nil, resolved: nil)

        let data = try logger.exportCSV(entries: entries)
        let csv = String(data: data, encoding: .utf8) ?? ""

        XCTAssertTrue(csv.contains("alertTitle") || csv.contains("id"))
        XCTAssertTrue(csv.contains("CSV Alert"))
    }

    func test_exportCSV_emptyEntries_producesHeaderOnly() throws {
        let data = try logger.exportCSV(entries: [])
        let csv = String(data: data, encoding: .utf8) ?? ""
        XCTAssertFalse(csv.isEmpty)
        XCTAssertEqual(csv.components(separatedBy: "\n").filter { !$0.isEmpty }.count, 1)
    }

    // MARK: - Pruning

    func test_pruneOlderThan_deletesStaleEntries() async {
        let ctx = ModelContext(container)
        let old = ThreatLogEntry(
            id: UUID(),
            timestamp: Date(timeIntervalSinceNow: -100 * 86_400), // 100 days ago
            content: ThreatLogContent(
                alertTitle: "Stale Alert",
                alertDescription: "stale",
                score: 0.5,
                severity: "medium"
            )
        )
        ctx.insert(old)
        try? ctx.save()

        await logger.log(alert: makeAlert(score: 0.5, severity: .medium, title: "Recent"), explanation: nil)
        await logger.pruneOlderThan(days: 30)

        let results = await logger.query(severity: nil, dateRange: nil, resolved: nil)
        XCTAssertEqual(results.count, 1)
        XCTAssertEqual(results.first?.alertTitle, "Recent")
    }

    func test_pruneOlderThan_keepsRecentEntries() async {
        await logger.log(alert: makeAlert(score: 0.6, severity: .medium, title: "Keep Me"), explanation: nil)
        await logger.pruneOlderThan(days: 90)
        let results = await logger.query(severity: nil, dateRange: nil, resolved: nil)
        XCTAssertEqual(results.count, 1)
    }

    // MARK: - Helpers

    private func makeAlert(score: Double, severity: SignalSeverity, title: String) -> ThreatAlert {
        ThreatAlert(
            score: score,
            content: AlertContent(
                title: title,
                description: "Test description",
                severity: severity,
                recommendedAction: "Investigate."
            ),
            contributingSignals: []
        )
    }

    private func makeAlertWithSignals(score: Double, severity: SignalSeverity) -> ThreatAlert {
        let proc = NickProcessInfo(
            pid: 1234,
            path: "/usr/bin/curl",
            name: "curl",
            parentPID: 1,
            parentName: nil,
            signingStatus: .unsigned,
            metadata: ProcessMetadata(user: "root", startTime: Date())
        )
        let net = NetworkConnectionInfo(
            id: UUID(),
            pid: 1234,
            processName: "curl",
            transportProtocol: .tcp,
            localAddress: "127.0.0.1",
            localPort: 54321,
            remoteAddress: "203.0.113.1",
            remotePort: 4444,
            state: .established
        )
        let signal = ThreatSignal(
            id: UUID(),
            source: .network,
            severity: severity,
            timestamp: Date(),
            title: "Test Signal",
            description: "Test",
            context: ThreatSignalContext(processInfo: proc, networkInfo: net)
        )
        return ThreatAlert(
            score: score,
            content: AlertContent(
                title: "Alert with Signals",
                description: "Test",
                severity: severity,
                recommendedAction: "Investigate."
            ),
            contributingSignals: [signal]
        )
    }
}
