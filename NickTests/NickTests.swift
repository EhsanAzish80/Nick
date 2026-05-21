import XCTest

final class NickTests: XCTestCase {

    func testThreatSignalCreation() {
        let signal = ThreatSignal(
            source: .processAudit,
            severity: .high,
            title: "Test signal",
            detail: "Unit test"
        )
        XCTAssertEqual(signal.source, .processAudit)
        XCTAssertEqual(signal.severity, .high)
    }

    func testThreatCorrelatorScore() async {
        let correlator = await ThreatCorrelator()
        await correlator.ingest(ThreatSignal(source: .processAudit, severity: .critical, title: "t", detail: "d"))
        let score = await correlator.overallScore
        XCTAssertGreaterThan(score, 0)
    }
}
