// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import XCTest
@testable import Nick

final class SimpleAlertCopyTests: XCTestCase {

    private func alert(severity: SignalSeverity, rule: String = "macos_reverse_shell") -> ThreatAlert {
        ThreatAlert(
            score: 0.92,
            content: AlertContent(
                title: "Reverse shell detected",
                description: "A shell connected out.",
                severity: severity,
                recommendedAction: "Terminate the process."
            ),
            contributingSignals: [
                ThreatSignal(
                    source: .yara, severity: severity, title: "YARA match",
                    description: "match",
                    context: ThreatSignalContext(metadata: ["rule": rule, "path": "/tmp/x"])
                )
            ]
        )
    }

    private func user(_ severity: UserFacingAlert.AlertSeverity, action: String = "Move it to the Trash.") -> UserFacingAlert {
        UserFacingAlert(
            id: UUID(), headline: "An app tried to open a hidden connection",
            explanation: "A program opened a remote control channel.",
            assessment: "", recommendedAction: action, severity: severity,
            actions: [], technicalDetail: alert(severity: .high), timestamp: Date()
        )
    }

    func test_quarantinedAlertReadsAsBlocked() {
        let copy = SimpleAlertCopy.make(alert: alert(severity: .critical), user: user(.critical),
                                        isQuarantined: true, fileStillPresent: false)
        XCTAssertEqual(copy.status, .blocked)
        XCTAssertEqual(copy.title, "Nick stopped a harmful app")
        XCTAssertTrue(copy.whatNickDid.contains("Quarantine"))
    }

    func test_unquarantinedCriticalIsAThreatNotBlocked() {
        let copy = SimpleAlertCopy.make(alert: alert(severity: .critical), user: user(.critical),
                                        isQuarantined: false, fileStillPresent: true)
        XCTAssertEqual(copy.status, .threat)
        XCTAssertFalse(copy.whatNickDid.localizedCaseInsensitiveContains("blocked"))
        XCTAssertEqual(copy.whatToDo, "Move it to the Trash.")
    }

    func test_technicalDataOnlyInTheSummaryLine() {
        let copy = SimpleAlertCopy.make(alert: alert(severity: .high), user: user(.warning),
                                        isQuarantined: false, fileStillPresent: true)
        XCTAssertEqual(copy.technicalSummary, "macos_reverse_shell · 92% · signer unknown")
        for text in [copy.title, copy.subline, copy.whatHappened, copy.whatNickDid, copy.whatToDo] {
            XCTAssertFalse(text.contains("macos_"), text)
            XCTAssertFalse(text.contains("%"), text)
            XCTAssertFalse(text.contains("/tmp"), text)
        }
    }
}
