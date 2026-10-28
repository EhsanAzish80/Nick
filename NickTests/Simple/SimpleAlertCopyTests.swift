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

    func test_quarantinedAlertReadsAsQuarantined() {
        let copy = SimpleAlertCopy.make(alert: alert(severity: .critical), user: user(.critical),
                                        isQuarantined: true, fileStillPresent: false)
        XCTAssertEqual(copy.status, .quarantined)
        XCTAssertEqual(copy.title, "Nick stopped a harmful app")
        XCTAssertTrue(copy.whatNickDid.contains("Quarantine"))
    }

    func test_unquarantinedCriticalNeedsReviewAndIsNotBlocked() {
        let copy = SimpleAlertCopy.make(alert: alert(severity: .critical), user: user(.critical),
                                        isQuarantined: false, fileStillPresent: true)
        XCTAssertEqual(copy.status, .needsReview)
        XCTAssertEqual(copy.badgeText, "High risk")
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

    func test_nonFileFindingNeverClaimsRemovedFile() {
        let signal = ThreatSignal(
            source: .endpointSecurity,
            severity: .critical,
            title: "Decoded payload sent to an interpreter",
            description: "A decoder fed a shell.",
            context: .init(metadata: [
                "reason": "decoded_payload_interpreter",
                "rule": "decoded_payload_interpreter",
                "ruleTier": "protected"
            ])
        )
        let threat = ThreatAlert(
            score: 0.9,
            content: .init(
                title: signal.title,
                description: signal.description,
                severity: .critical,
                recommendedAction: "Review"
            ),
            contributingSignals: [signal]
        )
        let copy = SimpleAlertCopy.make(
            alert: threat,
            user: UserFacingAlertBuilder.shared.build(from: threat),
            isQuarantined: false,
            fileStillPresent: false
        )
        XCTAssertFalse(copy.subline.contains("no longer on your Mac"))
        XCTAssertFalse(copy.whatNickDid.contains("file has since been removed"))
        XCTAssertTrue(copy.subline.contains("command has finished"))
    }

    func testCredentialCatalogNeverClaimsRemovedFile() {
        for reason in [
            "credential_store_access", "keychain_secret_read", "keychain_dump",
            "keychain_command_correlation", "hidden_password_prompt"
        ] {
            let signal = ThreatSignal(
                source: .endpointSecurity, severity: .medium,
                title: "Credential evidence", description: "Credential evidence",
                context: .init(
                    processInfo: .init(
                        pid: 10, path: "/usr/bin/security", name: "security",
                        parentPID: 9, parentName: "gh", signingStatus: .signed(teamID: "APPLE_PLATFORM")
                    ),
                    fileInfo: .init(
                        path: "/Users/test/Library/Keychains/login.keychain-db",
                        sha256Hash: nil, entropy: nil, signingStatus: nil, sizeBytes: nil
                    ),
                    metadata: [
                        "reason": reason, "rule": reason, "ruleTier": "review",
                        "detectionKind": "credential-access", "credentialStore": "keychain"
                    ]
                )
            )
            let alert = ThreatAlert(
                score: 0.6,
                content: .init(title: signal.title, description: signal.description, severity: .medium, recommendedAction: "Review"),
                contributingSignals: [signal]
            )
            let copy = SimpleAlertCopy.make(
                alert: alert,
                user: UserFacingAlertBuilder.shared.build(from: alert),
                isQuarantined: false,
                fileStillPresent: false
            )
            XCTAssertFalse(copy.whatNickDid.contains("file has since been removed"), reason)
        }
    }
}
