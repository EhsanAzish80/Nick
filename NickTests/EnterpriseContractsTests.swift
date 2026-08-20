import Foundation
import Testing
@testable import Nick

struct EnterpriseContractsTests {
    private final class ManagedPreferencesStub: EnterpriseManagedPreferencesReading {
        let forced: Bool
        let values: [String: Any]?

        init(forced: Bool, values: [String: Any]?) {
            self.forced = forced
            self.values = values
        }

        func objectIsForced(forKey _: String) -> Bool { forced }
        func dictionary(forKey _: String) -> [String: Any]? { values }
    }

    @Test func managedConfigurationDecodesAndValidatesBoundedValues() throws {
        let configuration = try EnterpriseManagedConfiguration.decodeManagedValues([
            "organizationName": "Example Organization",
            "logLevel": "warning",
            "retentionDays": 30,
            "exportDirectory": "/Library/Application Support/Nick/Exports",
            "exportFormats": ["json", "markdown"],
            "captureDurationSeconds": 60,
            "sanitizeExports": true,
            "showUserInterface": false
        ])

        #expect(configuration.schemaVersion == 1)
        #expect(configuration.organizationName == "Example Organization")
        #expect(configuration.exportFormats == [.json, .markdown])
        #expect(configuration.sanitizeExports)
        #expect(!configuration.showUserInterface)
    }

    @Test func managedConfigurationRejectsUnboundedRetention() {
        #expect(throws: EnterpriseContractError.invalidRetentionDays) {
            try EnterpriseManagedConfiguration.decodeManagedValues([
                "logLevel": "info",
                "retentionDays": 3650,
                "exportFormats": ["json"],
                "captureDurationSeconds": 30,
                "sanitizeExports": true,
                "showUserInterface": true
            ])
        }
    }

    @Test func managedConfigurationRequiresAbsoluteExportDirectory() {
        #expect(throws: EnterpriseContractError.exportDirectoryMustBeAbsolute) {
            try EnterpriseManagedConfiguration.decodeManagedValues([
                "logLevel": "info",
                "retentionDays": 14,
                "exportDirectory": "relative/export",
                "exportFormats": ["json"],
                "captureDurationSeconds": 30,
                "sanitizeExports": true,
                "showUserInterface": true
            ])
        }
    }

    @Test func unforcedPreferencesCannotMasqueradeAsManagedPolicy() {
        let source = ManagedPreferencesStub(
            forced: false,
            values: ["organizationName": "Local impostor"]
        )

        let state = EnterpriseManagedConfigurationStore(preferences: source).load()

        #expect(state == .unmanaged)
    }

    @Test func forcedManagedPreferencesAreDecoded() {
        let source = ManagedPreferencesStub(forced: true, values: [
            "organizationName": "Example Organization",
            "logLevel": "info",
            "retentionDays": 14,
            "exportFormats": ["json"],
            "captureDurationSeconds": 30,
            "sanitizeExports": true,
            "showUserInterface": true
        ])

        let state = EnterpriseManagedConfigurationStore(preferences: source).load()

        #expect(state.configuration?.organizationName == "Example Organization")
        #expect(state.isManaged)
    }

    @Test func malformedForcedPreferencesRemainVisibleAsInvalid() {
        let source = ManagedPreferencesStub(forced: true, values: [
            "retentionDays": 9999
        ])

        let state = EnterpriseManagedConfigurationStore(preferences: source).load()

        guard case .invalid(let error) = state else {
            Issue.record("Expected an invalid managed configuration")
            return
        }
        #expect(error.code == .invalidManagedConfiguration)
    }

    @Test func liveProviderEvidenceProducesAvailableHealth() throws {
        let evidenceDate = Date(timeIntervalSince1970: 500)
        let report = try EnterpriseHealthReportBuilder.build(.init(
            generatedAt: Date(timeIntervalSince1970: 600),
            nickVersion: "4.1",
            nickBuild: "416",
            macOSVersion: "15.0",
            architecture: "arm64",
            managedConfiguration: .unmanaged,
            endpointResponding: true,
            endpointLastStatusResponseAt: evidenceDate,
            endpointLastEventAt: nil,
            networkState: .enabled(lastProviderEvidenceAt: evidenceDate)
        ))

        #expect(report.components.map(\.state) == [.available, .available])
        #expect(report.components.allSatisfy { $0.responsive == true })
        #expect(report.limitations.isEmpty)
    }

    @Test func missingProviderEvidenceNeverClaimsRemovalOrDisablement() throws {
        let report = try EnterpriseHealthReportBuilder.build(.init(
            generatedAt: Date(timeIntervalSince1970: 600),
            nickVersion: "4.1",
            nickBuild: "416",
            macOSVersion: "15.0",
            architecture: "arm64",
            managedConfiguration: .unmanaged,
            endpointResponding: false,
            endpointLastStatusResponseAt: nil,
            endpointLastEventAt: nil,
            networkState: .loading
        ))

        #expect(report.components.map(\.state) == [.cannotVerify, .cannotVerify])
        #expect(report.components.allSatisfy { $0.installed == nil && $0.enabled == nil })
        #expect(report.limitations.count == 2)
    }

    @Test func healthReportRejectsDuplicateComponentIdentifiers() {
        let component = EnterpriseComponentHealth(
            identifier: "endpoint-security",
            displayName: "Endpoint Security",
            state: .cannotVerify,
            installed: true,
            enabled: true,
            responsive: nil,
            version: "1",
            lastSuccessfulEventAt: nil,
            errorCode: nil,
            message: "No recent provider evidence"
        )
        let report = EnterpriseHealthReport(
            schemaVersion: 1,
            generatedAt: .now,
            nickVersion: "4.1",
            nickBuild: "416",
            macOSVersion: "15.0",
            architecture: "arm64",
            managedConfigurationDetected: true,
            organizationName: "Example Organization",
            components: [component, component],
            limitations: []
        )

        #expect(throws: EnterpriseContractError.duplicateComponentIdentifier) {
            try report.validate()
        }
    }

    @Test func cannotVerifyRemainsDistinctFromUnavailable() throws {
        let report = EnterpriseHealthReport(
            schemaVersion: 1,
            generatedAt: .now,
            nickVersion: "4.1",
            nickBuild: "416",
            macOSVersion: "15.0",
            architecture: "arm64",
            managedConfigurationDetected: false,
            organizationName: nil,
            components: [
                EnterpriseComponentHealth(
                    identifier: "network-filter",
                    displayName: "Network Filter",
                    state: .cannotVerify,
                    installed: nil,
                    enabled: nil,
                    responsive: nil,
                    version: nil,
                    lastSuccessfulEventAt: nil,
                    errorCode: "NICK-VISIBILITY-001",
                    message: "Provider state is not visible"
                )
            ],
            limitations: ["Network Extension evidence was unavailable"]
        )

        try report.validate()
        #expect(report.components[0].state == .cannotVerify)
        #expect(report.components[0].state != .unavailable)
    }

    @Test func CLIExitAndErrorCodesRemainUnique() {
        #expect(Set(NickCLIExitCode.allCases.map(\.rawValue)).count == NickCLIExitCode.allCases.count)
        #expect(Set(NickEnterpriseErrorCode.allCases.map(\.rawValue)).count == NickEnterpriseErrorCode.allCases.count)
    }

    @Test func CLIEnvelopeRejectsContradictorySuccessState() {
        let envelope = NickCLIEnvelope<EnterpriseHealthReport>(
            schemaVersion: 1,
            command: .status,
            generatedAt: .now,
            success: true,
            exitCode: .visibilityLimited,
            payload: nil,
            errors: []
        )

        #expect(throws: EnterpriseContractError.inconsistentCLIResult) {
            try envelope.validate()
        }
    }

    @Test func statusCommandSucceedsOnlyWhenAllComponentsAreAvailable() throws {
        let report = enterpriseStatusReport(states: [.available, .available])
        let result = EnterpriseStatusCommand.result(
            report: report,
            managedConfiguration: .managed(.defaults)
        )

        try result.validate()
        #expect(result.success)
        #expect(result.exitCode == .success)
        #expect(result.payload == report)
    }

    @Test func statusCommandPreservesPartialEvidenceWhenVisibilityIsLimited() throws {
        let report = enterpriseStatusReport(states: [.cannotVerify, .available])
        let result = EnterpriseStatusCommand.result(
            report: report,
            managedConfiguration: .managed(.defaults)
        )

        try result.validate()
        #expect(!result.success)
        #expect(result.exitCode == .visibilityLimited)
        #expect(result.payload == report)
        #expect(result.errors.first?.code == .visibilityLimited)
    }

    @Test func deploymentReadinessIsReadyOnlyWithCurrentProviderEvidence() {
        let readiness = EnterpriseDeploymentReadiness(
            report: enterpriseStatusReport(states: [.available, .available]),
            managedConfiguration: .managed(.defaults)
        )

        #expect(readiness.level == .ready)
        #expect(readiness.supportSummary.contains("Endpoint Security: available"))
        #expect(readiness.supportSummary.contains("runtime evidence only"))
    }

    @Test func deploymentReadinessKeepsVisibilityLimitsDistinct() {
        let readiness = EnterpriseDeploymentReadiness(
            report: enterpriseStatusReport(states: [.cannotVerify, .available]),
            managedConfiguration: .managed(.defaults)
        )

        #expect(readiness.level == .cannotVerify)
        #expect(readiness.detail.contains("not proof of removal"))
    }

    @Test func invalidManagedPolicyPreventsReadyState() {
        let error = NickCLIError(
            code: .invalidManagedConfiguration,
            message: "Invalid configuration",
            recoverySuggestion: nil
        )
        let readiness = EnterpriseDeploymentReadiness(
            report: enterpriseStatusReport(states: [.available, .available]),
            managedConfiguration: .invalid(error)
        )

        #expect(readiness.level == .needsAttention)
        #expect(readiness.supportSummary.contains("Forced policy detected but invalid"))
    }

    @Test func invalidManagedConfigurationTakesPriorityInStatusCommand() throws {
        let report = enterpriseStatusReport(states: [.available, .available])
        let configurationError = NickCLIError(
            code: .invalidManagedConfiguration,
            message: "Invalid configuration",
            recoverySuggestion: nil
        )
        let result = EnterpriseStatusCommand.result(
            report: report,
            managedConfiguration: .invalid(configurationError)
        )

        try result.validate()
        #expect(result.exitCode == .configurationInvalid)
        #expect(result.errors == [configurationError])
    }

    @Test func invalidStatusArgumentsUseStableExitAndErrorCodes() throws {
        let result = EnterpriseStatusCommand.invalidArguments(
            now: Date(timeIntervalSince1970: 1)
        )

        try result.validate()
        #expect(result.exitCode == .invalidArguments)
        #expect(result.errors.first?.code == .invalidArguments)
    }

    @Test func diagnosticManifestRejectsTraversalAndUnsanitizedOutput() {
        let unsafe = EnterpriseDiagnosticManifest(
            schemaVersion: 1,
            generatedAt: .now,
            nickVersion: "4.1",
            sanitized: true,
            healthReportPath: "../health.json",
            artifacts: [],
            limitations: []
        )
        #expect(throws: EnterpriseContractError.invalidArtifactPath) {
            try unsafe.validate()
        }

        let unsanitized = EnterpriseDiagnosticManifest(
            schemaVersion: 1,
            generatedAt: .now,
            nickVersion: "4.1",
            sanitized: false,
            healthReportPath: "health.json",
            artifacts: [],
            limitations: []
        )
        #expect(throws: EnterpriseContractError.unsanitizedDiagnosticBundle) {
            try unsanitized.validate()
        }
    }

    private func enterpriseStatusReport(
        states: [EnterpriseComponentState]
    ) -> EnterpriseHealthReport {
        EnterpriseHealthReport(
            schemaVersion: EnterpriseHealthReport.currentSchemaVersion,
            generatedAt: Date(timeIntervalSince1970: 100),
            nickVersion: "4.1",
            nickBuild: "416",
            macOSVersion: "macOS",
            architecture: "arm64",
            managedConfigurationDetected: true,
            organizationName: "Example",
            components: states.enumerated().map { index, state in
                EnterpriseComponentHealth(
                    identifier: index == 0 ? "endpoint-security" : "network-filter",
                    displayName: index == 0 ? "Endpoint Security" : "Network Filter",
                    state: state,
                    installed: state == .available,
                    enabled: state == .available,
                    responsive: state == .available,
                    version: nil,
                    lastSuccessfulEventAt: state == .available ? Date(timeIntervalSince1970: 99) : nil,
                    errorCode: state == .available ? nil : NickEnterpriseErrorCode.visibilityLimited.rawValue,
                    message: "Test evidence"
                )
            },
            limitations: states.contains(.cannotVerify) ? ["Visibility limited"] : []
        )
    }

    @Test func baselineManifestRejectsExpiredAndDuplicateAssertions() {
        let assertion = EnterpriseRuntimeAssertion(
            identifier: "expected.endpoint",
            ruleIdentifier: "baseline.endpoint",
            kind: .extensionActive,
            subject: "com.example.endpoint",
            explanation: "Expected Endpoint Security extension"
        )
        let expired = EnterpriseBaselineManifest(
            schemaVersion: 1,
            baselineIdentifier: "example.baseline",
            baselineVersion: "1.0",
            publisher: "Example Publisher",
            platform: "macOS",
            minimumOSVersion: nil,
            maximumOSVersion: nil,
            issuedAt: Date(timeIntervalSince1970: 1),
            expiresAt: Date(timeIntervalSince1970: 2),
            contentSHA256: String(repeating: "a", count: 64),
            signingKeyIdentifier: "example-key",
            assertions: [assertion]
        )
        #expect(throws: EnterpriseBaselineError.expired) {
            try expired.validate(now: Date(timeIntervalSince1970: 3))
        }

        let duplicate = EnterpriseBaselineManifest(
            schemaVersion: 1,
            baselineIdentifier: "example.baseline",
            baselineVersion: "1.0",
            publisher: "Example Publisher",
            platform: "macOS",
            minimumOSVersion: nil,
            maximumOSVersion: nil,
            issuedAt: Date(timeIntervalSince1970: 1),
            expiresAt: nil,
            contentSHA256: String(repeating: "b", count: 64),
            signingKeyIdentifier: "example-key",
            assertions: [assertion, assertion]
        )
        #expect(throws: EnterpriseBaselineError.duplicateAssertionIdentifier) {
            try duplicate.validate(now: Date(timeIntervalSince1970: 3))
        }
    }
}
