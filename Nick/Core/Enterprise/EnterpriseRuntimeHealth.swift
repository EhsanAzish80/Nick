import Foundation

protocol EnterpriseManagedPreferencesReading {
    func objectIsForced(forKey defaultName: String) -> Bool
    func dictionary(forKey defaultName: String) -> [String: Any]?
}

extension UserDefaults: EnterpriseManagedPreferencesReading {}

enum EnterpriseManagedConfigurationState: Equatable, Sendable {
    case unmanaged
    case managed(EnterpriseManagedConfiguration)
    case invalid(NickCLIError)

    var configuration: EnterpriseManagedConfiguration? {
        guard case .managed(let configuration) = self else { return nil }
        return configuration
    }

    var isManaged: Bool {
        if case .unmanaged = self { return false }
        return true
    }
}

/// Reads one dictionary delivered through the app's forced preference domain.
/// A normal UserDefaults value with the same key is deliberately ignored.
struct EnterpriseManagedConfigurationStore {
    static let preferenceKey = "enterpriseManagedConfiguration"

    private let preferences: any EnterpriseManagedPreferencesReading

    init(preferences: any EnterpriseManagedPreferencesReading = UserDefaults.standard) {
        self.preferences = preferences
    }

    func load() -> EnterpriseManagedConfigurationState {
        guard preferences.objectIsForced(forKey: Self.preferenceKey) else {
            return .unmanaged
        }
        guard let values = preferences.dictionary(forKey: Self.preferenceKey) else {
            return .invalid(Self.invalidConfigurationError)
        }
        do {
            return .managed(try EnterpriseManagedConfiguration.decodeManagedValues(values))
        } catch {
            return .invalid(Self.invalidConfigurationError)
        }
    }

    private static let invalidConfigurationError = NickCLIError(
        code: .invalidManagedConfiguration,
        message: "The forced enterprise configuration is invalid.",
        recoverySuggestion: "Review the enterpriseManagedConfiguration payload and its schema version."
    )
}

struct EnterpriseRuntimeHealthInput: Equatable, Sendable {
    enum NetworkState: Equatable, Sendable {
        case loading
        case disabled
        case enabled(lastProviderEvidenceAt: Date)
        case awaitingApproval
        case failed(String)
    }

    let generatedAt: Date
    let nickVersion: String
    let nickBuild: String
    let macOSVersion: String
    let architecture: String
    let managedConfiguration: EnterpriseManagedConfigurationState
    let endpointResponding: Bool
    let endpointLastStatusResponseAt: Date?
    let endpointLastEventAt: Date?
    let networkState: NetworkState
}

enum EnterpriseHealthReportBuilder {
    static func build(_ input: EnterpriseRuntimeHealthInput) throws -> EnterpriseHealthReport {
        let endpoint = endpointComponent(input)
        let network = networkComponent(input.networkState)
        var limitations: [String] = []

        if endpoint.state == .cannotVerify {
            limitations.append("Endpoint Security runtime state could not be verified.")
        }
        if network.state == .cannotVerify || network.state == .degraded {
            limitations.append("Network Filter runtime state could not be fully verified.")
        }
        if case .invalid = input.managedConfiguration {
            limitations.append("A forced enterprise configuration was detected but could not be validated.")
        }

        let report = EnterpriseHealthReport(
            schemaVersion: EnterpriseHealthReport.currentSchemaVersion,
            generatedAt: input.generatedAt,
            nickVersion: input.nickVersion,
            nickBuild: input.nickBuild,
            macOSVersion: input.macOSVersion,
            architecture: input.architecture,
            managedConfigurationDetected: input.managedConfiguration.isManaged,
            organizationName: input.managedConfiguration.configuration?.organizationName,
            components: [endpoint, network],
            limitations: limitations
        )
        try report.validate()
        return report
    }

    @MainActor
    static func buildLive(
        xpcClient: ExtensionXPCClient,
        networkProtection: NetworkProtectionManager,
        managedConfigurationStore: EnterpriseManagedConfigurationStore = .init(),
        bundle: Bundle = .main,
        processInfo: ProcessInfo = .processInfo,
        now: Date = .now
    ) throws -> EnterpriseHealthReport {
        let networkState: EnterpriseRuntimeHealthInput.NetworkState
        switch networkProtection.state {
        case .loading:
            networkState = .loading
        case .disabled:
            networkState = .disabled
        case .enabled:
            if let evidenceDate = NetworkProtectionSharedStore.currentHealthDate(
                now: now.timeIntervalSince1970,
                expectedProviderVersion: NetworkProtectionSharedStore.bundledProviderVersion()
            ) {
                networkState = .enabled(lastProviderEvidenceAt: evidenceDate)
            } else {
                networkState = .failed("The Network Filter preference is enabled, but current provider evidence is unavailable.")
            }
        case .awaitingApproval:
            networkState = .awaitingApproval
        case .failed(let message):
            networkState = .failed(message)
        }

        let input = EnterpriseRuntimeHealthInput(
            generatedAt: now,
            nickVersion: bundle.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "unknown",
            nickBuild: bundle.object(forInfoDictionaryKey: kCFBundleVersionKey as String) as? String ?? "unknown",
            macOSVersion: processInfo.operatingSystemVersionString,
            architecture: currentArchitecture,
            managedConfiguration: managedConfigurationStore.load(),
            endpointResponding: xpcClient.isConnected,
            endpointLastStatusResponseAt: xpcClient.lastStatusResponseAt,
            endpointLastEventAt: xpcClient.lastEventReceivedAt ?? xpcClient.events.first?.timestamp,
            networkState: networkState
        )
        return try build(input)
    }

    private static func endpointComponent(
        _ input: EnterpriseRuntimeHealthInput
    ) -> EnterpriseComponentHealth {
        if input.endpointResponding {
            return EnterpriseComponentHealth(
                identifier: "endpoint-security",
                displayName: "Endpoint Security",
                state: .available,
                installed: true,
                enabled: true,
                responsive: true,
                version: nil,
                lastSuccessfulEventAt: input.endpointLastEventAt ?? input.endpointLastStatusResponseAt,
                errorCode: nil,
                message: "The Endpoint Security provider answered a live status request."
            )
        }
        return EnterpriseComponentHealth(
            identifier: "endpoint-security",
            displayName: "Endpoint Security",
            state: .cannotVerify,
            installed: nil,
            enabled: nil,
            responsive: input.endpointLastStatusResponseAt == nil ? nil : false,
            version: nil,
            lastSuccessfulEventAt: input.endpointLastEventAt,
            errorCode: NickEnterpriseErrorCode.visibilityLimited.rawValue,
            message: "Nick does not have a current successful response from the Endpoint Security provider."
        )
    }

    private static func networkComponent(
        _ state: EnterpriseRuntimeHealthInput.NetworkState
    ) -> EnterpriseComponentHealth {
        switch state {
        case .enabled(let evidenceDate):
            return EnterpriseComponentHealth(
                identifier: "network-filter", displayName: "Network Filter",
                state: .available, installed: true, enabled: true, responsive: true,
                version: nil, lastSuccessfulEventAt: evidenceDate,
                errorCode: nil,
                message: "The enabled Network Filter provider published current health evidence."
            )
        case .disabled:
            return EnterpriseComponentHealth(
                identifier: "network-filter", displayName: "Network Filter",
                state: .notConfigured, installed: nil, enabled: false, responsive: false,
                version: nil, lastSuccessfulEventAt: nil,
                errorCode: nil,
                message: "The Network Filter preference is disabled."
            )
        case .awaitingApproval:
            return EnterpriseComponentHealth(
                identifier: "network-filter", displayName: "Network Filter",
                state: .notConfigured, installed: nil, enabled: false, responsive: false,
                version: nil, lastSuccessfulEventAt: nil,
                errorCode: nil,
                message: "The Network Filter is awaiting administrator approval."
            )
        case .failed(let message):
            return EnterpriseComponentHealth(
                identifier: "network-filter", displayName: "Network Filter",
                state: .degraded, installed: nil, enabled: nil, responsive: false,
                version: nil, lastSuccessfulEventAt: nil,
                errorCode: NickEnterpriseErrorCode.networkFilterUnresponsive.rawValue,
                message: message
            )
        case .loading:
            return EnterpriseComponentHealth(
                identifier: "network-filter", displayName: "Network Filter",
                state: .cannotVerify, installed: nil, enabled: nil, responsive: nil,
                version: nil, lastSuccessfulEventAt: nil,
                errorCode: NickEnterpriseErrorCode.visibilityLimited.rawValue,
                message: "Network Filter preferences have not finished loading."
            )
        }
    }

    private static var currentArchitecture: String {
        #if arch(arm64)
        "arm64"
        #elseif arch(x86_64)
        "x86_64"
        #else
        "unknown"
        #endif
    }
}

struct EnterpriseDeploymentReadiness: Equatable, Sendable {
    enum Level: String, Equatable, Sendable {
        case ready
        case needsAttention
        case cannotVerify
    }

    let level: Level
    let title: String
    let detail: String
    let supportSummary: String

    init(
        report: EnterpriseHealthReport,
        managedConfiguration: EnterpriseManagedConfigurationState
    ) {
        if case .invalid = managedConfiguration {
            level = .needsAttention
            title = "Managed configuration needs attention"
            detail = "Nick found a forced policy, but it does not pass the enterprise configuration contract."
        } else if report.components.contains(where: {
            $0.state == .unavailable || $0.state == .notConfigured || $0.state == .degraded
        }) {
            level = .needsAttention
            title = "Deployment needs attention"
            detail = "At least one required protection provider is unavailable, disabled, or degraded."
        } else if report.components.contains(where: { $0.state == .cannotVerify }) {
            level = .cannotVerify
            title = "Deployment cannot be fully verified"
            detail = "Nick is missing current provider evidence. This is a visibility limitation, not proof of removal."
        } else {
            level = .ready
            title = "Deployment is ready"
            detail = "Required providers supplied current runtime evidence and the managed configuration is valid."
        }

        supportSummary = Self.makeSupportSummary(
            report: report,
            managedConfiguration: managedConfiguration,
            level: level
        )
    }

    private static func makeSupportSummary(
        report: EnterpriseHealthReport,
        managedConfiguration: EnterpriseManagedConfigurationState,
        level: Level
    ) -> String {
        let policyState: String
        switch managedConfiguration {
        case .unmanaged: policyState = "Not detected"
        case .managed: policyState = "Forced policy detected and valid"
        case .invalid: policyState = "Forced policy detected but invalid"
        }
        let formatter = ISO8601DateFormatter()
        var lines = [
            "Nick deployment readiness: \(level.rawValue)",
            "Organization: \(report.organizationName ?? "Not configured")",
            "Generated: \(formatter.string(from: report.generatedAt))",
            "Nick: \(report.nickVersion) (\(report.nickBuild))",
            "macOS: \(report.macOSVersion) [\(report.architecture)]",
            "Managed policy: \(policyState)"
        ]
        for component in report.components {
            let evidence = component.lastSuccessfulEventAt.map(formatter.string(from:)) ?? "none"
            lines.append("\(component.displayName): \(component.state.rawValue); evidence=\(evidence)")
        }
        if report.limitations.isEmpty {
            lines.append("Limitations: none reported")
        } else {
            lines.append("Limitations: \(report.limitations.joined(separator: " | "))")
        }
        lines.append("Assessment: runtime evidence only; not a compliance certification")
        return lines.joined(separator: "\n")
    }
}

enum EnterpriseStatusCommand {
    static func result(
        report: EnterpriseHealthReport,
        managedConfiguration: EnterpriseManagedConfigurationState
    ) -> NickCLIEnvelope<EnterpriseHealthReport> {
        if case .invalid(let error) = managedConfiguration {
            return failure(report: report, exitCode: .configurationInvalid, error: error)
        }

        if let component = report.components.first(where: { $0.state == .unavailable || $0.state == .notConfigured }) {
            return failure(
                report: report,
                exitCode: .componentUnavailable,
                error: NickCLIError(
                    code: component.identifier == "network-filter" ? .networkFilterUnresponsive : .endpointUnresponsive,
                    message: "\(component.displayName) is not available.",
                    recoverySuggestion: component.message
                )
            )
        }
        if let component = report.components.first(where: { $0.state == .degraded }) {
            return failure(
                report: report,
                exitCode: .componentDegraded,
                error: NickCLIError(
                    code: component.identifier == "network-filter" ? .networkFilterUnresponsive : .endpointUnresponsive,
                    message: "\(component.displayName) is degraded.",
                    recoverySuggestion: component.message
                )
            )
        }
        if let component = report.components.first(where: { $0.state == .cannotVerify }) {
            return failure(
                report: report,
                exitCode: .visibilityLimited,
                error: NickCLIError(
                    code: .visibilityLimited,
                    message: "Nick cannot verify \(component.displayName).",
                    recoverySuggestion: component.message
                )
            )
        }
        return NickCLIEnvelope(
            schemaVersion: NickCLIEnvelope<EnterpriseHealthReport>.currentSchemaVersion,
            command: .status,
            generatedAt: report.generatedAt,
            success: true,
            exitCode: .success,
            payload: report,
            errors: []
        )
    }

    static func invalidArguments(now: Date = .now) -> NickCLIEnvelope<EnterpriseHealthReport> {
        NickCLIEnvelope(
            schemaVersion: NickCLIEnvelope<EnterpriseHealthReport>.currentSchemaVersion,
            command: .status,
            generatedAt: now,
            success: false,
            exitCode: .invalidArguments,
            payload: nil,
            errors: [NickCLIError(
                code: .invalidArguments,
                message: "Invalid command-line arguments.",
                recoverySuggestion: "Use: nickctl status --json"
            )]
        )
    }

    private static func failure(
        report: EnterpriseHealthReport,
        exitCode: NickCLIExitCode,
        error: NickCLIError
    ) -> NickCLIEnvelope<EnterpriseHealthReport> {
        NickCLIEnvelope(
            schemaVersion: NickCLIEnvelope<EnterpriseHealthReport>.currentSchemaVersion,
            command: .status,
            generatedAt: report.generatedAt,
            success: false,
            exitCode: exitCode,
            payload: report,
            errors: [error]
        )
    }
}
