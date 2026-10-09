// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation
import os
import Security

// MARK: - ExtensionXPCClient

/// XPC client in the container app that connects to the `NickExtension`
/// System Extension and receives live `ESEvent` objects.
///
/// `ExtensionXPCClient` is the **container-app side** of the XPC bridge:
/// - It **calls** `NickExtensionXPCProtocol` (methods on the extension).
/// - It **implements** `NickAppXPCProtocol` (receives events pushed by the extension).
///
/// Published properties are updated on the main actor so SwiftUI views can
/// observe them directly.
///
/// **Usage (from AppDelegate or a view model):**
/// ```swift
/// let xpcClient = ExtensionXPCClient()
/// xpcClient.connect()
/// ```
@MainActor
@Observable
public final class ExtensionXPCClient: NSObject {

    // MARK: - Observable State

    /// Whether the XPC connection to the extension is currently active.
    public private(set) var isConnected = false

    /// Live log of `ESEvent` objects received from the extension.
    /// Capped at `maxEventCount` to avoid unbounded memory growth.
    public private(set) var events: [ESEvent] = []

    /// Quarantined files reported by the extension (Phase 3+).
    public private(set) var quarantineRecords: [QuarantineRecord] = []

    /// File Integrity Monitor violations reported by the extension (Phase 3+).
    public private(set) var integrityViolations: [IntegrityViolation] = []

    /// TCC privacy permission changes reported by the extension (Phase 5+).
    public private(set) var privacyAlerts: [PrivacyAlert] = []

    /// Threats found on external/removable volumes (Phase 5+).
    public private(set) var usbThreats: [USBThreat] = []

    /// Authenticated health snapshot returned by the system extension.
    public private(set) var extensionHealth: [String: Any]?

    // MARK: - Configuration

    /// Maximum number of events kept in `events`. Older events are discarded.
    public var maxEventCount = 2_000

    /// Installed by AppDelegate so privileged findings enter SecurityEngine's
    /// single incident pipeline. Kept as a closure to avoid a Core service
    /// owning UI/application lifetime state.
    var findingHandler: ((ExtensionFinding) async -> Void)?

    // MARK: - Private

    private nonisolated static let logger = Logger(
        subsystem: "com.ehsanazish.nick",
        category: "ExtensionXPCClient"
    )

    private var connection: NSXPCConnection?
    private let decoder = JSONDecoder()
    private var incidentRevision: UInt64?
    private var securitySettingsRevision: UInt64?
    private var pendingSecuritySettingsPayload: Data?
    private var pendingSecuritySettingsAuthorization: Data?
    private var securitySettingsWriteInFlight = false
    private var pendingIncidentPayload: Data?
    private var pendingIncidentAuthorization: Data?
    private var incidentWriteInFlight = false
    private var activeProtectionAuthorizations: [Data: AuthorizationRef] = [:]
    private var incidentBootstrapCompleted = false
    private var bootstrapLegacyPayload: Data?
    private var bootstrapCompletion: (@MainActor @Sendable (PrivilegedIncidentStoreRecord?, Bool) -> Void)?
    private var bootstrapReconnectTask: Task<Void, Never>?
    private var bootstrapReconnectAttempt = 0
    private var healthRefreshTask: Task<Void, Never>?

    // MARK: - Public API

    /// Opens the XPC connection to the System Extension.
    ///
    /// Safe to call multiple times — an existing connection is reused.
    public func connect(
        legacyIncidentPayload: Data? = nil,
        incidentStoreReady: (@MainActor @Sendable (PrivilegedIncidentStoreRecord?, Bool) -> Void)? = nil
    ) {
        if connection != nil {
            // A view may have opened the shared connection before AppDelegate
            // supplies the migration payload and completion handler. Attach the
            // privileged-store bootstrap to that live connection instead of
            // silently discarding the security-critical request.
            guard legacyIncidentPayload != nil || incidentStoreReady != nil else { return }
            incidentBootstrapCompleted = false
            bootstrapLegacyPayload = legacyIncidentPayload
            bootstrapCompletion = incidentStoreReady
            bootstrapReconnectAttempt = 0
            if isConnected {
                bootstrapIncidentStore(
                    legacyPayload: legacyIncidentPayload,
                    completion: incidentStoreReady
                )
            }
            return
        }
        incidentBootstrapCompleted = false
        bootstrapLegacyPayload = legacyIncidentPayload
        bootstrapCompletion = incidentStoreReady
        bootstrapReconnectAttempt = 0
        openConnection()
    }

    private func openConnection() {
        guard connection == nil, !incidentBootstrapCompleted else { return }

        let conn = NSXPCConnection(machServiceName: NickExtensionConstants.machServiceName)

        // The extension exposes NickExtensionXPCProtocol (we call into it).
        conn.remoteObjectInterface = NSXPCInterface(with: NickExtensionXPCProtocol.self)

        // The container app exposes NickAppXPCProtocol (extension calls us).
        conn.exportedInterface = NSXPCInterface(with: NickAppXPCProtocol.self)
        conn.exportedObject    = self

        conn.invalidationHandler = { [weak self] in
            Task { @MainActor [weak self] in
                guard let self else { return }
                Self.logger.warning("XPC connection to extension invalidated")
                self.isConnected = false
                self.connection = nil
                if !self.incidentBootstrapCompleted {
                    self.scheduleBootstrapReconnect()
                }
            }
        }
        conn.interruptionHandler = { [weak self] in
            Task { @MainActor [weak self] in
                guard let self else { return }
                Self.logger.warning("XPC connection to extension interrupted — extension may have crashed")
                self.isConnected = false
                if !self.incidentBootstrapCompleted {
                    self.scheduleBootstrapReconnect()
                }
            }
        }

        conn.resume()
        connection = conn
        isConnected = false
        Self.logger.info("XPC connection to NickExtension opened; verifying ES client status")

        // Opening an NSXPCConnection does not prove the service exists or that
        // its Endpoint Security client started successfully. Only promote the
        // connection after the extension answers its status request.
        let errorHandler: @Sendable (Error) -> Void = { [weak self] error in
            Self.logger.warning("Extension status verification failed: \(error.localizedDescription)")
            Task { @MainActor [weak self] in
                guard let self, !self.incidentBootstrapCompleted else { return }
                self.scheduleBootstrapReconnect()
            }
        }
        guard let proxy = conn.remoteObjectProxyWithErrorHandler(errorHandler)
            as? NickExtensionXPCProtocol else {
            scheduleBootstrapReconnect()
            return
        }
        let statusReply: @Sendable (Bool) -> Void = { [weak self] active in
            Task { @MainActor [weak self] in
                self?.isConnected = active
                Self.logger.info("Verified extension status: isActive=\(active)")
                if active {
                    self?.startHealthRefresh()
                    self?.loadPersistedEvents()
                    self?.loadPendingFIMViolations()
                    self?.bootstrapIncidentStore(
                        legacyPayload: self?.bootstrapLegacyPayload,
                        completion: self?.bootstrapCompletion
                    )
                } else {
                    self?.scheduleBootstrapReconnect()
                }
            }
        }
        proxy.getStatus(reply: statusReply)
    }

    private func startHealthRefresh() {
        healthRefreshTask?.cancel()
        healthRefreshTask = Task { [weak self] in
            while !Task.isCancelled {
                await self?.refreshExtensionHealth()
                try? await Task.sleep(for: .seconds(5))
            }
        }
    }

    public func refreshExtensionHealth() async {
        guard let proxy = connection?.remoteObjectProxy as? NickExtensionXPCProtocol else {
            extensionHealth = nil
            return
        }
        let data: Data = await withCheckedContinuation { continuation in
            proxy.getExtensionHealth { continuation.resume(returning: $0) }
        }
        extensionHealth = data.isEmpty
            ? nil
            : (try? JSONSerialization.jsonObject(with: data) as? [String: Any])
    }

    private func loadPendingFIMViolations() {
        guard let proxy = connection?.remoteObjectProxy as? NickExtensionXPCProtocol else { return }
        proxy.getPendingFIMViolations { [weak self] data in
            guard !data.isEmpty,
                  let violations = try? JSONDecoder().decode([IntegrityViolation].self, from: data)
            else { return }
            Task { @MainActor [weak self] in
                self?.integrityViolations = violations.sorted { $0.timestamp > $1.timestamp }
            }
        }
    }

    public func bootstrapSecuritySettings(legacyPayload: Data) async -> Data? {
        guard let proxy = connection?.remoteObjectProxy as? NickExtensionXPCProtocol else { return nil }
        let response: (Bool, Data) = await withCheckedContinuation { continuation in
            proxy.migrateSecuritySettings(legacyPayload) {
                continuation.resume(returning: ($0, $1))
            }
        }
        guard response.0,
              let record = try? JSONDecoder().decode(PrivilegedIncidentStoreRecord.self, from: response.1)
        else { return nil }
        securitySettingsRevision = record.revision
        return record.payload
    }

    public func persistSecuritySettings(_ payload: Data, authorizationExternalForm: Data? = nil) {
        pendingSecuritySettingsPayload = payload
        if let authorizationExternalForm {
            finishProtectionAuthorization(pendingSecuritySettingsAuthorization)
            pendingSecuritySettingsAuthorization = authorizationExternalForm
        }
        flushSecuritySettingsIfNeeded()
    }

    private func flushSecuritySettingsIfNeeded() {
        guard !securitySettingsWriteInFlight,
              let payload = pendingSecuritySettingsPayload,
              let revision = securitySettingsRevision,
              let proxy = connection?.remoteObjectProxy as? NickExtensionXPCProtocol else { return }
        pendingSecuritySettingsPayload = nil
        let authorization = pendingSecuritySettingsAuthorization
        pendingSecuritySettingsAuthorization = nil
        securitySettingsWriteInFlight = true
        proxy.replaceSecuritySettings(
            payload,
            expectedRevision: revision,
            authorizationExternalForm: authorization
        ) { [weak self] accepted, data in
            Task { @MainActor [weak self] in
                guard let self else { return }
                self.finishProtectionAuthorization(authorization)
                self.securitySettingsWriteInFlight = false
                guard let record = try? JSONDecoder().decode(PrivilegedIncidentStoreRecord.self, from: data) else {
                    return
                }
                self.securitySettingsRevision = record.revision
                if !accepted {
                    Self.logger.warning("Security settings write was rejected; authoritative state retained")
                }
                self.flushSecuritySettingsIfNeeded()
            }
        }
    }

    private func scheduleBootstrapReconnect() {
        guard !incidentBootstrapCompleted, bootstrapReconnectTask == nil else { return }
        guard bootstrapReconnectAttempt < 12 else {
            Self.logger.error("Incident-store bootstrap failed after repeated XPC reconnects")
            finishIncidentBootstrap(record: nil, migrated: false)
            return
        }

        bootstrapReconnectAttempt += 1
        let delayNanoseconds = UInt64(min(bootstrapReconnectAttempt, 4)) * 500_000_000
        connection?.invalidationHandler = nil
        connection?.interruptionHandler = nil
        connection?.invalidate()
        connection = nil

        bootstrapReconnectTask = Task { @MainActor [weak self] in
            try? await Task.sleep(nanoseconds: delayNanoseconds)
            guard let self, !Task.isCancelled, !self.incidentBootstrapCompleted else { return }
            self.bootstrapReconnectTask = nil
            Self.logger.notice(
                "Retrying incident-store bootstrap after extension replacement (attempt \(self.bootstrapReconnectAttempt))"
            )
            self.openConnection()
        }
    }

    private func finishIncidentBootstrap(
        record: PrivilegedIncidentStoreRecord?,
        migrated: Bool
    ) {
        guard !incidentBootstrapCompleted else { return }
        incidentBootstrapCompleted = true
        bootstrapReconnectTask?.cancel()
        bootstrapReconnectTask = nil
        let completion = bootstrapCompletion
        bootstrapCompletion = nil
        bootstrapLegacyPayload = nil
        completion?(record, migrated)
    }

    private func bootstrapIncidentStore(
        legacyPayload: Data?,
        completion: (@MainActor @Sendable (PrivilegedIncidentStoreRecord?, Bool) -> Void)?
    ) {
        let errorHandler: @Sendable (Error) -> Void = { [weak self] error in
            Self.logger.warning("Incident-store bootstrap failed: \(error.localizedDescription)")
            Task { @MainActor [weak self] in
                self?.scheduleBootstrapReconnect()
            }
        }
        guard let proxy = connection?.remoteObjectProxyWithErrorHandler(errorHandler)
            as? NickExtensionXPCProtocol else {
            scheduleBootstrapReconnect()
            return
        }
        proxy.getIncidentStore { [weak self] data in
            Task { @MainActor [weak self] in
                guard let self else { return }
                if let record = try? JSONDecoder().decode(PrivilegedIncidentStoreRecord.self, from: data) {
                    self.incidentRevision = record.revision
                    self.finishIncidentBootstrap(record: record, migrated: false)
                    return
                }
                guard let legacyPayload else {
                    self.finishIncidentBootstrap(record: nil, migrated: false)
                    return
                }
                proxy.migrateIncidentStore(legacyPayload) { [weak self] accepted, recordData in
                    Task { @MainActor [weak self] in
                        guard let self else { return }
                        let record = try? JSONDecoder().decode(
                            PrivilegedIncidentStoreRecord.self,
                            from: recordData
                        )
                        self.incidentRevision = record?.revision
                        self.finishIncidentBootstrap(
                            record: record,
                            migrated: accepted && record != nil
                        )
                    }
                }
            }
        }
    }

    func persistIncidentStore(_ payload: Data, authorizationExternalForm: Data? = nil) {
        pendingIncidentPayload = payload
        if let authorizationExternalForm {
            finishProtectionAuthorization(pendingIncidentAuthorization)
            pendingIncidentAuthorization = authorizationExternalForm
        }
        drainIncidentStoreWrites()
    }

    private func drainIncidentStoreWrites() {
        guard !incidentWriteInFlight,
              let payload = pendingIncidentPayload,
              let revision = incidentRevision,
              let proxy = connection?.remoteObjectProxy as? NickExtensionXPCProtocol else { return }
        pendingIncidentPayload = nil
        let authorization = pendingIncidentAuthorization
        pendingIncidentAuthorization = nil
        incidentWriteInFlight = true
        proxy.replaceIncidentStore(
            payload,
            expectedRevision: revision,
            authorizationExternalForm: authorization
        ) { [weak self] accepted, recordData in
            Task { @MainActor [weak self] in
                guard let self else { return }
                self.finishProtectionAuthorization(authorization)
                self.incidentWriteInFlight = false
                if let record = try? JSONDecoder().decode(
                    PrivilegedIncidentStoreRecord.self,
                    from: recordData
                ) {
                    self.incidentRevision = record.revision
                }
                if !accepted, authorization == nil {
                    self.pendingIncidentPayload = self.pendingIncidentPayload ?? payload
                } else if !accepted {
                    Self.logger.error("Authorized incident-store write was rejected; authoritative state retained")
                }
                self.drainIncidentStoreWrites()
            }
        }
    }

    func validateIncidentVerdictTarget(
        id: UUID,
        action: IncidentActionKind
    ) async -> IncidentActionApproval? {
        guard let proxy = connection?.remoteObjectProxy as? NickExtensionXPCProtocol else { return nil }
        let requiresAuthorization: Bool = [.dismissed, .allowedOnce, .alwaysAllowed].contains(action)
        let authorization = requiresAuthorization
            ? requestProtectionModificationAuthorization()
            : nil
        if requiresAuthorization && authorization == nil { return nil }
        let accepted = await withCheckedContinuation { continuation in
            proxy.validateIncidentVerdictTarget(
                incidentID: id.uuidString,
                action: action.rawValue,
                authorizationExternalForm: authorization,
                reply: { continuation.resume(returning: $0) }
            )
        }
        guard accepted else {
            finishProtectionAuthorization(authorization)
            return nil
        }
        return IncidentActionApproval(authorizationExternalForm: authorization)
    }

    /// Requests explicit user presence for an action that weakens protection.
    /// The returned external form is never trusted by the app; the extension
    /// reconstructs and verifies the right for the individual XPC call.
    public func requestProtectionModificationAuthorization() -> Data? {
        var authorization: AuthorizationRef?
        guard AuthorizationCreate(nil, nil, [], &authorization) == errAuthorizationSuccess,
              let authorization else { return nil }
        let externalForm: Data? = "com.ehsanazish.nick.modify-protection".withCString { name in
            var item = AuthorizationItem(name: name, valueLength: 0, value: nil, flags: 0)
            return withUnsafeMutablePointer(to: &item) { pointer in
                var rights = AuthorizationRights(count: 1, items: pointer)
                guard AuthorizationCopyRights(
                    authorization,
                    &rights,
                    nil,
                    [.interactionAllowed, .extendRights, .preAuthorize],
                    nil
                ) == errAuthorizationSuccess else { return nil }
                var external = AuthorizationExternalForm()
                guard AuthorizationMakeExternalForm(authorization, &external) == errAuthorizationSuccess else {
                    return nil
                }
                return withUnsafeBytes(of: external) { Data($0) }
            }
        }
        guard let externalForm else {
            AuthorizationFree(authorization, [.destroyRights])
            return nil
        }
        activeProtectionAuthorizations[externalForm] = authorization
        return externalForm
    }

    private func finishProtectionAuthorization(_ externalForm: Data?) {
        guard let externalForm,
              let authorization = activeProtectionAuthorizations.removeValue(forKey: externalForm)
        else { return }
        AuthorizationFree(authorization, [.destroyRights])
    }

    /// Closes the XPC connection.
    public func disconnect() {
        bootstrapReconnectTask?.cancel()
        bootstrapReconnectTask = nil
        connection?.invalidate()
        connection  = nil
        isConnected = false
        incidentBootstrapCompleted = false
        bootstrapLegacyPayload = nil
        bootstrapCompletion = nil
        bootstrapReconnectAttempt = 0
        for authorization in activeProtectionAuthorizations.values {
            AuthorizationFree(authorization, [.destroyRights])
        }
        activeProtectionAuthorizations.removeAll()
    }

    private func loadPersistedEvents() {
        guard let proxy = connection?.remoteObjectProxy as? NickExtensionXPCProtocol else { return }
        proxy.getPersistedEvents { [weak self] data in
            guard let replay = try? JSONDecoder().decode([PersistedExtensionFinding].self, from: data) else {
                return
            }
            Task { @MainActor [weak self] in
                guard let self else { return }
                for finding in replay.sorted(by: { $0.timestamp < $1.timestamp }) {
                    await self.receivePersisted(finding)
                }
            }
        }
    }

    func receivePersisted(_ finding: PersistedExtensionFinding) async {
        switch finding.kind {
        case .endpointEvent, .threat:
            guard let event = try? decoder.decode(ESEvent.self, from: finding.payload) else { return }
            receive(event, deliverToEngine: false)
        case .remediation:
            guard let report = try? decoder.decode(RemediationReport.self, from: finding.payload) else { return }
            receive(report, deliverToEngine: false)
        case .integrityViolation:
            guard let violation = try? decoder.decode(IntegrityViolation.self, from: finding.payload) else { return }
            receive(violation, deliverToEngine: false)
        case .privacyAlert:
            guard let alert = try? decoder.decode(PrivacyAlert.self, from: finding.payload) else { return }
            receive(alert, deliverToEngine: false)
        case .usbThreat:
            guard let threat = try? decoder.decode(USBThreat.self, from: finding.payload) else { return }
            receive(threat, deliverToEngine: false)
        }
    }

    private func receive(_ event: ESEvent, deliverToEngine: Bool = true) {
        if !events.contains(where: { $0.id == event.id }) { events.insert(event, at: 0) }
        trim(&events)
        if deliverToEngine, let finding = ExtensionFinding(event: event) { deliver(finding) }
    }

    private func receive(_ report: RemediationReport, deliverToEngine: Bool = true) {
        if let record = report.quarantineRecord {
            quarantineRecords.removeAll { $0.id == record.id }
            quarantineRecords.insert(record, at: 0)
        }
        if deliverToEngine { deliver(ExtensionFinding(report: report)) }
    }

    private func receive(_ violation: IntegrityViolation, deliverToEngine: Bool = true) {
        if !integrityViolations.contains(where: { $0.id == violation.id }) {
            integrityViolations.insert(violation, at: 0)
        }
        trim(&integrityViolations)
        if deliverToEngine { deliver(ExtensionFinding(violation: violation)) }
    }

    private func receive(_ alert: PrivacyAlert, deliverToEngine: Bool = true) {
        if !privacyAlerts.contains(where: { $0.id == alert.id }) { privacyAlerts.insert(alert, at: 0) }
        trim(&privacyAlerts)
        if deliverToEngine { deliver(ExtensionFinding(privacyAlert: alert)) }
    }

    private func receive(_ threat: USBThreat, deliverToEngine: Bool = true) {
        if !usbThreats.contains(where: { $0.id == threat.id }) { usbThreats.insert(threat, at: 0) }
        trim(&usbThreats)
        if deliverToEngine { deliver(ExtensionFinding(usbThreat: threat)) }
    }

    private func trim<T>(_ values: inout [T]) {
        if values.count > maxEventCount { values.removeLast(values.count - maxEventCount) }
    }

    private func deliver(_ finding: ExtensionFinding) {
        guard let findingHandler else { return }
        Task { await findingHandler(finding) }
    }

    // MARK: - Outbound Calls (Container App → Extension)

    /// Queries the extension's running status.
    /// - Parameter completion: Called on the main queue with `true` if the ES client is active.
    public func getExtensionStatus(completion: @escaping (Bool) -> Void) {
        guard let proxy = connection?.remoteObjectProxy as? NickExtensionXPCProtocol else {
            completion(false)
            return
        }
        proxy.getStatus(reply: completion)
    }

    public func requestQuarantineFile(
        path: String,
        expectedThreatName: String,
        completion: @escaping (Bool, String?) -> Void
    ) {
        guard let proxy = connection?.remoteObjectProxy as? NickExtensionXPCProtocol else {
            completion(false, "Real-Time Protection is not connected.")
            return
        }
        proxy.requestQuarantineFile(path: path, expectedThreatName: expectedThreatName) {
            [weak self] success, message, recordData in
            Task { @MainActor [weak self] in
                if success,
                   let recordData,
                   let record = try? JSONDecoder().decode(QuarantineRecord.self, from: recordData) {
                    self?.quarantineRecords.removeAll { $0.id == record.id }
                    self?.quarantineRecords.insert(record, at: 0)
                }
                completion(success, message)
            }
        }
    }

    public func requestAllowFileOnce(
        path: String,
        completion: @escaping (Bool) -> Void
    ) {
        guard let proxy = connection?.remoteObjectProxy as? NickExtensionXPCProtocol else {
            completion(false)
            return
        }
        guard let authorization = requestProtectionModificationAuthorization() else {
            completion(false)
            return
        }
        proxy.requestAllowFileOnce(
            path: path,
            authorizationExternalForm: authorization
        ) { [weak self] accepted in
            Task { @MainActor [weak self] in
                self?.finishProtectionAuthorization(authorization)
                completion(accepted)
            }
        }
    }

    public func requestBlockReviewedFile(
        path: String,
        completion: @escaping (Bool) -> Void
    ) {
        guard let proxy = connection?.remoteObjectProxy as? NickExtensionXPCProtocol else {
            completion(false)
            return
        }
        proxy.requestBlockReviewedFile(path: path, reply: completion)
    }

    /// Instructs the extension to rebuild the FIM baseline (Phase 5+).
    public func requestRebuildFIMBaseline(completion: @escaping (Bool) -> Void) {
        guard let proxy = connection?.remoteObjectProxy as? NickExtensionXPCProtocol else {
            completion(false)
            return
        }
        proxy.requestRebuildFIMBaseline(reply: completion)
    }

    public func acknowledgeFIMViolation(
        id: UUID,
        completion: @escaping (Bool) -> Void
    ) {
        guard let proxy = connection?.remoteObjectProxy as? NickExtensionXPCProtocol else {
            completion(false)
            return
        }
        guard let authorization = requestProtectionModificationAuthorization() else {
            completion(false)
            return
        }
        proxy.acknowledgeFIMViolation(
            id: id.uuidString,
            authorizationExternalForm: authorization
        ) { [weak self] accepted in
            Task { @MainActor [weak self] in
                self?.finishProtectionAuthorization(authorization)
                if accepted {
                    self?.integrityViolations.removeAll { $0.id == id }
                }
                completion(accepted)
            }
        }
    }

    /// Instructs the extension to deploy ransomware canary files into common user directories.
    public func requestDeployCanaries(completion: @escaping (Bool) -> Void) {
        guard let proxy = connection?.remoteObjectProxy as? NickExtensionXPCProtocol else {
            completion(false)
            return
        }
        proxy.requestDeployCanaries(reply: completion)
    }

    public func requestRestoreQuarantinedFile(
        id: UUID,
        completion: @escaping (Bool) -> Void
    ) {
        guard let proxy = connection?.remoteObjectProxy as? NickExtensionXPCProtocol else {
            completion(false)
            return
        }
        guard let authorization = requestProtectionModificationAuthorization() else {
            completion(false)
            return
        }
        proxy.requestRestoreQuarantinedFile(
            id: id.uuidString,
            authorizationExternalForm: authorization
        ) { [weak self] success in
            Task { @MainActor [weak self] in
                self?.finishProtectionAuthorization(authorization)
                if success {
                    self?.quarantineRecords.removeAll { $0.id == id }
                }
                completion(success)
            }
        }
    }

#if DEBUG
    public func debugSendNeverAuthorizedProtectionCall(
        completion: @escaping (Bool) -> Void
    ) {
        guard let proxy = connection?.remoteObjectProxy as? NickExtensionXPCProtocol else {
            completion(false)
            return
        }
        var authorization: AuthorizationRef?
        guard AuthorizationCreate(nil, nil, [], &authorization) == errAuthorizationSuccess,
              let authorization else {
            completion(false)
            return
        }
        var external = AuthorizationExternalForm()
        guard AuthorizationMakeExternalForm(authorization, &external) == errAuthorizationSuccess else {
            AuthorizationFree(authorization, [.destroyRights])
            completion(false)
            return
        }
        let form = withUnsafeBytes(of: external) { Data($0) }
        proxy.debugValidateProtectionAuthorization(authorizationExternalForm: form) { accepted in
            AuthorizationFree(authorization, [.destroyRights])
            completion(accepted)
        }
    }
#endif

    public func requestDeleteQuarantinedFile(
        id: UUID,
        completion: @escaping (Bool) -> Void
    ) {
        guard let proxy = connection?.remoteObjectProxy as? NickExtensionXPCProtocol else {
            completion(false)
            return
        }
        proxy.requestDeleteQuarantinedFile(id: id.uuidString) { [weak self] success in
            Task { @MainActor [weak self] in
                if success {
                    self?.quarantineRecords.removeAll { $0.id == id }
                }
                completion(success)
            }
        }
    }
}

// MARK: - Unified extension evidence

struct ExtensionFinding: Sendable {
    let signal: ThreatSignal
    let score: Double
    let recommendedAction: String

    init?(event: ESEvent) {
        guard event.decision == .deny || event.threatName != nil else { return nil }
        let filePath = event.filePath ?? event.processPath
        let isTamper = event.threatFamily == "tamper"
        let isNickMaintenance = event.threatFamily == "nick-maintenance"
        let isDocumentedUninstall = event.threatFamily == "nick-documented-uninstall"
        let isManagementObservation = event.threatFamily == "endpoint-management"
        let isRansomwareBehavior = event.metadata?["detectionKind"] == "ransomware-behavior"
        let severity: SignalSeverity
        if event.decision == .deny {
            severity = .critical
        } else if isManagementObservation || isNickMaintenance || isDocumentedUninstall {
            severity = .info
        } else {
            severity = .high
        }
        let signingStatus: SigningStatus
        if let teamID = event.teamID, !teamID.isEmpty {
            signingStatus = .signed(teamID: teamID, signingID: event.signingID)
        } else {
            signingStatus = .unknown
        }
        let process = NickProcessInfo(
            pid: event.pid,
            path: event.processPath,
            name: URL(fileURLWithPath: event.processPath).lastPathComponent,
            parentPID: event.parentPid,
            parentName: nil,
            signingStatus: signingStatus
        )
        let isAuditEvent = isManagementObservation || isNickMaintenance || isDocumentedUninstall
        let ruleClass = isTamper ? "integrity" : (isAuditEvent ? "audit" : (isRansomwareBehavior ? "behavior" : "signature"))
        let ruleTier = isAuditEvent ? "review" : "protected"
        signal = ThreatSignal(
            id: event.id,
            source: .endpointSecurity,
            severity: severity,
            timestamp: event.timestamp,
            title: event.threatName ?? "Endpoint Security blocked a file",
            description: Self.description(
                for: event,
                isTamper: isTamper,
                isManagementObservation: isManagementObservation,
                isNickMaintenance: isNickMaintenance,
                isDocumentedUninstall: isDocumentedUninstall
            ),
            context: ThreatSignalContext(
                processInfo: process,
                fileInfo: FileInfo(
                    path: filePath,
                    sha256Hash: event.sha256,
                    entropy: nil,
                    signingStatus: nil,
                    sizeBytes: nil
                ),
                metadata: [
                    "reason": isTamper
                        ? "endpoint_tamper_observed"
                        : (isDocumentedUninstall ? "nick_documented_uninstall" : (isNickMaintenance ? "nick_protected_path_maintenance" : (isManagementObservation ? "endpoint_management_observed" : "endpoint_threat"))),
                    "rule": isDocumentedUninstall ? "nick_documented_uninstall" : (isNickMaintenance ? "nick_protected_path_maintenance" : (event.threatName ?? "endpoint_known_threat")),
                    "class": ruleClass,
                    "ruleTier": ruleTier,
                    "threatFamily": event.threatFamily ?? "unknown"
                ].merging(event.metadata ?? [:]) { current, _ in current }
            )
        )
        score = event.decision == .deny ? 0.98 : (isAuditEvent ? 0.1 : 0.9)
        recommendedAction = isAuditEvent
            ? "No action is needed if you ran this command."
            : "Review the event and investigate it if you do not recognise the activity."
    }

    private static func description(
        for event: ESEvent,
        isTamper: Bool,
        isManagementObservation: Bool,
        isNickMaintenance: Bool,
        isDocumentedUninstall: Bool
    ) -> String {
        if isManagementObservation {
            return "Nick observed routine use of Apple's system-extension management tool."
        }
        if isTamper {
            if let observed = event.metadata?["observedRule"],
               let expected = event.metadata?["expectedRule"],
               event.metadata?["repairStatus"] == "restored" {
                return "Nick found an unexpected authorization rule, restored it, and recorded the observed rule (\(observed)) and expected rule (\(expected))."
            }
            return event.decision == .deny
                ? "Nick refused an attempt to change a protected Nick path."
                : "Nick observed an attempt to change a protected Nick path."
        }
        if isNickMaintenance {
            return "A validated Nick update, reinstall, or uninstall changed protected Nick files."
        }
        if isDocumentedUninstall {
            return "Finder is moving Nick.app to the Trash. Protection components and generated data remain until you use Nick Uninstaller."
        }
        if event.metadata?["detectionKind"] == "ransomware-behavior" {
            let actor = URL(fileURLWithPath: event.processPath).lastPathComponent
            if let files = event.metadata?["renameFileCount"],
               let folders = event.metadata?["renameDirectoryCount"],
               let ext = event.metadata?["renameExtension"],
               let seconds = event.metadata?["renameWindowSeconds"] {
                return "\(files) files in \(folders) folders were renamed to .\(ext) within \(seconds) seconds by \(actor.isEmpty ? "an unknown process" : actor)."
            }
            return "Nick observed rapid file-renaming behavior by \(actor.isEmpty ? "an unknown process" : actor)."
        }
        return event.decision == .deny
            ? "Nick blocked access to a file previously identified as suspicious."
            : "Nick's system extension found detector-confirmed suspicious file content."
    }

    init(report: RemediationReport) {
        let stableID = Self.stableUUID(
            "\(report.timestamp.timeIntervalSince1970)|\(report.threatPath)|\(report.threatName)"
        )
        let succeeded = report.actions.contains(where: { $0.success })
        signal = ThreatSignal(
            id: stableID,
            source: .filesystem,
            severity: succeeded ? .high : .critical,
            timestamp: report.timestamp,
            title: succeeded ? "Threat remediation completed" : "Threat remediation needs attention",
            description: succeeded
                ? "Nick completed a response action for \(report.threatName)."
                : "Nick detected \(report.threatName), but the requested response did not complete.",
            context: ThreatSignalContext(
                fileInfo: FileInfo(
                    path: report.threatPath,
                    sha256Hash: nil,
                    entropy: nil,
                    signingStatus: nil,
                    sizeBytes: nil
                ),
                metadata: [
                    "reason": "endpoint_remediation",
                    "rule": "endpoint_remediation",
                    "ruleTier": "protected"
                ]
            )
        )
        score = succeeded ? 0.88 : 0.98
        recommendedAction = succeeded
            ? "Review the remediation record and keep the item quarantined unless you trust it."
            : "Review the file immediately and retry quarantine if it is still present."
    }

    /// Deterministic non-cryptographic identifier used only for incident
    /// replay deduplication. Security decisions never depend on this value.
    private static func stableUUID(_ value: String) -> UUID {
        func fnv64(_ bytes: [UInt8], seed: UInt64) -> UInt64 {
            bytes.reduce(seed) { hash, byte in
                (hash ^ UInt64(byte)) &* 1_099_511_628_211
            }
        }
        let bytes = Array(value.utf8)
        let first = fnv64(bytes, seed: 14_695_981_039_346_656_037)
        let second = fnv64(bytes.reversed(), seed: 10_995_116_282_11)
        let raw: [UInt8] = (0..<8).map { UInt8(truncatingIfNeeded: first >> ($0 * 8)) }
            + (0..<8).map { UInt8(truncatingIfNeeded: second >> ($0 * 8)) }
        return UUID(uuid: (
            raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
            raw[8], raw[9], raw[10], raw[11], raw[12], raw[13], raw[14], raw[15]
        ))
    }

    init(violation: IntegrityViolation) {
        signal = ThreatSignal(
            id: violation.id,
            source: .filesystem,
            severity: .high,
            timestamp: violation.timestamp,
            title: "Protected file \(violation.violationType.rawValue)",
            description: "A monitored security-sensitive file changed outside Nick's recorded baseline.",
            context: ThreatSignalContext(
                fileInfo: FileInfo(
                    path: violation.path,
                    sha256Hash: violation.actualHash,
                    entropy: nil,
                    signingStatus: nil,
                    sizeBytes: nil
                ),
                metadata: [
                    "reason": "file_integrity_\(violation.violationType.rawValue)",
                    "rule": "file_integrity_monitor",
                    "ruleTier": "protected",
                    "expectedHash": violation.expectedHash ?? "unavailable"
                ]
            )
        )
        score = 0.9
        recommendedAction = "Review the file and acknowledge the change only if you made it."
    }

    init(privacyAlert: PrivacyAlert) {
        let isGrant = privacyAlert.changeType == .granted
        signal = ThreatSignal(
            id: privacyAlert.id,
            source: .avCapture,
            severity: isGrant ? .medium : .info,
            timestamp: privacyAlert.timestamp,
            title: "\(privacyAlert.service) permission \(privacyAlert.changeType.rawValue)",
            description: "macOS privacy permission changed for \(privacyAlert.appBundleID).",
            context: ThreatSignalContext(metadata: [
                "reason": "tcc_permission_change",
                "rule": "tcc_\(privacyAlert.service.lowercased().replacingOccurrences(of: " ", with: "_"))",
                "service": privacyAlert.service,
                "appBundleID": privacyAlert.appBundleID,
                "appPath": privacyAlert.appPath,
                "changeType": privacyAlert.changeType.rawValue,
                "deviceName": privacyAlert.service,
                "process": privacyAlert.appBundleID,
                "attributionConfidence": "authoritative"
            ])
        )
        score = isGrant ? 0.55 : 0.15
        recommendedAction = isGrant
            ? "Confirm that you expected this permission change in System Settings."
            : "No action is needed if you removed this permission."
    }

    init(usbThreat: USBThreat) {
        signal = ThreatSignal(
            id: usbThreat.id,
            source: .yara,
            severity: .high,
            timestamp: usbThreat.timestamp,
            title: usbThreat.threatName ?? "Threat found on removable media",
            description: "Nick found suspicious content on an external volume.",
            context: ThreatSignalContext(
                fileInfo: FileInfo(
                    path: usbThreat.filePath,
                    sha256Hash: usbThreat.sha256,
                    entropy: nil,
                    signingStatus: nil,
                    sizeBytes: nil
                ),
                metadata: [
                    "reason": "usb_threat",
                    "rule": usbThreat.threatName ?? "usb_threat",
                    "ruleTier": "protected",
                    "volumePath": usbThreat.volumePath,
                    "threatFamily": usbThreat.threatFamily ?? "unknown"
                ]
            )
        )
        score = 0.92
        recommendedAction = "Disconnect the volume and quarantine the file if you do not recognise it."
    }
}

// MARK: - NickAppXPCProtocol (Inbound from Extension)

extension ExtensionXPCClient: NickAppXPCProtocol {

    public nonisolated func reportEvent(_ eventData: Data) {
        guard let event = try? JSONDecoder().decode(ESEvent.self, from: eventData) else {
            Self.logger.error("Failed to decode ESEvent from extension")
            return
        }
        Task { @MainActor [weak self] in
            self?.receive(event)
        }
    }

    public nonisolated func reportThreat(_ threatData: Data) {
        guard let event = try? JSONDecoder().decode(ESEvent.self, from: threatData) else {
            Self.logger.error("Failed to decode threat report from extension")
            return
        }
        Task { @MainActor [weak self] in self?.receive(event) }
    }

    public nonisolated func reportRemediationAction(_ reportData: Data) {
        guard let report = try? JSONDecoder().decode(RemediationReport.self, from: reportData) else {
            Self.logger.error("Failed to decode RemediationReport")
            return
        }
        Task { @MainActor [weak self] in
            self?.receive(report)
        }
    }

    public nonisolated func reportIntegrityViolation(_ violationData: Data) {
        guard let violation = try? JSONDecoder().decode(IntegrityViolation.self, from: violationData) else {
            Self.logger.error("Failed to decode IntegrityViolation")
            return
        }
        Task { @MainActor [weak self] in
            self?.receive(violation)
        }
    }

    public nonisolated func reportStatusChange(_ isActive: Bool) {
        Task { @MainActor [weak self] in
            Self.logger.info("Extension status changed: isActive=\(isActive)")
            self?.isConnected = isActive
        }
    }

    public nonisolated func reportPrivacyAlert(_ alertData: Data) {
        guard let alert = try? JSONDecoder().decode(PrivacyAlert.self, from: alertData) else {
            Self.logger.error("Failed to decode PrivacyAlert")
            return
        }
        Task { @MainActor [weak self] in
            self?.receive(alert)
        }
    }

    public nonisolated func reportUSBThreat(_ threatData: Data) {
        guard let threat = try? JSONDecoder().decode(USBThreat.self, from: threatData) else {
            Self.logger.error("Failed to decode USBThreat")
            return
        }
        Task { @MainActor [weak self] in
            self?.receive(threat)
        }
    }
}
