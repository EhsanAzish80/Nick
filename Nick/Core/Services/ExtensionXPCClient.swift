// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation
import os

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
    private var pendingIncidentPayload: Data?
    private var incidentWriteInFlight = false
    private var incidentBootstrapCompleted = false
    private var bootstrapLegacyPayload: Data?
    private var bootstrapCompletion: (@MainActor @Sendable (PrivilegedIncidentStoreRecord?, Bool) -> Void)?
    private var bootstrapReconnectTask: Task<Void, Never>?
    private var bootstrapReconnectAttempt = 0

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
                    self?.loadPersistedEvents()
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

    func persistIncidentStore(_ payload: Data) {
        pendingIncidentPayload = payload
        drainIncidentStoreWrites()
    }

    private func drainIncidentStoreWrites() {
        guard !incidentWriteInFlight,
              let payload = pendingIncidentPayload,
              let revision = incidentRevision,
              let proxy = connection?.remoteObjectProxy as? NickExtensionXPCProtocol else { return }
        pendingIncidentPayload = nil
        incidentWriteInFlight = true
        proxy.replaceIncidentStore(payload, expectedRevision: revision) { [weak self] accepted, recordData in
            Task { @MainActor [weak self] in
                guard let self else { return }
                self.incidentWriteInFlight = false
                if let record = try? JSONDecoder().decode(
                    PrivilegedIncidentStoreRecord.self,
                    from: recordData
                ) {
                    self.incidentRevision = record.revision
                }
                if !accepted {
                    self.pendingIncidentPayload = self.pendingIncidentPayload ?? payload
                }
                self.drainIncidentStoreWrites()
            }
        }
    }

    func authoriseIncidentVerdict(id: UUID, action: IncidentActionKind) async -> Bool {
        guard let proxy = connection?.remoteObjectProxy as? NickExtensionXPCProtocol else { return false }
        return await withCheckedContinuation { continuation in
            proxy.authoriseIncidentVerdict(
                incidentID: id.uuidString,
                action: action.rawValue,
                reply: { continuation.resume(returning: $0) }
            )
        }
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

    private func receivePersisted(_ finding: PersistedExtensionFinding) async {
        switch finding.kind {
        case .endpointEvent, .threat:
            guard let event = try? decoder.decode(ESEvent.self, from: finding.payload) else { return }
            receive(event)
        case .remediation:
            guard let report = try? decoder.decode(RemediationReport.self, from: finding.payload) else { return }
            receive(report)
        case .integrityViolation:
            guard let violation = try? decoder.decode(IntegrityViolation.self, from: finding.payload) else { return }
            receive(violation)
        case .privacyAlert:
            guard let alert = try? decoder.decode(PrivacyAlert.self, from: finding.payload) else { return }
            receive(alert)
        case .usbThreat:
            guard let threat = try? decoder.decode(USBThreat.self, from: finding.payload) else { return }
            receive(threat)
        }
    }

    private func receive(_ event: ESEvent) {
        if !events.contains(where: { $0.id == event.id }) { events.insert(event, at: 0) }
        trim(&events)
        if let finding = ExtensionFinding(event: event) { deliver(finding) }
    }

    private func receive(_ report: RemediationReport) {
        if let record = report.quarantineRecord {
            quarantineRecords.removeAll { $0.id == record.id }
            quarantineRecords.insert(record, at: 0)
        }
        deliver(ExtensionFinding(report: report))
    }

    private func receive(_ violation: IntegrityViolation) {
        if !integrityViolations.contains(where: { $0.id == violation.id }) {
            integrityViolations.insert(violation, at: 0)
        }
        trim(&integrityViolations)
        deliver(ExtensionFinding(violation: violation))
    }

    private func receive(_ alert: PrivacyAlert) {
        if !privacyAlerts.contains(where: { $0.id == alert.id }) { privacyAlerts.insert(alert, at: 0) }
        trim(&privacyAlerts)
        deliver(ExtensionFinding(privacyAlert: alert))
    }

    private func receive(_ threat: USBThreat) {
        if !usbThreats.contains(where: { $0.id == threat.id }) { usbThreats.insert(threat, at: 0) }
        trim(&usbThreats)
        deliver(ExtensionFinding(usbThreat: threat))
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
        proxy.requestAllowFileOnce(path: path, reply: completion)
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
        proxy.requestRestoreQuarantinedFile(id: id.uuidString) { [weak self] success in
            Task { @MainActor [weak self] in
                if success {
                    self?.quarantineRecords.removeAll { $0.id == id }
                }
                completion(success)
            }
        }
    }

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
        let isManagementObservation = event.threatFamily == "endpoint-management"
        let severity: SignalSeverity
        if event.decision == .deny {
            severity = .critical
        } else if isManagementObservation {
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
        let ruleClass = isTamper ? "integrity" : (isManagementObservation ? "audit" : "signature")
        let ruleTier = isManagementObservation ? "review" : "protected"
        signal = ThreatSignal(
            id: event.id,
            source: .endpointSecurity,
            severity: severity,
            timestamp: event.timestamp,
            title: event.threatName ?? "Endpoint Security blocked a file",
            description: Self.description(
                for: event,
                isTamper: isTamper,
                isManagementObservation: isManagementObservation
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
                        : (isManagementObservation ? "endpoint_management_observed" : "endpoint_threat"),
                    "rule": event.threatName ?? "endpoint_known_threat",
                    "class": ruleClass,
                    "ruleTier": ruleTier,
                    "threatFamily": event.threatFamily ?? "unknown"
                ]
            )
        )
        score = event.decision == .deny ? 0.98 : (isManagementObservation ? 0.1 : 0.9)
        recommendedAction = isManagementObservation
            ? "No action is needed if you ran this command."
            : "Review the event and investigate it if you do not recognise the activity."
    }

    private static func description(
        for event: ESEvent,
        isTamper: Bool,
        isManagementObservation: Bool
    ) -> String {
        if isManagementObservation {
            return "Nick observed routine use of Apple's system-extension management tool."
        }
        if isTamper {
            return "Nick observed an attempt to change a protected Nick path. The operation was allowed."
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
