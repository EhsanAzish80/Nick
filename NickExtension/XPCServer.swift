// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation
import os

// MARK: - ESXPCServer

/// XPC listener running inside the System Extension.
///
/// Listens on the Mach service name `NickExtensionConstants.machServiceName`.
/// Keeps each independently authenticated app connection until that connection
/// invalidates. A second connection can never replace the first connection's
/// event channel or inherit its lifecycle.
///
/// Exposes `NickExtensionXPCProtocol` to the container app (inbound calls).
/// Calls `NickAppXPCProtocol` on the container app (outbound event push).
final class ESXPCServer: NSObject {

    // MARK: - Private

    fileprivate static let logger = Logger(
        subsystem: "com.ehsanazish.nick.NickExtension",
        category: "XPCServer"
    )

    private var listener: NSXPCListener
    private var appConnections: [ObjectIdentifier: NSXPCConnection] = [:]
    private let listenerIsConfigured: Bool

    /// Serialises the independently authenticated connection set.
    private let connectionLock = NSLock()
    private let eventStore = EndpointEventStore(
        path: "/Library/Application Support/com.ehsanazish.nick/events/endpoint-events.json",
        legacyPath: "/Library/Application Support/com.ehsanazish.nick/endpoint-events.json"
    )
    private let incidentStore = PrivilegedIncidentFileStore()
    private let settingsStore = PrivilegedIncidentFileStore(
        fileURL: URL(fileURLWithPath: "/Library/Application Support/com.ehsanazish.nick/state/settings.json")
    )

    // MARK: - Init

    override init() {
        let configuredListener = NSXPCListener(
            machServiceName: NickExtensionConstants.machServiceName
        )
        var configured = false
        if let identifier = Bundle.main.object(
            forInfoDictionaryKey: "NickAllowedClientIdentifier"
        ) as? String,
           let teamID = Bundle.main.object(
               forInfoDictionaryKey: "NickAllowedClientTeamID"
           ) as? String,
           !identifier.isEmpty,
           !teamID.isEmpty,
           !identifier.contains("$("),
           !teamID.contains("$(") {
            let requirement = "identifier \"\(identifier)\" and anchor apple generic "
                + "and certificate leaf[subject.OU] = \"\(teamID)\""
            configuredListener.setConnectionCodeSigningRequirement(requirement)
            configured = true
        }
        self.listener = configuredListener
        self.listenerIsConfigured = configured
        super.init()
        listener.delegate = self
    }

    // MARK: - Lifecycle

    /// Starts the XPC listener. Call once from `main.swift`.
    func start() {
        guard listenerIsConfigured else {
            Self.logger.fault("XPC listener not started because its client identity is not configured")
            return
        }
        listener.resume()
        Self.logger.info("XPC listener started on \(NickExtensionConstants.machServiceName)")
    }

    var listenerConfigurationStatus: String {
        listenerIsConfigured ? "configured" : "missing"
    }

    // MARK: - Outbound: Extension → Container App

    /// Pushes a JSON-encoded `ESEvent` to the container app.
    func sendEventToApp(_ eventData: Data) {
        eventStore.appendIfImportant(.init(kind: .endpointEvent, payload: eventData))
        withAppProxy { proxy in
            proxy.reportEvent(eventData)
        }
    }

    /// Pushes a JSON-encoded threat payload to the container app (Phase 2+).
    func sendThreatToApp(_ threatData: Data) {
        eventStore.append(.init(kind: .threat, payload: threatData))
        withAppProxy { proxy in
            proxy.reportThreat(threatData)
        }
    }

    /// Pushes a JSON-encoded `RemediationReport` to the container app (Phase 3+).
    func sendRemediationToApp(_ reportData: Data) {
        eventStore.append(.init(kind: .remediation, payload: reportData))
        withAppProxy { proxy in
            proxy.reportRemediationAction(reportData)
        }
    }

    /// Pushes a JSON-encoded `IntegrityViolation` to the container app (Phase 3+).
    func sendIntegrityViolationToApp(_ violationData: Data) {
        eventStore.append(.init(kind: .integrityViolation, payload: violationData))
        withAppProxy { proxy in
            proxy.reportIntegrityViolation(violationData)
        }
    }

    /// Pushes a JSON-encoded `PrivacyAlert` to the container app (Phase 5+).
    func sendPrivacyAlertToApp(_ alertData: Data) {
        eventStore.append(.init(kind: .privacyAlert, payload: alertData))
        withAppProxy { proxy in
            proxy.reportPrivacyAlert(alertData)
        }
    }

    /// Pushes a JSON-encoded `USBThreat` to the container app (Phase 5+).
    func sendUSBThreatToApp(_ threatData: Data) {
        eventStore.append(.init(kind: .usbThreat, payload: threatData))
        withAppProxy { proxy in
            proxy.reportUSBThreat(threatData)
        }
    }

    /// Notifies the container app that the extension's running state changed.
    func sendStatusChange(isActive: Bool) {
        withAppProxy { proxy in
            proxy.reportStatusChange(isActive)
        }
    }

    // MARK: - Private Helpers

    private func withAppProxy(_ block: (NickAppXPCProtocol) -> Void) {
        let connections = connectionLock.withLock { Array(appConnections.values) }
        for connection in connections {
            guard let proxy = connection.remoteObjectProxy as? NickAppXPCProtocol else {
                continue
            }
            block(proxy)
        }
    }
}

// MARK: - NSXPCListenerDelegate

extension ESXPCServer: NSXPCListenerDelegate {

    func listener(
        _: NSXPCListener,
        shouldAcceptNewConnection newConnection: NSXPCConnection
    ) -> Bool {
        // Keep the legacy validation for one release as defence in depth. The
        // listener has already required Nick's exact signed identifier before
        // this delegate can be reached.
        guard isAuthorised(connection: newConnection) else {
            Self.logger.warning("Rejected XPC connection from unauthorised process (pid \(newConnection.processIdentifier))")
            return false
        }

        // The extension exposes NickExtensionXPCProtocol inbound.
        newConnection.exportedInterface = NSXPCInterface(with: NickExtensionXPCProtocol.self)
        newConnection.exportedObject    = self

        // The app exposes NickAppXPCProtocol for outbound event push.
        newConnection.remoteObjectInterface = NSXPCInterface(with: NickAppXPCProtocol.self)

        let connectionID = ObjectIdentifier(newConnection)
        newConnection.invalidationHandler = { [weak self] in
            Self.logger.info("XPC connection invalidated")
            self?.connectionLock.withLock {
                self?.appConnections.removeValue(forKey: connectionID)
            }
        }
        newConnection.interruptionHandler = {
            Self.logger.warning("XPC connection interrupted — container app may have crashed")
        }

        newConnection.resume()

        connectionLock.withLock {
            appConnections[connectionID] = newConnection
        }

        Self.logger.info("Accepted XPC connection from pid \(newConnection.processIdentifier)")
        return true
    }

    // MARK: - Caller Validation

    /// Validates that the connecting process is signed by the authorised team ID.
    private func isAuthorised(connection: NSXPCConnection) -> Bool {
        var code: SecCode?
        let attrs = [kSecGuestAttributePid: connection.processIdentifier] as CFDictionary
        guard SecCodeCopyGuestWithAttributes(nil, attrs, [], &code) == errSecSuccess,
              let code else {
            Self.logger.warning("Could not obtain SecCode for pid \(connection.processIdentifier)")
            return false
        }

        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess,
              let staticCode else {
            return false
        }

        guard let identifier = Bundle.main.object(
            forInfoDictionaryKey: "NickAllowedClientIdentifier"
        ) as? String,
              let teamID = Bundle.main.object(
                  forInfoDictionaryKey: "NickAllowedClientTeamID"
              ) as? String else {
            return false
        }
        let requirement = "identifier \"\(identifier)\" and anchor apple generic "
            + "and certificate leaf[subject.OU] = \"\(teamID)\""
        var reqRef: SecRequirement?
        guard SecRequirementCreateWithString(requirement as CFString, [], &reqRef) == errSecSuccess,
              let reqRef else {
            return false
        }

        return SecStaticCodeCheckValidity(staticCode, [], reqRef) == errSecSuccess
    }
}

// MARK: - NickExtensionXPCProtocol (inbound calls from container app)

extension ESXPCServer: NickExtensionXPCProtocol {

    func getStatus(reply: @escaping (Bool) -> Void) {
        // Phase 1: always report active while the extension is running.
        reply(true)
    }

    func getExtensionHealth(reply: @escaping (Data) -> Void) {
        let path = "/Library/Application Support/com.ehsanazish.nick/extension_health.json"
        reply(FileManager.default.contents(atPath: path) ?? Data())
    }

    func getPersistedEvents(reply: @escaping (Data) -> Void) {
        reply(eventStore.snapshot())
    }

    func getIncidentStore(reply: @escaping (Data) -> Void) {
        reply(incidentStore.load())
    }

    func getSecuritySettings(reply: @escaping (Data) -> Void) {
        reply(settingsStore.load())
    }

    func migrateSecuritySettings(_ payload: Data, reply: @escaping (Bool, Data) -> Void) {
        let result = settingsStore.migrate(payload: payload)
        reply(result.accepted, result.record)
    }

    func replaceSecuritySettings(
        _ payload: Data,
        expectedRevision: UInt64,
        reply: @escaping (Bool, Data) -> Void
    ) {
        let result = settingsStore.replace(payload: payload, expectedRevision: expectedRevision)
        reply(result.accepted, result.record)
    }

    func migrateIncidentStore(_ payload: Data, reply: @escaping (Bool, Data) -> Void) {
        let result = incidentStore.migrate(payload: payload)
        reply(result.accepted, result.record)
    }

    func replaceIncidentStore(
        _ payload: Data,
        expectedRevision: UInt64,
        reply: @escaping (Bool, Data) -> Void
    ) {
        let result = incidentStore.replace(payload: payload, expectedRevision: expectedRevision)
        reply(result.accepted, result.record)
    }

    func authoriseIncidentVerdict(
        incidentID: String,
        action: String,
        reply: @escaping (Bool) -> Void
    ) {
        let allowedActions: Set<String> = [
            "reviewed", "hidden", "dismissed", "resolved", "allowedOnce", "alwaysAllowed"
        ]
        reply(UUID(uuidString: incidentID) != nil && allowedActions.contains(action))
    }

    func requestQuarantineFile(
        path: String,
        expectedThreatName: String,
        reply: @escaping (Bool, String?, Data?) -> Void
    ) {
        guard let scanner = ESXPCServer.fileScannerRef,
              let manager = ESXPCServer.quarantineManagerRef else {
            reply(false, "Nick's protection service is not ready.", nil)
            return
        }

        let standardPath = URL(fileURLWithPath: path).standardizedFileURL.path
        var isDirectory: ObjCBool = false
        guard standardPath.hasPrefix("/"),
              FileManager.default.fileExists(atPath: standardPath, isDirectory: &isDirectory),
              !isDirectory.boolValue else {
            reply(false, "The detected file no longer exists.", nil)
            return
        }

        DispatchQueue.global(qos: .userInitiated).async {
            let result = scanner.scan(filePath: standardPath)
            guard result.isThreat else {
                reply(
                    false,
                    "Nick re-scanned the file and could not confirm the detection. The file was not moved.",
                    nil
                )
                return
            }
            guard !result.hash.isEmpty else {
                reply(false, "Nick could not read the detected file.", nil)
                return
            }

            let threatName = result.threatName
                ?? (expectedThreatName.isEmpty ? "Detected threat" : expectedThreatName)
            guard let record = manager.quarantine(
                filePath: standardPath,
                hash: result.hash,
                threatName: threatName,
                severity: "critical",
                processPath: "",
                pid: 0
            ) else {
                reply(false, "Nick could not move this file into quarantine.", nil)
                return
            }
            reply(true, nil, try? JSONEncoder().encode(record))
        }
    }

    func requestAllowFileOnce(path: String, reply: @escaping (Bool) -> Void) {
        guard let scanner = ESXPCServer.fileScannerRef else {
            reply(false)
            return
        }
        let standardPath = URL(fileURLWithPath: path).standardizedFileURL.path
        guard standardPath.hasPrefix("/") else {
            reply(false)
            return
        }
        guard let resolvedPath = EndpointSecurityPath.canonical(standardPath),
              let identity = FileIdentity(path: resolvedPath),
              let currentHash = scanner.contentHash(path: resolvedPath) else {
            reply(false)
            return
        }
        let result = scanner.cache.allowOnce(
            reviewedPath: standardPath,
            authorizationPath: resolvedPath,
            currentIdentity: identity,
            currentHash: currentHash
        )
        switch result {
        case .findingExpired:
            Self.logger.warning("Allow-once refused because the reviewed finding expired")
            reply(false)
            return
        case .fileChanged:
            Self.logger.warning("Allow-once refused because reviewed file identity changed")
            reply(false)
            return
        case .allowed:
            break
        }
        Self.logger.notice("User allowed one authorization for \(standardPath, privacy: .private)")
        reply(true)
    }

    func requestBlockReviewedFile(path: String, reply: @escaping (Bool) -> Void) {
        guard let scanner = ESXPCServer.fileScannerRef else {
            reply(false)
            return
        }
        let standardPath = URL(fileURLWithPath: path).standardizedFileURL.path
        let blocked = scanner.cache.blockReviewedFinding(path: standardPath)
        if blocked {
            Self.logger.notice("User blocked reviewed finding \(standardPath, privacy: .private)")
        }
        reply(blocked)
    }

    func requestRebuildFIMBaseline(reply: @escaping (Bool) -> Void) {
        // Delegate to the FileIntegrityMonitor that was wired in at startup.
        // The extension does not keep a strong reference to the monitor here,
        // so we use a module-level accessor set during main.swift initialisation.
        guard let monitor = ESXPCServer.fimMonitorRef else {
            reply(false)
            return
        }
        DispatchQueue.global(qos: .utility).async {
            guard monitor.pendingViolationCount == 0 else {
                reply(false)
                return
            }
            reply(monitor.buildBaseline())
        }
    }

    func acknowledgeFIMViolation(id: String, reply: @escaping (Bool) -> Void) {
        guard let id = UUID(uuidString: id),
              let monitor = ESXPCServer.fimMonitorRef else {
            reply(false)
            return
        }
        DispatchQueue.global(qos: .utility).async {
            reply(monitor.acknowledgeViolation(id: id))
        }
    }

    func requestDeployCanaries(reply: @escaping (Bool) -> Void) {
        guard let detector = ESXPCServer.ransomwareDetectorRef else {
            reply(false)
            return
        }
        DispatchQueue.global(qos: .utility).async {
            detector.canaryManager.deployCanaries()
            reply(true)
        }
    }

    func requestRestoreQuarantinedFile(
        id: String,
        reply: @escaping (Bool) -> Void
    ) {
        guard let id = UUID(uuidString: id),
              let manager = ESXPCServer.quarantineManagerRef else {
            reply(false)
            return
        }
        DispatchQueue.global(qos: .userInitiated).async {
            reply(manager.restore(id: id))
        }
    }

    func requestDeleteQuarantinedFile(
        id: String,
        reply: @escaping (Bool) -> Void
    ) {
        guard let id = UUID(uuidString: id),
              let manager = ESXPCServer.quarantineManagerRef else {
            reply(false)
            return
        }
        DispatchQueue.global(qos: .userInitiated).async {
            reply(manager.deletePermanently(id: id))
        }
    }

    // MARK: - Module back-references (set by main.swift)

    /// Weak reference to the `FileIntegrityMonitor` used to service
    /// `requestRebuildFIMBaseline` calls from the container app.
    nonisolated(unsafe) static weak var fimMonitorRef: FileIntegrityMonitor?

    /// Weak reference to the `RansomwareDetector` used to service
    /// `requestDeployCanaries` calls from the container app.
    nonisolated(unsafe) static weak var ransomwareDetectorRef: RansomwareDetector?

    nonisolated(unsafe) static weak var quarantineManagerRef: QuarantineManager?

    nonisolated(unsafe) static weak var fileScannerRef: FileScanner?
}

/// Small durable ring buffer for denied and threat-enriched ES events. Routine
/// writes stay live-only so database journals cannot create continuous disk I/O.
private final class EndpointEventStore {
    private let url: URL
    private let queue = DispatchQueue(
        label: "com.ehsanazish.nick.NickExtension.persisted-events",
        qos: .utility
    )
    private let maximumCount = 250

    init(path: String, legacyPath: String) {
        url = URL(fileURLWithPath: path)
        let directory = url.deletingLastPathComponent()
        let fileManager = FileManager.default
        do {
            try fileManager.createDirectory(
                at: directory,
                withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o700]
            )
            try fileManager.setAttributes(
                [.posixPermissions: 0o700],
                ofItemAtPath: directory.path
            )

            let legacyURL = URL(fileURLWithPath: legacyPath)
            if !fileManager.fileExists(atPath: url.path),
               fileManager.fileExists(atPath: legacyURL.path) {
                try fileManager.moveItem(at: legacyURL, to: url)
            } else if fileManager.fileExists(atPath: url.path),
                      fileManager.fileExists(atPath: legacyURL.path) {
                // A prior interrupted migration may leave both files behind.
                // The protected file is authoritative; remove the stale public
                // copy so old path-bearing events do not remain readable.
                try fileManager.removeItem(at: legacyURL)
            }
            if fileManager.fileExists(atPath: url.path) {
                try fileManager.setAttributes(
                    [.posixPermissions: 0o600],
                    ofItemAtPath: url.path
                )
            }
        } catch {
            ESXPCServer.logger.error(
                "Could not prepare protected event storage: \(error.localizedDescription, privacy: .public)"
            )
        }
    }

    func appendIfImportant(_ finding: PersistedExtensionFinding) {
        guard let event = try? JSONDecoder().decode(ESEvent.self, from: finding.payload),
              event.decision == .deny || event.threatName != nil else { return }
        append(finding)
    }

    func append(_ finding: PersistedExtensionFinding) {
        queue.async {
            var events = self.load()
            guard !events.contains(where: { $0.id == finding.id }) else { return }
            events.append(finding)
            if events.count > self.maximumCount {
                events.removeFirst(events.count - self.maximumCount)
            }
            do {
                try FileManager.default.createDirectory(
                    at: self.url.deletingLastPathComponent(),
                    withIntermediateDirectories: true,
                    attributes: [.posixPermissions: 0o700]
                )
                let encoded = try JSONEncoder().encode(events)
                try encoded.write(to: self.url, options: .atomic)
                try FileManager.default.setAttributes(
                    [.posixPermissions: 0o600],
                    ofItemAtPath: self.url.path
                )
            } catch {
                ESXPCServer.logger.error(
                    "Could not persist important event: \(error.localizedDescription, privacy: .public)"
                )
            }
        }
    }

    func snapshot() -> Data {
        queue.sync {
            (try? JSONEncoder().encode(load())) ?? Data("[]".utf8)
        }
    }

    private func load() -> [PersistedExtensionFinding] {
        guard let data = try? Data(contentsOf: url) else { return [] }
        if let findings = try? JSONDecoder().decode([PersistedExtensionFinding].self, from: data) {
            return findings
        }
        // One-time migration from the 4.6.3 ESEvent-only journal.
        let oldEvents = (try? JSONDecoder().decode([ESEvent].self, from: data)) ?? []
        return oldEvents.compactMap { event in
            guard let payload = try? JSONEncoder().encode(event) else { return nil }
            return PersistedExtensionFinding(
                id: event.id,
                kind: .endpointEvent,
                timestamp: event.timestamp,
                payload: payload
            )
        }
    }
}
