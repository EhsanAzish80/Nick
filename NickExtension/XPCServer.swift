// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation
import Darwin
import os
import Security

private enum ProtectionAuthorization {
    fileprivate static let rightName = "com.ehsanazish.nick.modify-protection"
    enum RightState { case valid, installed, repaired(observed: String), failed }

    static func ensureRight() -> RightState {
        var definition: CFDictionary?
        let getStatus = rightName.withCString { AuthorizationRightGet($0, &definition) }
        if getStatus == errAuthorizationSuccess, let dictionary = definition as? [String: Any] {
            if ProtectionAuthorizationRightPolicy.isExpected(dictionary) { return .valid }
            let observed = ProtectionAuthorizationRightPolicy.observedSummary(dictionary)
            return registerRight() ? .repaired(observed: observed) : .failed
        }
        return registerRight() ? .installed : .failed
    }

    private static func registerRight() -> Bool {
        var authorization: AuthorizationRef?
        guard AuthorizationCreate(nil, nil, [], &authorization) == errAuthorizationSuccess,
              let authorization else { return false }
        defer { AuthorizationFree(authorization, []) }
        let rule: [String: Any] = [
            "class": "rule",
            "rule": ["authenticate-session-owner-or-admin"],
            "timeout": 120,
            "shared": false
        ]
        let status = AuthorizationRightSet(
            authorization,
            rightName,
            rule as CFTypeRef,
            "Nick needs approval to reduce protection settings." as CFString,
            nil,
            nil
        )
        return status == errAuthorizationSuccess
    }

}

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
    private var authenticatedAppPIDs: Set<Int32> = []
    private var storageEligibleAppIdentities: [Int32: Int32] = [:]
    let storageOperationRegistry = StorageOperationRegistry()
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
    weak var updateLeaseManager: NickUpdateLeaseManager?
    var securitySettingsDidChange: ((Data) -> Void)?
    var threatIntelligenceBundleInstaller: ((Data) -> Bool)?

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
        let rightState = ProtectionAuthorization.ensureRight()
        switch rightState {
        case .failed:
            Self.logger.fault("Could not register the protection-modification authorization right")
        case .repaired(let observed):
            reportAuthorizationRuleTamper(observed: observed)
        case .valid, .installed:
            break
        }
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

    func approvedDevelopmentRoots() -> Set<String> {
        guard let record = try? JSONDecoder().decode(
            PrivilegedIncidentStoreRecord.self,
            from: settingsStore.load()
        ),
              let object = try? JSONSerialization.jsonObject(with: record.payload) as? [String: Any]
        else { return [] }
        return Set((object["approvedDevelopmentRoots"] as? [String]) ?? [])
    }

    private func verifyProtectionAuthorization(_ data: Data?) -> Bool {
        switch ProtectionAuthorization.ensureRight() {
        case .repaired(let observed):
            reportAuthorizationRuleTamper(observed: observed)
        case .failed:
            return false
        case .valid, .installed:
            break
        }
        return ProtectionAuthorizationExternalFormVerifier.verify(
            data,
            rightName: ProtectionAuthorization.rightName
        )
    }

    private func reportAuthorizationRuleTamper(observed: String) {
        Self.logger.fault("Protection-modification authorization rule was changed and has been restored")
        let event = ESEvent(
            eventType: .notifyWrite,
            processPath: Bundle.main.executableURL?.path ?? "/Library/SystemExtensions/com.ehsanazish.nick.NickExtension",
            pid: 0,
            parentPid: 0,
            filePath: nil,
            decision: .notApplicable,
            threat: .init(
                threatName: "Nick authorization policy tampering detected",
                threatFamily: "tamper",
                metadata: [
                    "observedRule": observed,
                    "expectedRule": ProtectionAuthorizationRightPolicy.expectedSummary,
                    "repairStatus": "restored"
                ]
            )
        )
        if let data = try? JSONEncoder().encode(event) {
            sendThreatToApp(data)
        }
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
            let errorHandler: @Sendable (Error) -> Void = { error in
                Self.logger.warning("App XPC proxy failed: \(error.localizedDescription, privacy: .public)")
            }
            guard let proxy = connection.remoteObjectProxyWithErrorHandler(errorHandler)
                as? NickAppXPCProtocol else {
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
                let pid = newConnection.processIdentifier
                self?.storageEligibleAppIdentities.removeValue(forKey: pid)
                self?.storageOperationRegistry.cancelForDisconnectedProcess(pid: pid)
            }
        }
        newConnection.interruptionHandler = {
            Self.logger.warning("XPC connection interrupted — container app may have crashed")
        }

        newConnection.resume()

        connectionLock.withLock {
            appConnections[connectionID] = newConnection
            if isReleaseContainer(connection: newConnection) {
                authenticatedAppPIDs.insert(newConnection.processIdentifier)
            }
            if isInstalledReleaseContainer(connection: newConnection) {
                storageEligibleAppIdentities[newConnection.processIdentifier] = 0
            }
        }

        Self.logger.info("Accepted XPC connection from pid \(newConnection.processIdentifier)")
        return true
    }

    /// Consumes proof that this exact process instance previously established
    /// an authenticated container-app connection. XCTest hosts and local
    /// binaries which merely share a name never enter this registry.
    func consumeAuthenticatedAppExit(pid: Int32) -> Bool {
        connectionLock.withLock { authenticatedAppPIDs.remove(pid) != nil }
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

    /// Only the shipped Developer ID container can establish the lifecycle
    /// proof used for unexpected-exit incidents. Development builds and
    /// XCTest hosts may use XPC while testing, but never enter this registry.
    private func isReleaseContainer(connection: NSXPCConnection) -> Bool {
        var code: SecCode?
        let attrs = [kSecGuestAttributePid: connection.processIdentifier] as CFDictionary
        guard SecCodeCopyGuestWithAttributes(nil, attrs, [], &code) == errSecSuccess,
              let code,
              let identifier = Bundle.main.object(
                  forInfoDictionaryKey: "NickAllowedClientIdentifier"
              ) as? String,
              let teamID = Bundle.main.object(
                  forInfoDictionaryKey: "NickAllowedClientTeamID"
              ) as? String else {
            return false
        }
        let text = "identifier \"\(identifier)\" and anchor apple generic "
            + "and certificate 1[field.1.2.840.113635.100.6.2.6] "
            + "and certificate leaf[subject.OU] = \"\(teamID)\""
        var requirement: SecRequirement?
        guard SecRequirementCreateWithString(text as CFString, [], &requirement) == errSecSuccess,
              let requirement else {
            return false
        }
        return SecCodeCheckValidity(code, [], requirement) == errSecSuccess
    }

    /// Storage approvals are intentionally narrower than ordinary app XPC:
    /// only the shipped app at its installed location can receive one. A copied
    /// (even still-validly-signed) Nick.app therefore cannot create a window.
    private func isInstalledReleaseContainer(connection: NSXPCConnection) -> Bool {
        guard isReleaseContainer(connection: connection) else { return false }
        var buffer = [CChar](repeating: 0, count: Int(PATH_MAX))
        let count = proc_pidpath(connection.processIdentifier, &buffer, UInt32(buffer.count))
        guard count > 0 else { return false }
        return String(cString: buffer) == "/Applications/Nick.app/Contents/MacOS/Nick"
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

    func registerStorageOperation(_ payload: Data, reply: @escaping (Bool) -> Void) {
        guard let request = try? JSONDecoder().decode(StorageOperationRequest.self, from: payload) else {
            reply(false)
            return
        }
        let identity: (Int32, Int32)? = connectionLock.withLock {
            guard storageEligibleAppIdentities.count == 1,
                  let entry = storageEligibleAppIdentities.first else { return nil }
            return (entry.key, entry.value)
        }
        guard let identity else {
            reply(false)
            return
        }
        reply(storageOperationRegistry.register(
            request,
            authenticatedPID: identity.0,
            // The app obtains its own kernel audit token. NSXPCConnection
            // exposes the authenticated PID but not that token; the non-zero
            // pidversion is then matched against every ES event before any
            // suppression can occur.
            authenticatedPIDVersion: request.actorPIDVersion
        ))
    }

    func completeStorageOperation(
        operationID: String,
        itemCount: Int,
        bytesMoved: Int64,
        reply: @escaping (Bool) -> Void
    ) {
        guard let id = UUID(uuidString: operationID),
              let operation = storageOperationRegistry.complete(operationID: id) else {
            reply(false)
            return
        }
        guard operation.kind == .trashCleanup else {
            reply(true)
            return
        }
        let formatter = ByteCountFormatter()
        formatter.countStyle = .file
        let event = ESEvent(
            eventType: .notifyWrite,
            processPath: "/Applications/Nick.app/Contents/MacOS/Nick",
            pid: 0,
            parentPid: 0,
            filePath: nil,
            decision: .notApplicable,
            // Metadata-only ES events are retained in Activity/Timeline but
            // ExtensionFinding intentionally ignores them because there is no
            // threat name and no deny decision. Completion is not an incident.
            threat: .init(metadata: [
                    "ruleTier": "observed",
                    "deliveryLevel": "silent",
                    "recordType": "storage-operation-completed",
                    "itemCount": String(max(0, itemCount)),
                    "bytesMoved": String(max(0, bytesMoved)),
                    "summary": "Storage cleanup: \(max(0, itemCount)) items, \(formatter.string(fromByteCount: max(0, bytesMoved))) moved to Trash"
                ])
        )
        if let data = try? JSONEncoder().encode(event) { sendEventToApp(data) }
        reply(true)
    }

    func recordAuthorizedProtectionStop(
        reason: String,
        authorizationExternalForm: Data?,
        reply: @escaping (Bool) -> Void
    ) {
        guard verifyProtectionAuthorization(authorizationExternalForm),
              let ledger = Self.protectionContinuityLedgerRef else {
            reply(false)
            return
        }
        let now = Date()
        let boot = ProtectionBootIdentity.sessionUUID()
        guard ledger.markAuthorizedStop(now: now, bootSessionUUID: boot, reason: reason) else {
            reply(false)
            return
        }
        let event = ESEvent(
            eventType: .notifyWrite,
            processPath: "/Applications/Nick.app/Contents/MacOS/Nick",
            pid: 0,
            parentPid: 0,
            filePath: nil,
            decision: .allow,
            threat: .init(
                threatName: "Protection turned off by user (authorized)",
                threatFamily: "protection-continuity",
                metadata: [
                    "reason": String(reason.prefix(160)),
                    "trust": "root-observed",
                    "ruleTier": "review",
                    "deliveryLevel": "silent"
                ]
            )
        )
        if let data = try? JSONEncoder().encode(event) { sendEventToApp(data) }
        reply(true)
    }

    func ingestAppObservedProtectionGap(_ payload: Data, reply: @escaping (Bool) -> Void) {
        guard payload.count <= 4096,
              let observation = try? JSONDecoder().decode(AppObservedProtectionGap.self, from: payload),
              let ledger = Self.protectionContinuityLedgerRef else {
            reply(false)
            return
        }
        guard ledger.ingestAppObservation(observation) else {
            reply(false)
            return
        }
        let event = ESEvent(
            eventType: .notifyWrite,
            processPath: "/Applications/Nick.app/Contents/MacOS/Nick",
            pid: 0,
            parentPid: 0,
            filePath: nil,
            decision: .notApplicable,
            threat: .init(
                threatName: "Nick app observed protection unavailable",
                threatFamily: "protection-continuity",
                metadata: [
                    "trust": "app-observed",
                    "observationID": observation.id.uuidString,
                    "observedAt": ISO8601DateFormatter().string(from: observation.observedAt),
                    "reason": String(observation.reason.prefix(160)),
                    "ruleTier": "protected",
                    "deliveryLevel": "inform"
                ]
            )
        )
        if let data = try? JSONEncoder().encode(event) { sendThreatToApp(data) }
        reply(true)
    }

    func recordIntentionalAppExit(pid: Int32, reason: String, reply: @escaping (Bool) -> Void) {
        guard pid > 1, reason.count <= 160, let registry = Self.intentionalAppExitRegistryRef else {
            reply(false)
            return
        }
        registry.authorize(pid: pid)
        reply(true)
    }

    func getPersistedEvents(reply: @escaping (Data) -> Void) {
        reply(eventStore.snapshot())
    }

    func acknowledgePersistedThreats(eventIDs: [String]) {
        eventStore.removeThreats(eventIDs: Set(eventIDs.compactMap(UUID.init(uuidString:))))
    }

    func getIncidentStore(reply: @escaping (Data) -> Void) {
        reply(incidentStore.load())
    }

    func getSecuritySettings(reply: @escaping (Data) -> Void) {
        reply(settingsStore.load())
    }

    func migrateSecuritySettings(_ payload: Data, reply: @escaping (Bool, Data) -> Void) {
        let result = settingsStore.migrate(payload: payload)
        if result.accepted { securitySettingsDidChange?(result.record) }
        reply(result.accepted, result.record)
    }

    func replaceSecuritySettings(
        _ payload: Data,
        expectedRevision: UInt64,
        authorizationExternalForm: Data?,
        reply: @escaping (Bool, Data) -> Void
    ) {
        if securitySettingsReduction(from: settingsStore.load(), to: payload),
           !verifyProtectionAuthorization(authorizationExternalForm) {
            reply(false, settingsStore.load())
            return
        }
        let result = settingsStore.replace(payload: payload, expectedRevision: expectedRevision)
        if result.accepted { securitySettingsDidChange?(result.record) }
        reply(result.accepted, result.record)
    }

    func currentSecuritySettingsRecord() -> Data {
        settingsStore.load()
    }

    func installThreatIntelligenceBundle(_ data: Data, reply: @escaping (Bool) -> Void) {
        guard data.count <= 10 * 1_024 * 1_024,
              let installer = threatIntelligenceBundleInstaller else {
            reply(false)
            return
        }
        reply(installer(data))
    }

    func migrateIncidentStore(_ payload: Data, reply: @escaping (Bool, Data) -> Void) {
        let result = incidentStore.migrate(payload: payload)
        reply(result.accepted, result.record)
    }

    func replaceIncidentStore(
        _ payload: Data,
        expectedRevision: UInt64,
        authorizationExternalForm: Data?,
        reply: @escaping (Bool, Data) -> Void
    ) {
        if incidentStoreReduction(from: incidentStore.load(), to: payload),
           !verifyProtectionAuthorization(authorizationExternalForm) {
            reply(false, incidentStore.load())
            return
        }
        let result = incidentStore.replace(payload: payload, expectedRevision: expectedRevision)
        reply(result.accepted, result.record)
    }

    func validateIncidentVerdictTarget(
        alertID: String,
        action: String,
        authorizationExternalForm: Data?,
        reply: @escaping (String) -> Void
    ) {
        reply(IncidentVerdictValidationPolicy.result(
            alertID: alertID,
            action: action,
            existingAlertIDs: incidentAlertIDs(),
            persistentTrustEligible: IncidentStoreTrustEligibilityPolicy.isEligible(
                alertID: alertID,
                encodedRecord: incidentStore.load()
            ),
            hasProtectionAuthorization: verifyProtectionAuthorization(authorizationExternalForm)
        ).rawValue)
    }

    func requestUpdateLease(
        sourceBuild: Int,
        destinationBuild: Int,
        authorizationExternalForm: Data?,
        reply: @escaping (Bool) -> Void
    ) {
        guard verifyProtectionAuthorization(authorizationExternalForm),
              let manager = updateLeaseManager,
              let consoleUser = TamperConsoleUserResolver.current(),
              let runningBuildString = Bundle.main.object(
                  forInfoDictionaryKey: "CFBundleVersion"
              ) as? String,
              let runningBuild = Int(runningBuildString),
              sourceBuild == runningBuild else {
            reply(false)
            return
        }
        reply(manager.create(
            consoleUID: consoleUser.uid,
            sourceBuild: sourceBuild,
            destinationBuild: destinationBuild
        ))
    }

    func requestQuarantineFile(
        path: String,
        expectedThreatName: String,
        expectedSHA256: String,
        reply: @escaping (Bool, String?, Data?) -> Void
    ) {
        guard let scanner = ESXPCServer.fileScannerRef,
              let manager = ESXPCServer.quarantineManagerRef else {
            reply(false, "Nick's protection service is not ready.", nil)
            return
        }

        let standardPath = URL(fileURLWithPath: path).standardizedFileURL.path
        guard !LOLBinExecutionPolicy.isProtectedSystemPath(standardPath) else {
            reply(false, "Nick will not move a protected macOS system executable.", nil)
            return
        }
        guard !Self.isAppleSystemExecutable(at: standardPath) else {
            reply(false, "Nick will not move an Apple-signed system executable.", nil)
            return
        }
        var isDirectory: ObjCBool = false
        guard standardPath.hasPrefix("/"),
              FileManager.default.fileExists(atPath: standardPath, isDirectory: &isDirectory),
              !isDirectory.boolValue else {
            reply(false, "The detected file no longer exists.", nil)
            return
        }

        DispatchQueue.global(qos: .userInitiated).async {
            let result = scanner.scan(filePath: standardPath)
            let reviewedHash = expectedSHA256.lowercased()
            if !reviewedHash.isEmpty,
               (reviewedHash.count != 64 || result.hash.lowercased() != reviewedHash) {
                let failure = QuarantineFailure(
                    reason: .fileChanged,
                    errorDomain: NSPOSIXErrorDomain,
                    errorCode: Int(ESTALE)
                )
                reply(false, failure.statusLine + ". " + failure.guidance, try? JSONEncoder().encode(failure))
                return
            }
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
            let quarantineResult = manager.quarantine(
                filePath: standardPath,
                hash: reviewedHash.isEmpty ? result.hash : reviewedHash,
                threatName: threatName,
                severity: "critical",
                processPath: "",
                pid: 0
            )
            switch quarantineResult {
            case .success(let record):
                reply(true, nil, try? JSONEncoder().encode(record))
            case .failure(let failure):
                reply(false, failure.statusLine + ". " + failure.guidance, try? JSONEncoder().encode(failure))
            }
        }
    }

    private static func isAppleSystemExecutable(at path: String) -> Bool {
        var code: SecStaticCode?
        guard SecStaticCodeCreateWithPath(URL(fileURLWithPath: path) as CFURL, [], &code) == errSecSuccess,
              let code else { return false }
        var requirement: SecRequirement?
        guard SecRequirementCreateWithString("anchor apple" as CFString, [], &requirement) == errSecSuccess,
              let requirement else { return false }
        return SecStaticCodeCheckValidity(
            code,
            SecCSFlags(rawValue: UInt32(kSecCSDoNotValidateResources)),
            requirement
        ) == errSecSuccess
    }

    func requestAllowFileOnce(
        path: String,
        authorizationExternalForm: Data?,
        reply: @escaping (Bool) -> Void
    ) {
        guard verifyProtectionAuthorization(authorizationExternalForm) else {
            reply(false)
            return
        }
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

    func getPendingFIMViolations(reply: @escaping (Data) -> Void) {
        guard let monitor = ESXPCServer.fimMonitorRef,
              let data = try? JSONEncoder().encode(monitor.pendingViolationSnapshot()) else {
            reply(Data())
            return
        }
        reply(data)
    }

    func acknowledgeFIMViolation(
        id: String,
        authorizationExternalForm: Data?,
        reply: @escaping (Bool) -> Void
    ) {
        guard let id = UUID(uuidString: id),
              let monitor = ESXPCServer.fimMonitorRef,
              verifyProtectionAuthorization(authorizationExternalForm) else {
            reply(false)
            return
        }
        DispatchQueue.global(qos: .utility).async {
            reply(monitor.acknowledgeViolation(id: id))
        }
    }

    /// Alert IDs are the canonical user-action target. `SecurityIncident.id`
    /// remains an internal persistence identity and must never cross this API.
    private func incidentAlertIDs() -> Set<String> {
        IncidentStoreAlertIDPolicy.alertIDs(from: incidentStore.load())
    }

    private func securitySettingsReduction(from encodedRecord: Data, to payload: Data) -> Bool {
        SecuritySettingsWritePolicy.requiresAuthorization(
            previousRecord: encodedRecord,
            proposedPayload: payload
        )
    }

    private func incidentStoreReduction(from encodedRecord: Data, to payload: Data) -> Bool {
        guard let record = try? JSONDecoder().decode(PrivilegedIncidentStoreRecord.self, from: encodedRecord),
              record.schemaVersion == PrivilegedIncidentStoreRecord.currentSchemaVersion else {
            return true
        }
        return IncidentStoreWritePolicy.requiresAuthorization(
            previousPayload: record.payload,
            proposedPayload: payload
        )
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
        authorizationExternalForm: Data?,
        reply: @escaping (Bool) -> Void
    ) {
        guard verifyProtectionAuthorization(authorizationExternalForm) else {
            reply(false)
            return
        }
        guard let id = UUID(uuidString: id),
              let manager = ESXPCServer.quarantineManagerRef else {
            reply(false)
            return
        }
        DispatchQueue.global(qos: .userInitiated).async {
            reply(manager.restore(id: id))
        }
    }

#if DEBUG
    func debugValidateProtectionAuthorization(
        authorizationExternalForm: Data,
        reply: @escaping (Bool) -> Void
    ) {
        reply(verifyProtectionAuthorization(authorizationExternalForm))
    }
#endif

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
    nonisolated(unsafe) static weak var protectionContinuityLedgerRef: ProtectionContinuityLedger?
    nonisolated(unsafe) static weak var intentionalAppExitRegistryRef: IntentionalAppExitRegistry?

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

    func removeThreats(eventIDs: Set<UUID>) {
        guard !eventIDs.isEmpty else { return }
        queue.async {
            var events = self.load()
            events.removeAll { finding in
                guard finding.kind == .threat,
                      let event = try? JSONDecoder().decode(ESEvent.self, from: finding.payload)
                else { return false }
                return eventIDs.contains(event.id)
            }
            do {
                let encoded = try JSONEncoder().encode(events)
                try encoded.write(to: self.url, options: .atomic)
                try FileManager.default.setAttributes(
                    [.posixPermissions: 0o600],
                    ofItemAtPath: self.url.path
                )
            } catch {
                ESXPCServer.logger.error(
                    "Could not acknowledge persisted threats: \(error.localizedDescription, privacy: .public)"
                )
            }
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
