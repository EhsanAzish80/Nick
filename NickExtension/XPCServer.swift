// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation
import os

// MARK: - ESXPCServer

/// XPC listener running inside the System Extension.
///
/// Listens on the Mach service name `NickExtensionConstants.machServiceName`.
/// Accepts one connection at a time from the container app; stale connections
/// are invalidated and replaced when a new connection arrives.
///
/// Exposes `NickExtensionXPCProtocol` to the container app (inbound calls).
/// Calls `NickAppXPCProtocol` on the container app (outbound event push).
final class ESXPCServer: NSObject {

    // MARK: - Private

    private static let logger = Logger(
        subsystem: "com.ehsanazish.nick.NickExtension",
        category: "XPCServer"
    )

    private var listener: NSXPCListener
    private var appConnection: NSXPCConnection?

    /// Serialises writes to `appConnection`.
    private let connectionLock = NSLock()

    // MARK: - Init

    override init() {
        self.listener = NSXPCListener(machServiceName: NickExtensionConstants.machServiceName)
        super.init()
        listener.delegate = self
    }

    // MARK: - Lifecycle

    /// Starts the XPC listener. Call once from `main.swift`.
    func start() {
        listener.resume()
        Self.logger.info("XPC listener started on \(NickExtensionConstants.machServiceName)")
    }

    // MARK: - Outbound: Extension → Container App

    /// Pushes a JSON-encoded `ESEvent` to the container app.
    func sendEventToApp(_ eventData: Data) {
        withAppProxy { proxy in
            proxy.reportEvent(eventData)
        }
    }

    /// Pushes a JSON-encoded threat payload to the container app (Phase 2+).
    func sendThreatToApp(_ threatData: Data) {
        withAppProxy { proxy in
            proxy.reportThreat(threatData)
        }
    }

    /// Pushes a JSON-encoded `RemediationReport` to the container app (Phase 3+).
    func sendRemediationToApp(_ reportData: Data) {
        withAppProxy { proxy in
            proxy.reportRemediationAction(reportData)
        }
    }

    /// Pushes a JSON-encoded `IntegrityViolation` to the container app (Phase 3+).
    func sendIntegrityViolationToApp(_ violationData: Data) {
        withAppProxy { proxy in
            proxy.reportIntegrityViolation(violationData)
        }
    }

    /// Pushes a JSON-encoded `PrivacyAlert` to the container app (Phase 5+).
    func sendPrivacyAlertToApp(_ alertData: Data) {
        withAppProxy { proxy in
            proxy.reportPrivacyAlert(alertData)
        }
    }

    /// Pushes a JSON-encoded `USBThreat` to the container app (Phase 5+).
    func sendUSBThreatToApp(_ threatData: Data) {
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
        connectionLock.lock()
        let conn = appConnection
        connectionLock.unlock()

        guard let proxy = conn?.remoteObjectProxy as? NickAppXPCProtocol else {
            return
        }
        block(proxy)
    }
}

// MARK: - NSXPCListenerDelegate

extension ESXPCServer: NSXPCListenerDelegate {

    func listener(
        _: NSXPCListener,
        shouldAcceptNewConnection newConnection: NSXPCConnection
    ) -> Bool {
        // Validate caller team ID before accepting.
        guard isAuthorised(connection: newConnection) else {
            Self.logger.warning("Rejected XPC connection from unauthorised process (pid \(newConnection.processIdentifier))")
            return false
        }

        // The extension exposes NickExtensionXPCProtocol inbound.
        newConnection.exportedInterface = NSXPCInterface(with: NickExtensionXPCProtocol.self)
        newConnection.exportedObject    = self

        // The app exposes NickAppXPCProtocol for outbound event push.
        newConnection.remoteObjectInterface = NSXPCInterface(with: NickAppXPCProtocol.self)

        newConnection.invalidationHandler = { [weak self] in
            Self.logger.info("XPC connection invalidated")
            self?.connectionLock.withLock {
                self?.appConnection = nil
            }
        }
        newConnection.interruptionHandler = {
            Self.logger.warning("XPC connection interrupted — container app may have crashed")
        }

        newConnection.resume()

        connectionLock.withLock {
            appConnection = newConnection
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

        // Require the caller to be signed by our team.
        let requirement = "anchor apple generic and certificate leaf[subject.OU] = \"\(NickExtensionConstants.teamID)\""
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

    func requestScan(path _: String, reply: @escaping (Bool, String?) -> Void) {
        // TODO: Phase 2 — on-demand file scanning via ES or YARA.
        reply(false, "On-demand scan not yet implemented (Phase 2)")
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
            monitor.buildBaseline()
            reply(true)
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

    // MARK: - Module back-references (set by main.swift)

    /// Weak reference to the `FileIntegrityMonitor` used to service
    /// `requestRebuildFIMBaseline` calls from the container app.
    nonisolated(unsafe) static weak var fimMonitorRef: FileIntegrityMonitor?

    /// Weak reference to the `RansomwareDetector` used to service
    /// `requestDeployCanaries` calls from the container app.
    nonisolated(unsafe) static weak var ransomwareDetectorRef: RansomwareDetector?
}
