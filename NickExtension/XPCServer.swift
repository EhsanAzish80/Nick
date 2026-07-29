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

    fileprivate static let logger = Logger(
        subsystem: "com.ehsanazish.nick.NickExtension",
        category: "XPCServer"
    )

    private var listener: NSXPCListener
    private var appConnection: NSXPCConnection?

    /// Serialises writes to `appConnection`.
    private let connectionLock = NSLock()
    private let eventStore = EndpointEventStore(
        path: "/Library/Application Support/com.ehsanazish.nick/endpoint-events.json"
    )

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
        eventStore.appendIfImportant(eventData)
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

    func getPersistedEvents(reply: @escaping (Data) -> Void) {
        reply(eventStore.snapshot())
    }

    func requestScan(path: String, reply: @escaping (Bool, String?) -> Void) {
        guard let scanner = ESXPCServer.fileScannerRef else {
            reply(false, "The security scanner is not ready.")
            return
        }

        let standardPath = URL(fileURLWithPath: path).standardizedFileURL.path
        guard standardPath.hasPrefix("/"), FileManager.default.fileExists(atPath: standardPath) else {
            reply(false, "The selected item no longer exists.")
            return
        }

        DispatchQueue.global(qos: .userInitiated).async {
            var isDirectory: ObjCBool = false
            FileManager.default.fileExists(atPath: standardPath, isDirectory: &isDirectory)
            let paths: [String]
            if isDirectory.boolValue {
                guard let enumerator = FileManager.default.enumerator(
                    at: URL(fileURLWithPath: standardPath),
                    includingPropertiesForKeys: [.isRegularFileKey, .fileSizeKey],
                    options: [.skipsHiddenFiles, .skipsPackageDescendants]
                ) else {
                    reply(false, "Nick could not read the selected folder.")
                    return
                }
                var collected: [String] = []
                for case let fileURL as URL in enumerator {
                    guard collected.count < 10_000 else {
                        reply(false, "The folder contains more than 10,000 files. Choose a smaller folder.")
                        return
                    }
                    let values = try? fileURL.resourceValues(forKeys: [.isRegularFileKey, .fileSizeKey])
                    guard values?.isRegularFile == true,
                          (values?.fileSize ?? 0) <= 250 * 1_024 * 1_024 else { continue }
                    collected.append(fileURL.path)
                }
                paths = collected
            } else {
                let values = try? URL(fileURLWithPath: standardPath)
                    .resourceValues(forKeys: [.isRegularFileKey, .fileSizeKey])
                guard values?.isRegularFile == true else {
                    reply(false, "The selected item is not a regular file.")
                    return
                }
                guard (values?.fileSize ?? 0) <= 250 * 1_024 * 1_024 else {
                    reply(false, "Files larger than 250 MB require a full scan.")
                    return
                }
                paths = [standardPath]
            }

            for filePath in paths {
                let result = scanner.scan(filePath: filePath)
                if result.isThreat {
                    reply(false, "Threat detected: \(result.threatName ?? "unknown threat")")
                    return
                }
            }
            reply(true, nil)
        }
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
        scanner.cache.allowOnce(path: standardPath)
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

    init(path: String) {
        url = URL(fileURLWithPath: path)
    }

    func appendIfImportant(_ data: Data) {
        guard let event = try? JSONDecoder().decode(ESEvent.self, from: data),
              event.decision == .deny || event.threatName != nil else { return }
        queue.async {
            var events = self.load()
            guard !events.contains(where: { $0.id == event.id }) else { return }
            events.append(event)
            if events.count > self.maximumCount {
                events.removeFirst(events.count - self.maximumCount)
            }
            do {
                try FileManager.default.createDirectory(
                    at: self.url.deletingLastPathComponent(),
                    withIntermediateDirectories: true,
                    attributes: [.posixPermissions: 0o755]
                )
                let encoded = try JSONEncoder().encode(events)
                try encoded.write(to: self.url, options: .atomic)
                try FileManager.default.setAttributes(
                    [.posixPermissions: 0o644],
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

    private func load() -> [ESEvent] {
        guard let data = try? Data(contentsOf: url) else { return [] }
        return (try? JSONDecoder().decode([ESEvent].self, from: data)) ?? []
    }
}
