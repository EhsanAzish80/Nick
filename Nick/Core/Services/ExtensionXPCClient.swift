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

    /// Last time the extension answered an explicit status request. This is
    /// runtime evidence, not an installation preference or cached UI flag.
    public private(set) var lastStatusResponseAt: Date?

    /// Last live Endpoint Security event received from the extension.
    public private(set) var lastEventReceivedAt: Date?

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

    // MARK: - Private

    private nonisolated static let logger = Logger(
        subsystem: "com.ehsanazish.nick",
        category: "ExtensionXPCClient"
    )

    private var connection: NSXPCConnection?
    private let decoder = JSONDecoder()

    // MARK: - Public API

    /// Opens the XPC connection to the System Extension.
    ///
    /// Safe to call multiple times — an existing connection is reused.
    public func connect() {
        guard connection == nil else { return }

        let conn = NSXPCConnection(machServiceName: NickExtensionConstants.machServiceName)

        // The extension exposes NickExtensionXPCProtocol (we call into it).
        conn.remoteObjectInterface = NSXPCInterface(with: NickExtensionXPCProtocol.self)

        // The container app exposes NickAppXPCProtocol (extension calls us).
        conn.exportedInterface = NSXPCInterface(with: NickAppXPCProtocol.self)
        conn.exportedObject    = self

        conn.invalidationHandler = { [weak self] in
            Task { @MainActor [weak self] in
                Self.logger.warning("XPC connection to extension invalidated")
                self?.isConnected = false
                self?.connection  = nil
            }
        }
        conn.interruptionHandler = { [weak self] in
            Task { @MainActor [weak self] in
                Self.logger.warning("XPC connection to extension interrupted — extension may have crashed")
                self?.isConnected = false
            }
        }

        conn.resume()
        connection = conn
        isConnected = false
        Self.logger.info("XPC connection to NickExtension opened; verifying ES client status")

        // Opening an NSXPCConnection does not prove the service exists or that
        // its Endpoint Security client started successfully. Only promote the
        // connection after the extension answers its status request.
        let errorHandler: @Sendable (Error) -> Void = { error in
            Self.logger.warning("Extension status verification failed: \(error.localizedDescription)")
        }
        guard let proxy = conn.remoteObjectProxyWithErrorHandler(errorHandler)
            as? NickExtensionXPCProtocol else {
            return
        }
        let statusReply: @Sendable (Bool) -> Void = { [weak self] active in
            Task { @MainActor [weak self] in
                self?.isConnected = active
                self?.lastStatusResponseAt = .now
                Self.logger.info("Verified extension status: isActive=\(active)")
                if active {
                    self?.loadPersistedEvents()
                }
            }
        }
        proxy.getStatus(reply: statusReply)
    }

    /// Closes the XPC connection.
    public func disconnect() {
        connection?.invalidate()
        connection  = nil
        isConnected = false
    }

    private func loadPersistedEvents() {
        guard let proxy = connection?.remoteObjectProxy as? NickExtensionXPCProtocol else { return }
        proxy.getPersistedEvents { [weak self] data in
            guard let replay = try? JSONDecoder().decode([ESEvent].self, from: data) else {
                return
            }
            Task { @MainActor [weak self] in
                guard let self else { return }
                let existingIDs = Set(events.map(\.id))
                events.append(contentsOf: replay.filter { !existingIDs.contains($0.id) })
                events.sort { $0.timestamp > $1.timestamp }
                if events.count > maxEventCount {
                    events.removeLast(events.count - maxEventCount)
                }
            }
        }
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

    /// Requests an on-demand scan of a file (Phase 2+).
    public func requestScan(path: String, completion: @escaping (Bool, String?) -> Void) {
        guard let proxy = connection?.remoteObjectProxy as? NickExtensionXPCProtocol else {
            completion(false, "Not connected to extension")
            return
        }
        proxy.requestScan(path: path, reply: completion)
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

// MARK: - NickAppXPCProtocol (Inbound from Extension)

extension ExtensionXPCClient: NickAppXPCProtocol {

    public nonisolated func reportEvent(_ eventData: Data) {
        guard let event = try? JSONDecoder().decode(ESEvent.self, from: eventData) else {
            Self.logger.error("Failed to decode ESEvent from extension")
            return
        }
        Task { @MainActor [weak self] in
            guard let self else { return }
            events.insert(event, at: 0)
            lastEventReceivedAt = .now
            if events.count > maxEventCount {
                events.removeLast(events.count - maxEventCount)
            }
        }
    }

    public nonisolated func reportThreat(_ threatData: Data) {
        Self.logger.notice("Received threat report from extension (\(threatData.count) bytes)")
    }

    public nonisolated func reportRemediationAction(_ reportData: Data) {
        guard let report = try? JSONDecoder().decode(RemediationReport.self, from: reportData) else {
            Self.logger.error("Failed to decode RemediationReport")
            return
        }
        Task { @MainActor [weak self] in
            guard let self else { return }
            if let record = report.quarantineRecord {
                // Prepend; remove duplicates by id
                quarantineRecords.removeAll { $0.id == record.id }
                quarantineRecords.insert(record, at: 0)
            }
        }
    }

    public nonisolated func reportIntegrityViolation(_ violationData: Data) {
        guard let violation = try? JSONDecoder().decode(IntegrityViolation.self, from: violationData) else {
            Self.logger.error("Failed to decode IntegrityViolation")
            return
        }
        Task { @MainActor [weak self] in
            guard let self else { return }
            integrityViolations.insert(violation, at: 0)
            if integrityViolations.count > maxEventCount {
                integrityViolations.removeLast(integrityViolations.count - maxEventCount)
            }
        }
    }

    public nonisolated func reportStatusChange(_ isActive: Bool) {
        Task { @MainActor [weak self] in
            Self.logger.info("Extension status changed: isActive=\(isActive)")
            self?.isConnected = isActive
            self?.lastStatusResponseAt = .now
        }
    }

    public nonisolated func reportPrivacyAlert(_ alertData: Data) {
        guard let alert = try? JSONDecoder().decode(PrivacyAlert.self, from: alertData) else {
            Self.logger.error("Failed to decode PrivacyAlert")
            return
        }
        Task { @MainActor [weak self] in
            guard let self else { return }
            privacyAlerts.insert(alert, at: 0)
            if privacyAlerts.count > maxEventCount {
                privacyAlerts.removeLast(privacyAlerts.count - maxEventCount)
            }
        }
    }

    public nonisolated func reportUSBThreat(_ threatData: Data) {
        guard let threat = try? JSONDecoder().decode(USBThreat.self, from: threatData) else {
            Self.logger.error("Failed to decode USBThreat")
            return
        }
        Task { @MainActor [weak self] in
            guard let self else { return }
            usbThreats.insert(threat, at: 0)
            if usbThreats.count > maxEventCount {
                usbThreats.removeLast(usbThreats.count - maxEventCount)
            }
        }
    }
}
