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

    // MARK: - Configuration

    /// Maximum number of events kept in `events`. Older events are discarded.
    public var maxEventCount = 2_000

    // MARK: - Private

    private nonisolated(unsafe) static let logger = Logger(
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
        isConnected = true
        Self.logger.info("XPC connection to NickExtension opened")
    }

    /// Closes the XPC connection.
    public func disconnect() {
        connection?.invalidate()
        connection  = nil
        isConnected = false
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
        }
    }
}
