// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation
import Darwin
import os
import Security

enum PersistedThreatIngestOutcome: Equatable {
    case persisted(UInt64)
    case coalesced(UInt64)
    case suppressedByPolicy(String)
    case failed

    var mayAcknowledge: Bool {
        switch self {
        case .persisted, .coalesced, .suppressedByPolicy: true
        case .failed: false
        }
    }
}

#if DEBUG
public enum DebugAuthorizationHarnessResult: Equatable, Sendable {
    case refused
    case unexpectedlyAccepted
    case unavailable(String)

    var statusText: String {
        switch self {
        case .refused:
            "Passed: the unapproved form was refused"
        case .unexpectedlyAccepted:
            "FAILED: the unapproved form was accepted"
        case .unavailable(let reason):
            "UNAVAILABLE: \(reason)"
        }
    }

    var passed: Bool { self == .refused }
}
#endif

private final class UpdateLeaseReplyBox: @unchecked Sendable {
    private let lock = NSLock()
    private var stored = false

    func set(_ value: Bool) { lock.withLock { stored = value } }
    func value() -> Bool { lock.withLock { stored } }
}

private final class AcceptedObservationIDs: @unchecked Sendable {
    private let lock = NSLock()
    private var ids = Set<UUID>()

    func insert(_ id: UUID) { lock.withLock { _ = ids.insert(id) } }
    func contains(_ id: UUID) -> Bool { lock.withLock { ids.contains(id) } }
}

/// Bridges an XPC reply or error back to async code exactly once without
/// inheriting MainActor isolation into the XPC callback queue.
final class OneShotDataReply: @unchecked Sendable {
    private let lock = NSLock()
    private var completion: (@Sendable (Data) -> Void)?

    init(completion: @escaping @Sendable (Data) -> Void) {
        self.completion = completion
    }

    @discardableResult
    func resolve(_ data: Data) -> Bool {
        let callback = lock.withLock {
            let callback = completion
            completion = nil
            return callback
        }
        callback?(data)
        return callback != nil
    }
}

/// Thread-safe, exactly-once bridge for Objective-C XPC callbacks. XPC may
/// invoke a reply, an error handler, and an invalidation handler in any order
/// and on non-main queues.
final class OneShotReply<Value: Sendable>: @unchecked Sendable {
    private let lock = NSLock()
    private var completion: (@Sendable (Value) -> Void)?

    init(completion: @escaping @Sendable (Value) -> Void) {
        self.completion = completion
    }

    @discardableResult
    func resolve(_ value: Value) -> Bool {
        let callback = lock.withLock {
            let callback = completion
            completion = nil
            return callback
        }
        callback?(value)
        return callback != nil
    }
}

final class MainActorOneShot<Value: Sendable>: @unchecked Sendable {
    private let lock = NSLock()
    private var completion: (@MainActor (Value) -> Void)?

    init(completion: @escaping @MainActor (Value) -> Void) {
        self.completion = completion
    }

    @discardableResult
    nonisolated func resolve(_ value: Value) -> Bool {
        let callback = lock.withLock {
            let callback = completion
            completion = nil
            return callback
        }
        guard let callback else { return false }
        Task { @MainActor in callback(value) }
        return true
    }
}

enum IncidentVerdictAuthorizationFlow {
    @MainActor
    static func complete(
        preflight: IncidentVerdictValidationResult,
        requiresAuthorization: Bool,
        requestAuthorization: () -> Data?,
        submitAuthorized: (Data) async -> IncidentVerdictValidationResult
    ) async -> IncidentActionAuthorizationResult {
        switch preflight {
        case .accepted:
            return .approved(IncidentActionApproval(authorizationExternalForm: nil))
        case .targetMissing:
            return .targetMissing
        case .invalidRequest:
            return .rejected
        case .authorizationRequired:
            guard requiresAuthorization else { return .rejected }
        }

        guard let authorization = requestAuthorization() else {
            return .approvalCancelled
        }
        switch await submitAuthorized(authorization) {
        case .accepted:
            return .approved(IncidentActionApproval(authorizationExternalForm: authorization))
        case .targetMissing:
            return .targetMissing
        case .authorizationRequired, .invalidRequest:
            return .rejected
        }
    }
}

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

    public private(set) var suppressedByDismissalCount = 0
    public private(set) var ackWithoutPersistenceCount = 0
    public private(set) var failedThreatEventIDs: Set<UUID> = []

    // MARK: - Configuration

    /// Maximum number of events kept in `events`. Older events are discarded.
    public var maxEventCount = 2_000

    /// Installed by AppDelegate so privileged findings enter SecurityEngine's
    /// single incident pipeline. Kept as a closure to avoid a Core service
    /// owning UI/application lifetime state.
    var findingHandler: ((ExtensionFinding) async -> IncidentIngestOutcome)?
    var incidentPersistenceConfirmationHandler: ((UInt64) -> Void)?
    var integrityAcknowledgementHandler: ((UUID) -> Void)?
    /// App-owned readiness boundary for the authoritative incident store.
    /// Findings remain in the extension journal and in `deferredThreatEvents`
    /// until this returns true.
    var incidentStoreReadyProvider: (() -> Bool)?

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
    private var pendingIncidentGeneration: UInt64?
    private var pendingIncidentAuthorization: Data?
    private var incidentWriteInFlight = false
    private var incidentWriteGeneration: UInt64 = 0
    private var incidentWriteResults: [UInt64: Bool] = [:]
    private var incidentWriteWaiters: [(UInt64, CheckedContinuation<Bool, Never>)] = []
    private var deferredThreatEvents: [UUID: ESEvent] = [:]
    private var threatEventIDsInFlight: Set<UUID> = []
    private var durablyHandledThreatEventIDs: Set<UUID> = []
    private var durablyHandledThreatEventOrder: [UUID] = []
    private var pendingIntegrityAcknowledgementIDs: Set<UUID> = []
    private let durableThreatDeduplicationLimit = 4_096
    var pendingIncidentWriteWaiterCount: Int { incidentWriteWaiters.count }
    private var activeProtectionAuthorizations: [Data: AuthorizationRef] = [:]
    private var incidentBootstrapCompleted = false
    private var bootstrapLegacyPayload: Data?
    private var bootstrapCompletion: (@MainActor @Sendable (PrivilegedIncidentStoreRecord?, Bool) -> Void)?
    private var reconnectTask: Task<Void, Never>?
    private var reconnectAttempt = 0
    private var healthRefreshTask: Task<Void, Never>?
    private var lastHealthyExtensionTime: Date?
    private var lastProtectionGapObservationAt: Date?
    private var attemptedThreatBundleRefresh = false
    /// Deterministic persistence completion seam used by unit tests. Production
    /// always uses the privileged XPC write/reply path.
    var incidentPersistenceOverride: ((UInt64) async -> (UInt64, Bool)?)?
    var threatAcknowledgementOverride: ((UUID) -> Void)?

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
            reconnectAttempt = 0
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
        reconnectAttempt = 0
        openConnection()
    }

    private func openConnection() {
        guard connection == nil else { return }

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
                self.failIncidentWriteWaitersOnConnectionLoss()
                self.recordAppObservedProtectionGap(reason: "Endpoint Security connection invalidated")
                self.scheduleReconnect()
            }
        }
        conn.interruptionHandler = { [weak self] in
            Task { @MainActor [weak self] in
                guard let self else { return }
                Self.logger.warning("XPC connection to extension interrupted — extension may have crashed")
                self.isConnected = false
                self.recordAppObservedProtectionGap(reason: "Endpoint Security connection interrupted")
                self.scheduleReconnect()
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
                self?.scheduleReconnect()
            }
        }
        guard let proxy = conn.remoteObjectProxyWithErrorHandler(errorHandler)
            as? NickExtensionXPCProtocol else {
            scheduleReconnect()
            return
        }
        let statusCompletion = OneShotReply<Bool> { [weak self] active in
            Task { @MainActor [weak self] in
                self?.isConnected = active
                Self.logger.info("Verified extension status: isActive=\(active)")
                if active {
                    self?.reconnectAttempt = 0
                    self?.reconnectTask?.cancel()
                    self?.reconnectTask = nil
                    self?.drainAppObservedProtectionGaps()
                    self?.startHealthRefresh()
                    self?.loadPersistedEvents()
                    self?.loadPendingFIMViolations()
                    self?.refreshThreatIntelligenceBundleIfEnabled()
                    if self?.incidentBootstrapCompleted == true {
                        self?.drainIncidentStoreWrites()
                        self?.flushSecuritySettingsIfNeeded()
                    } else {
                        self?.bootstrapIncidentStore(
                            legacyPayload: self?.bootstrapLegacyPayload,
                            completion: self?.bootstrapCompletion
                        )
                    }
                } else {
                    self?.scheduleReconnect()
                }
            }
        }
        let statusReply: @Sendable (Bool) -> Void = { statusCompletion.resolve($0) }
        proxy.getStatus(reply: statusReply)
        DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + 2) {
            statusCompletion.resolve(false)
        }
    }

    /// The only way this client obtains a remote proxy. Error callbacks never
    /// inherit MainActor isolation from the caller.
    private func extensionProxy(
        onError: (@Sendable (Error) -> Void)? = nil
    ) -> NickExtensionXPCProtocol? {
        guard let connection else { return nil }
        let handler: @Sendable (Error) -> Void = { [weak self] error in
            onError?(error)
            Task { @MainActor [weak self] in
                self?.failIncidentWriteWaitersOnConnectionLoss()
                self?.scheduleReconnect()
            }
        }
        return connection.remoteObjectProxyWithErrorHandler(handler) as? NickExtensionXPCProtocol
    }

    private func failIncidentWriteWaitersOnConnectionLoss() {
        incidentWriteInFlight = false
        let waiters = incidentWriteWaiters
        incidentWriteWaiters.removeAll()
        for (_, continuation) in waiters {
            continuation.resume(returning: false)
        }
    }

    private func refreshThreatIntelligenceBundleIfEnabled() {
        guard !attemptedThreatBundleRefresh,
              ThreatIntelligenceBundleTrustAnchor.updatesEnabled,
              let rawURL = Bundle.main.object(forInfoDictionaryKey: "NickThreatBundleURL") as? String,
              let url = URL(string: rawURL),
              ThreatBundleUpdateEndpointPolicy.allows(url) else { return }
        attemptedThreatBundleRefresh = true
        Task { [weak self] in
            do {
                var request = URLRequest(url: url)
                request.cachePolicy = .reloadRevalidatingCacheData
                request.timeoutInterval = 30
                let (data, response) = try await URLSession.shared.data(for: request)
                guard let http = response as? HTTPURLResponse,
                      http.statusCode == 200,
                      data.count <= ThreatBundleUpdateEndpointPolicy.maximumDownloadBytes,
                      let proxy = self?.extensionProxy()
                else { return }
                let accepted: Bool = await withCheckedContinuation { continuation in
                    let reply = OneShotReply<Bool> { continuation.resume(returning: $0) }
                    let xpcReply: @Sendable (Bool) -> Void = { reply.resolve($0) }
                    proxy.installThreatIntelligenceBundle(data, reply: xpcReply)
                    DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + 5) {
                        reply.resolve(false)
                    }
                }
                if !accepted {
                    Self.logger.error("The endpoint extension rejected the downloaded intelligence bundle")
                }
            } catch {
                Self.logger.warning("Threat-intelligence refresh failed: \(error.localizedDescription)")
            }
        }
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
        guard let connection else {
            extensionHealth = nil
            recordAppObservedProtectionGap(reason: "Endpoint Security heartbeat unavailable")
            return
        }
        let data: Data = await withCheckedContinuation { continuation in
            let reply = OneShotDataReply { data in
                continuation.resume(returning: data)
            }
            let errorHandler: @Sendable (Error) -> Void = { error in
                Self.logger.warning("Extension health request failed: \(error.localizedDescription)")
                reply.resolve(Data())
            }
            guard let proxy = connection.remoteObjectProxyWithErrorHandler(errorHandler)
                as? NickExtensionXPCProtocol else {
                reply.resolve(Data())
                return
            }
            let xpcReply: @Sendable (Data) -> Void = { data in
                reply.resolve(data)
            }
            proxy.getExtensionHealth(reply: xpcReply)
            DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + 2) {
                reply.resolve(Data())
            }
        }
        extensionHealth = data.isEmpty
            ? nil
            : (try? JSONSerialization.jsonObject(with: data) as? [String: Any])
        let updatedAt = extensionHealth?["updatedAt"] as? TimeInterval
        let healthy = extensionHealth?["active"] as? Bool == true
            && updatedAt.map { Date().timeIntervalSince1970 - $0 <= 30 } == true
        if healthy {
            lastHealthyExtensionTime = updatedAt.map { Date(timeIntervalSince1970: $0) } ?? Date()
        } else {
            recordAppObservedProtectionGap(reason: "Endpoint Security heartbeat is stale or missing")
        }
    }

    /// Opens one narrow Storage-operation window. Callers are the explicit
    /// Storage UI button actions only; background scans never receive one.
    func beginStorageOperation(
        kind: StorageOperationKind,
        scopedPaths: [String]
    ) async -> UUID? {
        guard let proxy = extensionProxy(),
              let pidVersion = Self.currentPIDVersion(), pidVersion > 0 else { return nil }
        let operationID = UUID()
        let request = StorageOperationRequest(
            operationID: operationID,
            kind: kind,
            actorPID: getpid(),
            actorPIDVersion: pidVersion,
            scopedPaths: Array(Set(scopedPaths)).sorted(),
            expiresAt: Date().addingTimeInterval(600)
        )
        guard let payload = try? JSONEncoder().encode(request) else { return nil }
        let accepted: Bool = await withCheckedContinuation { continuation in
            let reply = OneShotReply<Bool> { continuation.resume(returning: $0) }
            let callback: @Sendable (Bool) -> Void = { reply.resolve($0) }
            proxy.registerStorageOperation(payload, reply: callback)
            DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + 3) {
                reply.resolve(false)
            }
        }
        return accepted ? operationID : nil
    }

    func finishStorageOperation(operationID: UUID, itemCount: Int, bytesMoved: Int64) async {
        guard let proxy = extensionProxy() else { return }
        await withCheckedContinuation { continuation in
            let reply = OneShotReply<Bool> { _ in continuation.resume() }
            let callback: @Sendable (Bool) -> Void = { reply.resolve($0) }
            proxy.completeStorageOperation(
                operationID: operationID.uuidString,
                itemCount: itemCount,
                bytesMoved: bytesMoved,
                reply: callback
            )
            DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + 3) {
                reply.resolve(false)
            }
        }
    }

    private nonisolated static func currentPIDVersion() -> Int32? {
        var token = audit_token_t()
        var count = mach_msg_type_number_t(
            MemoryLayout<audit_token_t>.size / MemoryLayout<natural_t>.size
        )
        let result = withUnsafeMutablePointer(to: &token) { pointer in
            pointer.withMemoryRebound(to: natural_t.self, capacity: Int(count)) { rebound in
                task_info(mach_task_self_, task_flavor_t(TASK_AUDIT_TOKEN), rebound, &count)
            }
        }
        guard result == KERN_SUCCESS else { return nil }
        // audit_token_t is eight 32-bit words. Darwin exposes
        // audit_token_to_pidversion as a C macro on this target, so calling it
        // from Swift would incorrectly emit an unresolved external symbol.
        // pidversion is the final word in the kernel-provided token.
        return withUnsafeBytes(of: token) { rawBuffer in
            guard rawBuffer.count >= MemoryLayout<UInt32>.size * 8 else { return nil }
            return Int32(bitPattern: rawBuffer.load(
                fromByteOffset: MemoryLayout<UInt32>.size * 7,
                as: UInt32.self
            ))
        }
    }

    private var protectionObservationJournalURL: URL {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        return base.appendingPathComponent("com.ehsanazish.nick/protection-observations.json")
    }

    private func recordAppObservedProtectionGap(reason: String) {
        let now = Date()
        if let lastProtectionGapObservationAt,
           now.timeIntervalSince(lastProtectionGapObservationAt) < 300 { return }
        lastProtectionGapObservationAt = now
        var observations = loadAppObservedProtectionGaps()
        observations.append(.init(
            id: UUID(), observedAt: now, lastHealthyAt: lastHealthyExtensionTime,
            reason: String(reason.prefix(160))
        ))
        observations = Array(observations.suffix(32))
        do {
            let url = protectionObservationJournalURL
            try FileManager.default.createDirectory(
                at: url.deletingLastPathComponent(), withIntermediateDirectories: true
            )
            try JSONEncoder().encode(observations).write(to: url, options: .atomic)
        } catch {
            Self.logger.error("Could not write protection observation journal: \(error.localizedDescription)")
        }
        Task { await NotificationManager.shared.sendProtectionUnavailable() }
    }

    private func loadAppObservedProtectionGaps() -> [AppObservedProtectionGap] {
        guard let data = try? Data(contentsOf: protectionObservationJournalURL) else { return [] }
        return (try? JSONDecoder().decode([AppObservedProtectionGap].self, from: data)) ?? []
    }

    private func drainAppObservedProtectionGaps() {
        guard let proxy = extensionProxy() else { return }
        let observations = loadAppObservedProtectionGaps()
        guard !observations.isEmpty else { return }
        let url = protectionObservationJournalURL
        let group = DispatchGroup()
        let accepted = AcceptedObservationIDs()
        for observation in observations {
            guard let payload = try? JSONEncoder().encode(observation) else { continue }
            group.enter()
            let reply = OneShotReply<Bool> { success in
                if success { accepted.insert(observation.id) }
                group.leave()
            }
            let xpcReply: @Sendable (Bool) -> Void = { success in reply.resolve(success) }
            proxy.ingestAppObservedProtectionGap(payload, reply: xpcReply)
            DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + 2) {
                reply.resolve(false)
            }
        }
        group.notify(queue: .main) {
            let remaining = observations.filter { !accepted.contains($0.id) }
            if remaining.isEmpty {
                try? FileManager.default.removeItem(at: url)
            } else if let data = try? JSONEncoder().encode(remaining) {
                try? data.write(to: url, options: .atomic)
            }
        }
    }

    private func loadPendingFIMViolations() {
        guard let proxy = extensionProxy() else { return }
        let completion = MainActorOneShot<Data> { [weak self] data in
            guard !data.isEmpty,
                  let violations = try? JSONDecoder().decode([IntegrityViolation].self, from: data)
            else { return }
            self?.integrityViolations = violations.sorted { $0.timestamp > $1.timestamp }
        }
        let reply: @Sendable (Data) -> Void = { completion.resolve($0) }
        proxy.getPendingFIMViolations(reply: reply)
        DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + 2) {
            completion.resolve(Data())
        }
    }

    public func bootstrapSecuritySettings(legacyPayload: Data) async -> Data? {
        guard let proxy = extensionProxy() else { return nil }
        let response: (Bool, Data) = await withCheckedContinuation { continuation in
            let reply = OneShotReply<(Bool, Data)> { continuation.resume(returning: $0) }
            let xpcReply: @Sendable (Bool, Data) -> Void = { reply.resolve(($0, $1)) }
            proxy.migrateSecuritySettings(legacyPayload, reply: xpcReply)
            DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + 2) {
                reply.resolve((false, Data()))
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
              let proxy = extensionProxy() else { return }
        pendingSecuritySettingsPayload = nil
        let authorization = pendingSecuritySettingsAuthorization
        pendingSecuritySettingsAuthorization = nil
        securitySettingsWriteInFlight = true
        let completion = OneShotReply<(Bool, Data)> { [weak self] result in
            let (accepted, data) = result
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
        let xpcReply: @Sendable (Bool, Data) -> Void = { completion.resolve(($0, $1)) }
        proxy.replaceSecuritySettings(
            payload,
            expectedRevision: revision,
            authorizationExternalForm: authorization,
            reply: xpcReply
        )
        DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + 5) {
            completion.resolve((false, Data()))
        }
    }

    private func scheduleReconnect() {
        guard reconnectTask == nil else { return }
        guard incidentBootstrapCompleted || reconnectAttempt < 12 else {
            Self.logger.error("Incident-store bootstrap failed after repeated XPC reconnects")
            finishIncidentBootstrap(record: nil, migrated: false)
            return
        }

        reconnectAttempt += 1
        let delayNanoseconds = UInt64(min(reconnectAttempt, 4)) * 500_000_000
        isConnected = false
        healthRefreshTask?.cancel()
        healthRefreshTask = nil
        connection?.invalidationHandler = nil
        connection?.interruptionHandler = nil
        connection?.invalidate()
        connection = nil

        reconnectTask = Task { @MainActor [weak self] in
            try? await Task.sleep(nanoseconds: delayNanoseconds)
            guard let self, !Task.isCancelled else { return }
            self.reconnectTask = nil
            Self.logger.notice(
                "Retrying XPC connection after extension replacement (attempt \(self.reconnectAttempt))"
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
        reconnectTask?.cancel()
        reconnectTask = nil
        let completion = bootstrapCompletion
        bootstrapCompletion = nil
        bootstrapLegacyPayload = nil
        completion?(record, migrated)
    }

    private func bootstrapIncidentStore(
        legacyPayload: Data?,
        completion: (@MainActor @Sendable (PrivilegedIncidentStoreRecord?, Bool) -> Void)?
    ) {
        guard let proxy = extensionProxy() else {
            scheduleReconnect()
            return
        }
        let completion = MainActorOneShot<Data> { [weak self] data in
            guard let self else { return }
            if let record = try? JSONDecoder().decode(PrivilegedIncidentStoreRecord.self, from: data) {
                self.incidentRevision = record.revision
                self.finishIncidentBootstrap(record: record, migrated: false)
            } else if let legacyPayload {
                self.migrateLegacyIncidentStore(legacyPayload)
            } else {
                self.finishIncidentBootstrap(record: nil, migrated: false)
            }
        }
        let reply: @Sendable (Data) -> Void = { completion.resolve($0) }
        proxy.getIncidentStore(reply: reply)
        DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + 5) {
            completion.resolve(Data())
        }
    }

    private func migrateLegacyIncidentStore(_ payload: Data) {
        guard let proxy = extensionProxy() else {
            scheduleReconnect()
            return
        }
        let completion = MainActorOneShot<(Bool, Data)> { [weak self] result in
            guard let self else { return }
            let record = try? JSONDecoder().decode(
                PrivilegedIncidentStoreRecord.self,
                from: result.1
            )
            self.incidentRevision = record?.revision
            self.finishIncidentBootstrap(record: record, migrated: result.0 && record != nil)
        }
        let reply: @Sendable (Bool, Data) -> Void = { completion.resolve(($0, $1)) }
        proxy.migrateIncidentStore(payload, reply: reply)
        DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + 5) {
            completion.resolve((false, Data()))
        }
    }

    func persistIncidentStore(
        _ payload: Data,
        generation: UInt64,
        authorizationExternalForm: Data? = nil
    ) {
        incidentWriteGeneration = max(incidentWriteGeneration, generation)
        pendingIncidentPayload = payload
        pendingIncidentGeneration = generation
        if let authorizationExternalForm {
            finishProtectionAuthorization(pendingIncidentAuthorization)
            pendingIncidentAuthorization = authorizationExternalForm
        }
        drainIncidentStoreWrites()
    }

    private func drainIncidentStoreWrites() {
        guard !incidentWriteInFlight,
              let payload = pendingIncidentPayload,
              let generation = pendingIncidentGeneration,
              let revision = incidentRevision,
              let proxy = extensionProxy() else { return }
        pendingIncidentPayload = nil
        pendingIncidentGeneration = nil
        let authorization = pendingIncidentAuthorization
        pendingIncidentAuthorization = nil
        incidentWriteInFlight = true
        let completion = OneShotReply<(Bool, Data)> { [weak self] result in
            let (accepted, recordData) = result
            Task { @MainActor [weak self] in
                guard let self else { return }
                self.finishProtectionAuthorization(authorization)
                self.incidentWriteInFlight = false
                let record = try? JSONDecoder().decode(
                    PrivilegedIncidentStoreRecord.self,
                    from: recordData
                )
                if let record { self.incidentRevision = record.revision }
                if !accepted, authorization == nil {
                    self.pendingIncidentPayload = self.pendingIncidentPayload ?? payload
                    self.pendingIncidentGeneration = self.pendingIncidentGeneration ?? generation
                } else if !accepted {
                    Self.logger.error("Authorized incident-store write was rejected; authoritative state retained")
                }
                self.completeIncidentWrite(through: generation, succeeded: accepted && record != nil)
                if accepted && record != nil {
                    self.incidentPersistenceConfirmationHandler?(generation)
                }
                self.drainIncidentStoreWrites()
            }
        }
        let xpcReply: @Sendable (Bool, Data) -> Void = { completion.resolve(($0, $1)) }
        proxy.replaceIncidentStore(
            payload,
            expectedRevision: revision,
            authorizationExternalForm: authorization,
            reply: xpcReply
        )
        DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + 5) {
            completion.resolve((false, Data()))
        }
    }

    /// Waits until a root-owned whole-store snapshot covers the generation
    /// queued by the caller. A later successful generation covers all earlier
    /// still-pending generations; a failed reply fails every waiter it covers
    /// so those journal events remain eligible for redelivery.
    func awaitIncidentStorePersistence(generation: UInt64) async -> (UInt64, Bool)? {
        guard generation > 0, generation <= incidentWriteGeneration else {
            ackWithoutPersistenceCount += 1
            return nil
        }
        if let result = incidentWriteResults[generation] { return (generation, result) }
        guard connection != nil, incidentRevision != nil else { return nil }
        let result = await withCheckedContinuation { continuation in
            incidentWriteWaiters.append((generation, continuation))
        }
        return (generation, result)
    }

    private func completeIncidentWrite(through generation: UInt64, succeeded: Bool) {
        let coveredGenerations = Set(
            incidentWriteWaiters.lazy.map(\.0).filter { $0 <= generation }
        ).union([generation])
        for covered in coveredGenerations where incidentWriteResults[covered] == nil {
            incidentWriteResults[covered] = succeeded
        }
        if incidentWriteResults.count > 32 {
            let floor = incidentWriteGeneration > 32 ? incidentWriteGeneration - 32 : 0
            incidentWriteResults = incidentWriteResults.filter { $0.key >= floor }
        }
        let ready = incidentWriteWaiters.filter { $0.0 <= generation }
        incidentWriteWaiters.removeAll { $0.0 <= generation }
        for (_, continuation) in ready {
            continuation.resume(returning: succeeded)
        }
    }

#if DEBUG
    /// Test seam for exercising latest-wins write completion without XPC.
    func completeIncidentWriteForTesting(through generation: UInt64, succeeded: Bool) {
        completeIncidentWrite(through: generation, succeeded: succeeded)
    }

    func registerIncidentWriteGenerationForTesting(_ generation: UInt64) {
        incidentWriteGeneration = max(incidentWriteGeneration, generation)
    }

    func awaitIncidentStorePersistenceForTesting(generation: UInt64) async -> (UInt64, Bool) {
        let result = await withCheckedContinuation { continuation in
            incidentWriteWaiters.append((generation, continuation))
        }
        return (generation, result)
    }
#endif

    func validateIncidentVerdictTarget(
        id: UUID,
        action: IncidentActionKind
    ) async -> IncidentActionAuthorizationResult {
        guard isConnected,
              let proxy = extensionProxy() else {
            return .protectionDisconnected
        }
        await refreshExtensionHealth()
        guard isConnected else { return .protectionDisconnected }
        let appBuild = Bundle.main.object(forInfoDictionaryKey: kCFBundleVersionKey as String) as? String
        let extensionBuild = extensionHealth?["version"] as? String
        if let appBuild, let extensionBuild, appBuild != extensionBuild {
            return .versionMismatch(appBuild: appBuild, extensionBuild: extensionBuild)
        }

        let requiresAuthorization: Bool = [.dismissed, .allowedOnce, .alwaysAllowed].contains(action)
        let preflight = await withCheckedContinuation { continuation in
            let reply = OneShotReply<String> { continuation.resume(returning: $0) }
            let xpcReply: @Sendable (String) -> Void = { reply.resolve($0) }
            proxy.validateIncidentVerdictTarget(
                alertID: id.uuidString,
                action: action.rawValue,
                authorizationExternalForm: nil,
                reply: xpcReply
            )
            DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + 5) {
                reply.resolve(IncidentVerdictValidationResult.invalidRequest.rawValue)
            }
        }
        guard let preflightResult = IncidentVerdictValidationResult(rawValue: preflight) else {
            return .rejected
        }
        var requestedAuthorization: Data?
        let result = await IncidentVerdictAuthorizationFlow.complete(
            preflight: preflightResult,
            requiresAuthorization: requiresAuthorization,
            requestAuthorization: {
                requestedAuthorization = requestProtectionModificationAuthorization()
                return requestedAuthorization
            },
            submitAuthorized: { authorization in
                let raw = await withCheckedContinuation { continuation in
                    let reply = OneShotReply<String> { continuation.resume(returning: $0) }
                    let xpcReply: @Sendable (String) -> Void = { reply.resolve($0) }
                    proxy.validateIncidentVerdictTarget(
                        alertID: id.uuidString,
                        action: action.rawValue,
                        authorizationExternalForm: authorization,
                        reply: xpcReply
                    )
                    DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + 5) {
                        reply.resolve(IncidentVerdictValidationResult.invalidRequest.rawValue)
                    }
                }
                return IncidentVerdictValidationResult(rawValue: raw) ?? .invalidRequest
            }
        )
        switch result {
        case .approved:
            return result
        case .approvalCancelled, .targetMissing, .protectionDisconnected, .versionMismatch, .rejected:
            // A successful result keeps the AuthorizationRef alive until the
            // root-store write replies; every failure releases this exact one.
            finishProtectionAuthorization(requestedAuthorization)
            return result
        }
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

    /// Sparkle calls its installation delegate synchronously immediately
    /// before termination. Keep the verified AuthorizationRef alive until the
    /// extension acknowledges the lease, and bound the wait so a disconnected
    /// extension fails closed instead of hanging the updater.
    func prepareUpdateLeaseSynchronously(
        sourceBuild: Int,
        destinationBuild: Int,
        timeout: TimeInterval = 15
    ) -> Bool {
        guard destinationBuild > sourceBuild,
              let proxy = connection?.remoteObjectProxyWithErrorHandler({ error in
                  Self.logger.error("Update lease XPC failed: \(error.localizedDescription, privacy: .public)")
              }) as? NickExtensionXPCProtocol,
              let authorization = requestProtectionModificationAuthorization()
        else { return false }

        let semaphore = DispatchSemaphore(value: 0)
        let reply = UpdateLeaseReplyBox()
        let once = OneShotReply<Bool> { accepted in
            reply.set(accepted)
            semaphore.signal()
        }
        let xpcReply: @Sendable (Bool) -> Void = { once.resolve($0) }
        proxy.requestUpdateLease(
            sourceBuild: sourceBuild,
            destinationBuild: destinationBuild,
            authorizationExternalForm: authorization,
            reply: xpcReply
        )
        let completed = semaphore.wait(timeout: .now() + timeout) == .success
        finishProtectionAuthorization(authorization)
        return completed && reply.value()
    }

    /// Records durable evidence and a clean-stop marker before an authorized
    /// system-extension deactivation request is submitted to macOS.
    func recordAuthorizedProtectionStopSynchronously(
        reason: String,
        timeout: TimeInterval = 15
    ) -> Bool {
        guard let proxy = connection?.remoteObjectProxyWithErrorHandler({ error in
            Self.logger.error("Protection stop XPC failed: \(error.localizedDescription, privacy: .public)")
        }) as? NickExtensionXPCProtocol,
              let authorization = requestProtectionModificationAuthorization()
        else { return false }

        let semaphore = DispatchSemaphore(value: 0)
        let reply = UpdateLeaseReplyBox()
        let once = OneShotReply<Bool> { accepted in
            reply.set(accepted)
            semaphore.signal()
        }
        let xpcReply: @Sendable (Bool) -> Void = { once.resolve($0) }
        proxy.recordAuthorizedProtectionStop(
            reason: String(reason.prefix(160)),
            authorizationExternalForm: authorization,
            reply: xpcReply
        )
        let completed = semaphore.wait(timeout: .now() + timeout) == .success
        finishProtectionAuthorization(authorization)
        return completed && reply.value()
    }

    func recordIntentionalAppExitSynchronously(
        reason: String,
        timeout: TimeInterval = 2
    ) -> Bool {
        guard let proxy = extensionProxy() else { return false }
        let semaphore = DispatchSemaphore(value: 0)
        let reply = UpdateLeaseReplyBox()
        let once = OneShotReply<Bool> { accepted in
            reply.set(accepted)
            semaphore.signal()
        }
        let xpcReply: @Sendable (Bool) -> Void = { once.resolve($0) }
        proxy.recordIntentionalAppExit(
            pid: getpid(),
            reason: String(reason.prefix(160)),
            reply: xpcReply
        )
        return semaphore.wait(timeout: .now() + timeout) == .success && reply.value()
    }

    func ingestAppObservedProtectionGap(
        _ payload: Data,
        completion: @escaping @MainActor (Bool) -> Void
    ) {
        guard let proxy = extensionProxy() else {
            completion(false)
            return
        }
        let reply = MainActorOneShot<Bool>(completion: completion)
        let xpcReply: @Sendable (Bool) -> Void = { reply.resolve($0) }
        proxy.ingestAppObservedProtectionGap(payload, reply: xpcReply)
        DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + 2) { reply.resolve(false) }
    }

    private func finishProtectionAuthorization(_ externalForm: Data?) {
        guard let externalForm,
              let authorization = activeProtectionAuthorizations.removeValue(forKey: externalForm)
        else { return }
        AuthorizationFree(authorization, [.destroyRights])
    }

    /// Closes the XPC connection.
    public func disconnect() {
        reconnectTask?.cancel()
        reconnectTask = nil
        connection?.invalidate()
        connection  = nil
        isConnected = false
        failIncidentWriteWaitersOnConnectionLoss()
        incidentBootstrapCompleted = false
        bootstrapLegacyPayload = nil
        bootstrapCompletion = nil
        reconnectAttempt = 0
        for authorization in activeProtectionAuthorizations.values {
            AuthorizationFree(authorization, [.destroyRights])
        }
        activeProtectionAuthorizations.removeAll()
    }

    private func loadPersistedEvents() {
        guard let proxy = extensionProxy() else { return }
        let completion = MainActorOneShot<Data> { [weak self] data in
            guard let replay = try? JSONDecoder().decode([PersistedExtensionFinding].self, from: data) else {
                return
            }
            Task { @MainActor [weak self] in
                guard let self else { return }
                var acknowledgedThreatIDs: [String] = []
                for finding in replay.sorted(by: { $0.timestamp < $1.timestamp }) {
                    if let eventID = await self.receivePersisted(finding) {
                        acknowledgedThreatIDs.append(eventID.uuidString)
                    }
                }
                if !acknowledgedThreatIDs.isEmpty {
                    proxy.acknowledgePersistedThreats(eventIDs: acknowledgedThreatIDs)
                }
            }
        }
        let reply: @Sendable (Data) -> Void = { completion.resolve($0) }
        proxy.getPersistedEvents(reply: reply)
        DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + 5) {
            completion.resolve(Data())
        }
    }

    func receivePersisted(_ finding: PersistedExtensionFinding) async -> UUID? {
        switch finding.kind {
        case .endpointEvent:
            guard let event = try? decoder.decode(ESEvent.self, from: finding.payload) else { return nil }
            receive(event, deliverToEngine: false)
            return nil
        case .threat:
            guard let event = try? decoder.decode(ESEvent.self, from: finding.payload) else { return nil }
            return await receiveThreat(event).mayAcknowledge ? event.id : nil
        case .remediation:
            guard let report = try? decoder.decode(RemediationReport.self, from: finding.payload) else { return nil }
            receive(report, deliverToEngine: !report.quarantineSucceeded)
            return nil
        case .integrityViolation:
            guard let violation = try? decoder.decode(IntegrityViolation.self, from: finding.payload) else { return nil }
            receive(violation, deliverToEngine: false)
            return nil
        case .privacyAlert:
            guard let alert = try? decoder.decode(PrivacyAlert.self, from: finding.payload) else { return nil }
            receive(alert, deliverToEngine: false)
            return nil
        case .usbThreat:
            guard let threat = try? decoder.decode(USBThreat.self, from: finding.payload) else { return nil }
            receive(threat, deliverToEngine: false)
            return nil
        }
    }

    private func receiveThreat(_ event: ESEvent) async -> PersistedThreatIngestOutcome {
        if !events.contains(where: { $0.id == event.id }) { events.insert(event, at: 0) }
        trim(&events)
        if durablyHandledThreatEventIDs.contains(event.id) {
            return .suppressedByPolicy("already-durably-handled")
        }
        guard incidentStoreReadyProvider?() == true else {
            deferredThreatEvents[event.id] = event
            Self.logger.info("Holding ES threat until incident store is ready id=\(event.id.uuidString, privacy: .public)")
            return .failed
        }
        guard threatEventIDsInFlight.insert(event.id).inserted else { return .failed }
        defer { threatEventIDsInFlight.remove(event.id) }
        guard let finding = ExtensionFinding(event: event), let findingHandler else { return .failed }
        let outcome = await findingHandler(finding)
        switch outcome {
        case .persisted(let requiredGeneration), .coalesced(let requiredGeneration):
            let persistence = if let incidentPersistenceOverride {
                await incidentPersistenceOverride(requiredGeneration)
            } else {
                await awaitIncidentStorePersistence(generation: requiredGeneration)
            }
            guard let (generation, succeeded) = persistence,
                  generation == requiredGeneration, succeeded else {
                failedThreatEventIDs.insert(event.id)
                return .failed
            }
            failedThreatEventIDs.remove(event.id)
            deferredThreatEvents.removeValue(forKey: event.id)
            rememberDurablyHandledThreat(event.id)
            switch outcome {
            case .persisted: return .persisted(generation)
            case .coalesced: return .coalesced(generation)
            default: return .failed
            }
        case .suppressedByPolicy(let reason):
            if reason == "dismissal" { suppressedByDismissalCount += 1 }
            failedThreatEventIDs.remove(event.id)
            deferredThreatEvents.removeValue(forKey: event.id)
            rememberDurablyHandledThreat(event.id)
            return .suppressedByPolicy(reason)
        case .failed:
            failedThreatEventIDs.insert(event.id)
            return .failed
        }
    }

    private func acknowledgeThreat(_ eventID: UUID) {
        if let threatAcknowledgementOverride {
            threatAcknowledgementOverride(eventID)
            return
        }
        guard let proxy = extensionProxy() else { return }
        proxy.acknowledgePersistedThreats(eventIDs: [eventID.uuidString])
    }

    private func rememberDurablyHandledThreat(_ eventID: UUID) {
        guard durablyHandledThreatEventIDs.insert(eventID).inserted else { return }
        durablyHandledThreatEventOrder.append(eventID)
        let overflow = durablyHandledThreatEventOrder.count - durableThreatDeduplicationLimit
        guard overflow > 0 else { return }
        for expiredID in durablyHandledThreatEventOrder.prefix(overflow) {
            durablyHandledThreatEventIDs.remove(expiredID)
        }
        durablyHandledThreatEventOrder.removeFirst(overflow)
    }

    /// Applies a successful FIM acknowledgement only after the authoritative
    /// incident store exists. Pre-bootstrap IDs are retained for the readiness
    /// transition instead of disappearing from the app-side incident state.
    func applyOrDeferIntegrityAcknowledgement(_ id: UUID) {
        guard incidentStoreReadyProvider?() == true else {
            pendingIntegrityAcknowledgementIDs.insert(id)
            return
        }
        pendingIntegrityAcknowledgementIDs.remove(id)
        integrityAcknowledgementHandler?(id)
    }

    /// Opens the ES ingest gate after the root snapshot is installed. In-memory
    /// startup findings are drained first, then the extension journal is
    /// requested so a reconnect is never required for redelivery.
    func incidentStoreDidBecomeReady() {
        guard incidentStoreReadyProvider?() == true else { return }
        let pending = deferredThreatEvents.values.sorted { $0.timestamp < $1.timestamp }
        let pendingIntegrityAcknowledgements = pendingIntegrityAcknowledgementIDs
        pendingIntegrityAcknowledgementIDs.removeAll()
        for id in pendingIntegrityAcknowledgements {
            integrityAcknowledgementHandler?(id)
        }
        Task { @MainActor [weak self] in
            guard let self else { return }
            for event in pending where !self.durablyHandledThreatEventIDs.contains(event.id) {
                if (await self.receiveThreat(event)).mayAcknowledge {
                    self.acknowledgeThreat(event.id)
                }
            }
            self.loadPersistedEvents()
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
    public func getExtensionStatus(completion: @escaping @MainActor (Bool) -> Void) {
        guard let proxy = extensionProxy() else {
            completion(false)
            return
        }
        let reply = MainActorOneShot<Bool>(completion: completion)
        let xpcReply: @Sendable (Bool) -> Void = { reply.resolve($0) }
        proxy.getStatus(reply: xpcReply)
        DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + 2) { reply.resolve(false) }
    }

    public func requestQuarantineFile(
        path: String,
        expectedThreatName: String,
        expectedSHA256: String = "",
        completion: @escaping @MainActor (Result<QuarantineRecord, QuarantineFailure>) -> Void
    ) {
        guard let proxy = extensionProxy() else {
            completion(.failure(QuarantineFailure(
                reason: .protectionDisconnected,
                errorDomain: NSCocoaErrorDomain,
                errorCode: CocoaError.Code.xpcConnectionInterrupted.rawValue
            )))
            return
        }
        let reply = MainActorOneShot<(Bool, String?, Data?)> { [weak self] result in
            let (success, message, recordData) = result
            if success,
               let recordData,
               let record = try? JSONDecoder().decode(QuarantineRecord.self, from: recordData) {
                self?.quarantineRecords.removeAll { $0.id == record.id }
                self?.quarantineRecords.insert(record, at: 0)
                completion(.success(record))
            } else if let recordData,
                      let failure = try? JSONDecoder().decode(QuarantineFailure.self, from: recordData) {
                completion(.failure(failure))
            } else {
                completion(.failure(Self.unstructuredQuarantineFailure(message: message)))
            }
        }
        let xpcReply: @Sendable (Bool, String?, Data?) -> Void = {
            reply.resolve(($0, $1, $2))
        }
        proxy.requestQuarantineFile(
            path: path,
            expectedThreatName: expectedThreatName,
            expectedSHA256: expectedSHA256,
            reply: xpcReply
        )
        DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + 5) {
            reply.resolve((false, nil, nil))
        }
    }

    nonisolated static func unstructuredQuarantineFailure(message: String?) -> QuarantineFailure {
        QuarantineFailure(
            reason: message == nil ? .protectionDisconnected : .other,
            errorDomain: NSCocoaErrorDomain,
            errorCode: CocoaError.Code.xpcConnectionReplyInvalid.rawValue,
            message: message.map { String($0.prefix(512)) }
        )
    }

    public func requestAllowFileOnce(
        path: String,
        completion: @escaping @MainActor (Bool) -> Void
    ) {
        guard let proxy = extensionProxy() else {
            completion(false)
            return
        }
        guard let authorization = requestProtectionModificationAuthorization() else {
            completion(false)
            return
        }
        let reply = MainActorOneShot<Bool> { [weak self] accepted in
            self?.finishProtectionAuthorization(authorization)
            completion(accepted)
        }
        let xpcReply: @Sendable (Bool) -> Void = { reply.resolve($0) }
        proxy.requestAllowFileOnce(
            path: path,
            authorizationExternalForm: authorization,
            reply: xpcReply
        )
        DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + 5) { reply.resolve(false) }
    }

    public func requestBlockReviewedFile(
        path: String,
        completion: @escaping @MainActor (Bool) -> Void
    ) {
        guard let proxy = extensionProxy() else {
            completion(false)
            return
        }
        let reply = MainActorOneShot<Bool>(completion: completion)
        let xpcReply: @Sendable (Bool) -> Void = { reply.resolve($0) }
        proxy.requestBlockReviewedFile(path: path, reply: xpcReply)
        DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + 5) { reply.resolve(false) }
    }

    /// Instructs the extension to rebuild the FIM baseline (Phase 5+).
    public func requestRebuildFIMBaseline(completion: @escaping @MainActor (Bool) -> Void) {
        guard let proxy = extensionProxy() else {
            completion(false)
            return
        }
        let reply = MainActorOneShot<Bool>(completion: completion)
        let xpcReply: @Sendable (Bool) -> Void = { reply.resolve($0) }
        proxy.requestRebuildFIMBaseline(reply: xpcReply)
        DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + 10) { reply.resolve(false) }
    }

    public func acknowledgeFIMViolation(
        id: UUID,
        completion: @escaping @MainActor (Bool) -> Void
    ) {
        guard let proxy = extensionProxy() else {
            completion(false)
            return
        }
        guard let authorization = requestProtectionModificationAuthorization() else {
            completion(false)
            return
        }
        let reply = MainActorOneShot<Bool> { [weak self] accepted in
            self?.finishProtectionAuthorization(authorization)
            if accepted {
                self?.integrityViolations.removeAll { $0.id == id }
                self?.applyOrDeferIntegrityAcknowledgement(id)
            }
            completion(accepted)
        }
        let xpcReply: @Sendable (Bool) -> Void = { reply.resolve($0) }
        proxy.acknowledgeFIMViolation(
            id: id.uuidString,
            authorizationExternalForm: authorization,
            reply: xpcReply
        )
        DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + 5) { reply.resolve(false) }
    }

    /// Instructs the extension to deploy ransomware canary files into common user directories.
    public func requestDeployCanaries(completion: @escaping @MainActor (Bool) -> Void) {
        guard let proxy = extensionProxy() else {
            completion(false)
            return
        }
        let reply = MainActorOneShot<Bool>(completion: completion)
        let xpcReply: @Sendable (Bool) -> Void = { reply.resolve($0) }
        proxy.requestDeployCanaries(reply: xpcReply)
        DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + 10) { reply.resolve(false) }
    }

    public func requestRestoreQuarantinedFile(
        id: UUID,
        completion: @escaping @MainActor (Bool) -> Void
    ) {
        guard let proxy = extensionProxy() else {
            completion(false)
            return
        }
        guard let authorization = requestProtectionModificationAuthorization() else {
            completion(false)
            return
        }
        let reply = MainActorOneShot<Bool> { [weak self] success in
            self?.finishProtectionAuthorization(authorization)
            if success { self?.quarantineRecords.removeAll { $0.id == id } }
            completion(success)
        }
        let xpcReply: @Sendable (Bool) -> Void = { reply.resolve($0) }
        proxy.requestRestoreQuarantinedFile(
            id: id.uuidString,
            authorizationExternalForm: authorization,
            reply: xpcReply
        )
        DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + 5) { reply.resolve(false) }
    }

#if DEBUG
    var reconnectScheduledForTesting: Bool { reconnectTask != nil }

    /// Reproduces a post-bootstrap interruption without requiring a live
    /// system extension. Reconnection must remain enabled after startup.
    func simulateEstablishedConnectionLossForTesting(previousAttempts: Int = 20) {
        incidentBootstrapCompleted = true
        reconnectAttempt = previousAttempts
        scheduleReconnect()
    }

    public func debugSendNeverAuthorizedProtectionCall(
        completion: @escaping @MainActor @Sendable (DebugAuthorizationHarnessResult) -> Void
    ) {
        guard let connection else {
            completion(.unavailable("Real-Time Protection is not connected"))
            return
        }
        let errorHandler: @Sendable (Error) -> Void = { error in
            Task { @MainActor in
                completion(.unavailable("XPC request failed: \(error.localizedDescription)"))
            }
        }
        guard let proxy = connection.remoteObjectProxyWithErrorHandler(errorHandler)
            as? NickExtensionXPCProtocol else {
            completion(.unavailable("the extension proxy is unavailable"))
            return
        }
        var authorization: AuthorizationRef?
        let createStatus = AuthorizationCreate(nil, nil, [], &authorization)
        guard createStatus == errAuthorizationSuccess,
              let authorization else {
            completion(.unavailable("AuthorizationCreate failed (\(createStatus))"))
            return
        }
        var external = AuthorizationExternalForm()
        let externalStatus = AuthorizationMakeExternalForm(authorization, &external)
        guard externalStatus == errAuthorizationSuccess else {
            AuthorizationFree(authorization, [.destroyRights])
            completion(.unavailable("AuthorizationMakeExternalForm failed (\(externalStatus))"))
            return
        }
        let form = withUnsafeBytes(of: external) { Data($0) }
        let reply = MainActorOneShot<Bool> { accepted in
            AuthorizationFree(authorization, [.destroyRights])
            completion(accepted ? .unexpectedlyAccepted : .refused)
        }
        let xpcReply: @Sendable (Bool) -> Void = { reply.resolve($0) }
        proxy.debugValidateProtectionAuthorization(
            authorizationExternalForm: form,
            reply: xpcReply
        )
        DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + 5) {
            reply.resolve(false)
        }
    }
#endif

    public func requestDeleteQuarantinedFile(
        id: UUID,
        completion: @escaping @MainActor (Bool) -> Void
    ) {
        guard let proxy = extensionProxy() else {
            completion(false)
            return
        }
        let reply = MainActorOneShot<Bool> { [weak self] success in
            if success { self?.quarantineRecords.removeAll { $0.id == id } }
            completion(success)
        }
        let xpcReply: @Sendable (Bool) -> Void = { reply.resolve($0) }
        proxy.requestDeleteQuarantinedFile(id: id.uuidString, reply: xpcReply)
        DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + 5) { reply.resolve(false) }
    }
}

// MARK: - Unified extension evidence

private extension RemediationReport {
    var quarantineSucceeded: Bool {
        quarantineRecord != nil && actions.contains {
            $0.type == .quarantineFile && $0.success
        }
    }
}

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
        let isAppleReviewEvent = event.metadata?["ruleTier"] == "review"
        let isRansomwareBehavior = event.metadata?["detectionKind"] == "ransomware-behavior"
        let isLOLBinBehavior = event.metadata?["detectionKind"] == "lolbin-behavior"
        let isCredentialAccess = event.metadata?["detectionKind"] == "credential-access"
        let severity: SignalSeverity
        if event.decision == .deny {
            severity = .critical
        } else if isManagementObservation || isNickMaintenance || isDocumentedUninstall {
            severity = .info
        } else if isAppleReviewEvent {
            if isCredentialAccess, event.metadata?["signalSeverity"] == "info" {
                severity = .info
            } else {
                severity = .medium
            }
        } else if isLOLBinBehavior {
            switch event.metadata?["signalSeverity"] {
            case "critical": severity = .critical
            case "medium": severity = .medium
            default: severity = .high
            }
        } else {
            severity = .high
        }
        let actorPath = (isLOLBinBehavior || isCredentialAccess)
            ? (event.metadata?["execTargetPath"] ?? filePath)
            : event.processPath
        let signingStatus: SigningStatus
        if let teamID = event.teamID, !teamID.isEmpty {
            signingStatus = .signed(teamID: teamID, signingID: event.signingID)
        } else if !actorPath.isEmpty {
            signingStatus = SignatureValidator.shared.evaluate(binaryPath: actorPath)
        } else {
            signingStatus = .unknown
        }
        let process = NickProcessInfo(
            pid: event.pid,
            path: actorPath,
            name: URL(fileURLWithPath: actorPath).lastPathComponent,
            parentPID: event.parentPid,
            parentName: nil,
            signingStatus: signingStatus
        )
        let isAuditEvent = isManagementObservation || isNickMaintenance || isDocumentedUninstall
        let ruleClass = isTamper ? "integrity" : (isAuditEvent ? "audit" : ((isRansomwareBehavior || isLOLBinBehavior) ? "behavior" : "signature"))
        let ruleTier = event.metadata?["ruleTier"] ?? (isAuditEvent ? "review" : "protected")
        var metadata = [
            "reason": isTamper
                ? (event.metadata?["reason"] ?? "endpoint_tamper_observed")
                : (isDocumentedUninstall ? "nick_documented_uninstall" : (isNickMaintenance ? "nick_protected_path_maintenance" : (isManagementObservation ? "endpoint_management_observed" : "endpoint_threat"))),
            "rule": event.metadata?["reason"] ?? (isDocumentedUninstall
                ? "nick_documented_uninstall"
                : (isNickMaintenance
                    ? "nick_protected_path_maintenance"
                    : (isManagementObservation
                        ? "endpoint_management_observed"
                        : (event.threatName ?? "endpoint_known_threat")))),
            "class": ruleClass,
            "ruleTier": ruleTier,
            "threatFamily": event.threatFamily ?? "unknown"
        ].merging(event.metadata ?? [:]) { current, _ in current }
        // The extension's classifier owns the concrete behavior identity.
        // Defaults above exist only for older events that did not persist one;
        // they must never flatten a specific reason into endpoint_threat.
        if let reason = event.metadata?["reason"], !reason.isEmpty {
            metadata["reason"] = reason
        }
        if let rule = event.metadata?["rule"], !rule.isEmpty {
            metadata["rule"] = rule
        }
        if isLOLBinBehavior {
            // The classifier's concrete reason is the behavior identity used
            // by presentation and deduplication. The generic endpoint default
            // must not overwrite it on the persisted-event path.
            metadata["reason"] = event.metadata?["reason"] ?? "lolbin_behavior"
            metadata["rule"] = event.metadata?["rule"] ?? metadata["reason"]
            metadata["class"] = "behavior"
            metadata["ruleTier"] = event.metadata?["ruleTier"] ?? "protected"
        }
        if isTamper {
            metadata["tamperDisposition"] = event.decision == .deny ? "blocked" : "observed"
        }
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
                isDocumentedUninstall: isDocumentedUninstall,
                isLOLBinBehavior: isLOLBinBehavior
            ),
            context: ThreatSignalContext(
                processInfo: process,
                // Audit-only process observations are about the actor, not
                // suspicious content at its executable path. Treating the
                // platform-binary path as file evidence would incorrectly
                // promote an explicitly allow-listed review rule to protected.
                fileInfo: (isAuditEvent || isLOLBinBehavior || isRansomwareBehavior) ? nil : FileInfo(
                    path: filePath,
                    sha256Hash: event.sha256,
                    entropy: nil,
                    signingStatus: nil,
                    sizeBytes: nil
                ),
                metadata: metadata
            )
        )
        score = event.decision == .deny ? 0.98 : ((isAuditEvent || isAppleReviewEvent) ? 0.35 : 0.9)
        recommendedAction = (isAuditEvent || isAppleReviewEvent)
            ? "No action is needed if you ran this command."
            : "Review the event and investigate it if you do not recognise the activity."
    }

    private static func description(
        for event: ESEvent,
        isTamper: Bool,
        isManagementObservation: Bool,
        isNickMaintenance: Bool,
        isDocumentedUninstall: Bool,
        isLOLBinBehavior: Bool
    ) -> String {
        switch event.metadata?["appleEvent"] {
        case "xprotect-malware-detected":
            return "Apple XProtect detected known malware at the recorded path."
        case "xprotect-malware-remediated":
            return event.metadata?["remediationSucceeded"] == "true"
                ? "Apple XProtect reports that it remediated the detected malware."
                : "Apple XProtect attempted remediation but reported that it did not complete."
        case "background-item-added":
            return "macOS recorded a background item being added. Review it if you did not expect this change."
        case "background-item-removed":
            return "macOS recorded a background item being removed."
        case "gatekeeper-user-override":
            return "A user overrode Gatekeeper for this item. Review the item before opening it again."
        case "tcc-permission-modified":
            return "macOS recorded a privacy-permission change for the identified app."
        default:
            break
        }
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
        if isLOLBinBehavior {
            switch event.metadata?["reason"] {
            case "curl_pipe_shell", "wget_pipe_shell", "download_pipe_interpreter":
                return "Nick saw a shell run a script supplied by a download command."
            case "decoded_payload_interpreter":
                return "Nick saw decoded content fed directly into an interpreter."
            case "osascript_shell":
                return "Nick saw AppleScript start a shell command."
            case "quarantine_removal":
                return "Nick saw a command remove macOS quarantine metadata."
            case "base64_payload", "encoded_payload":
                return "Nick saw a command decode and execute an encoded payload."
            default:
                return "Nick saw a command perform security-sensitive behavior."
            }
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
        let succeeded = report.quarantineSucceeded
        let quarantineFailureReason = report.actions.first {
            $0.type == .quarantineFile && !$0.success
        }?.detail.trimmingCharacters(in: .whitespacesAndNewlines)
        let typedFailure = report.actions.first {
            $0.type == .quarantineFile && !$0.success
        }?.quarantineFailure
        let failureReason = quarantineFailureReason.flatMap { detail in
            detail.isEmpty ? nil : detail
        } ?? "The quarantine operation did not complete."
        signal = ThreatSignal(
            id: stableID,
            source: .filesystem,
            severity: succeeded ? .high : (typedFailure?.reason == .fileGone ? .info : .critical),
            timestamp: report.timestamp,
            title: succeeded ? "Threat remediation completed" : report.threatName,
            description: succeeded
                ? "Nick completed a response action for \(report.threatName)."
                : "Nick detected \(report.threatName), but quarantine failed. The file is still present at its original location. Reason: \(failureReason)",
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
                    "ruleTier": "protected",
                    "remediationStatus": succeeded ? "quarantined" : (typedFailure?.reason == .fileGone ? "file-gone" : "quarantine-failed"),
                    "remediationFailureReason": succeeded ? "" : (typedFailure?.reason.rawValue ?? failureReason),
                    "remediationStatusLine": succeeded ? "" : (typedFailure?.statusLine ?? "Quarantine failed — \(failureReason)"),
                    "remediationGuidance": succeeded ? "" : (typedFailure?.guidance ?? "Review the file immediately and retry quarantine if it is still present."),
                    "remediationErrorDomain": typedFailure?.errorDomain ?? "",
                    "remediationErrorCode": typedFailure.map { String($0.errorCode) } ?? "",
                    "remediationVolumeName": typedFailure?.volumeName ?? ""
                ]
            )
        )
        score = succeeded ? 0.88 : 0.98
        recommendedAction = succeeded
            ? "Review the remediation record and keep the item quarantined unless you trust it."
            : (typedFailure?.guidance ?? "Review the file immediately and retry quarantine if it is still present.")
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
                    "fimStatus": "pending",
                    "expectedHash": violation.expectedHash ?? "unavailable"
                ].merging(violation.metadata ?? [:]) { current, _ in current }
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
        Task { @MainActor [weak self] in
            guard let self, await self.receiveThreat(event).mayAcknowledge else { return }
            self.acknowledgeThreat(event.id)
        }
    }

    public nonisolated func reportRemediationAction(_ reportData: Data) {
        guard let report = try? JSONDecoder().decode(RemediationReport.self, from: reportData) else {
            Self.logger.error("Failed to decode RemediationReport")
            return
        }
        Task { @MainActor [weak self] in
            // Successful quarantine augments Quarantine state without creating
            // a duplicate alert. A failed quarantine remains actionable and
            // travels through the normal incident + notification boundary.
            self?.receive(report, deliverToEngine: !report.quarantineSucceeded)
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
