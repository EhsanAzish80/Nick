// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import EndpointSecurity
import Foundation
import os

// MARK: - EndpointSecurityClient

/// Thin Swift wrapper around the C-based Endpoint Security API.
///
/// Responsibilities:
/// - Create and own the `es_client_t` handle.
/// - Subscribe to (and unsubscribe from) event types.
/// - Mute its own process to prevent feedback loops.
/// - Forward raw `es_message_t` pointers to `ESEventHandler` for processing.
/// - Respond to AUTH events within the system-imposed deadline.
///
/// All calls to ES APIs are serialised on `queue`. Do not call `start()`,
/// `subscribe(to:)`, or `stop()` concurrently.
///
/// - Important: AUTH events that are not explicitly responded to will be
///   auto-allowed by the system after the deadline (~60 s). Never drop an
///   AUTH message — always call `respond(to:allow:)`.
final class EndpointSecurityClient {

    // MARK: - Private

    private static let logger = Logger(
        subsystem: "com.ehsanazish.nick.NickExtension",
        category: "ESClient"
    )

    /// Serialises access to `client` and all ES API calls.
    private let queue = DispatchQueue(
        label: "com.ehsanazish.nick.NickExtension.esclient",
        qos: .userInteractive
    )

    private var client: OpaquePointer?
    private weak var eventHandler: ESEventHandler?

    // MARK: - Init

    /// - Parameter eventHandler: Receives every decoded ES message for dispatch.
    init(eventHandler: ESEventHandler) {
        self.eventHandler = eventHandler
    }

    // MARK: - Lifecycle

    /// Creates the ES client and mutes this process.
    ///
    /// - Returns: `true` on success; `false` if `es_new_client` fails (e.g.
    ///   missing entitlement, SIP enabled during dev).
    func start() -> Bool {
        var newClient: OpaquePointer?

        let result = es_new_client(&newClient) { [weak self] _, message in
            // This block runs on an ES-internal serial queue — keep it fast.
            self?.eventHandler?.handle(message: message)
        }

        guard result == ES_NEW_CLIENT_RESULT_SUCCESS, let newClient else {
            Self.logger.error("es_new_client failed: \(result.rawValue)")
            return false
        }

        client = newClient

        // Mute ourselves so monitoring our own process doesn't cause a loop.
        muteSelf(client: newClient)

        Self.logger.info("ES client created successfully")
        return true
    }

    /// Subscribes the client to the given ES event types.
    ///
    /// - Parameter events: Array of `es_event_type_t` values to subscribe to.
    /// - Returns: `true` if `es_subscribe` returns `ES_RETURN_SUCCESS`.
    func subscribe(to events: [es_event_type_t]) -> Bool {
        guard let client else {
            Self.logger.error("subscribe called before start()")
            return false
        }

        let result = es_subscribe(client, events, UInt32(events.count))
        guard result == ES_RETURN_SUCCESS else {
            Self.logger.error("es_subscribe failed: \(result.rawValue)")
            return false
        }

        Self.logger.info("Subscribed to \(events.count) ES event type(s)")
        return true
    }

    /// Responds to an AUTH event.
    ///
    /// - Parameters:
    ///   - message: The message pointer received in the `es_new_client` callback.
    ///   - allow: `true` to allow; `false` to deny.
    ///
    /// - Note: Calling this on a NOTIFY event is a no-op (guarded by action-type check).
    func respond(to message: UnsafePointer<es_message_t>, allow: Bool) {
        guard let client else { return }
        guard message.pointee.action_type == ES_ACTION_TYPE_AUTH else { return }

        let authResult: es_auth_result_t = allow ? ES_AUTH_RESULT_ALLOW : ES_AUTH_RESULT_DENY
        let ret = es_respond_auth_result(client, message, authResult, false)
        if ret != ES_RESPOND_RESULT_SUCCESS {
            Self.logger.warning("es_respond_auth_result returned \(ret.rawValue) — may have missed deadline")
        }
    }

    /// Unsubscribes from all events and destroys the ES client.
    func stop() {
        guard let client else { return }
        es_unsubscribe_all(client)
        es_delete_client(client)
        self.client = nil
        Self.logger.info("ES client stopped")
    }

    // MARK: - Path Muting

    /// Mutes all events for paths that start with `prefix`.
    ///
    /// Call after `subscribe(to:)`. Events from muted paths are never delivered,
    /// reducing noise from trusted SIP-protected system directories.
    ///
    /// - Returns: `true` on success.
    @discardableResult
    func mutePathPrefix(_ prefix: String) -> Bool {
        guard let client else { return false }
        let result = es_mute_path(client, prefix, ES_MUTE_PATH_TYPE_PREFIX)
        if result != ES_RETURN_SUCCESS {
            Self.logger.warning("es_mute_path failed for '\(prefix)': \(result.rawValue)")
        }
        return result == ES_RETURN_SUCCESS
    }

    // MARK: - Private Helpers

    private func muteSelf(client: OpaquePointer) {
        // Retrieve the current process's audit token via the task port.
        var token = audit_token_t()
        var info  = mach_task_basic_info()
        var count = mach_msg_type_number_t(MemoryLayout<mach_task_basic_info>.size / MemoryLayout<integer_t>.size)

        withUnsafeMutablePointer(to: &info) { infoPtr in
            infoPtr.withMemoryRebound(to: integer_t.self, capacity: Int(count)) { reboundPtr in
                _ = task_info(mach_task_self_, task_flavor_t(MACH_TASK_BASIC_INFO), reboundPtr, &count)
            }
        }

        // Obtain the audit token for the current process.
        // `mach_msg_type_number_t` sized correctly for `audit_token_t`.
        var tokenSize = mach_msg_type_number_t(
            MemoryLayout<audit_token_t>.size / MemoryLayout<natural_t>.size
        )
        withUnsafeMutablePointer(to: &token) { tokenPtr in
            tokenPtr.withMemoryRebound(to: natural_t.self, capacity: Int(tokenSize)) { reboundPtr in
                _ = task_info(mach_task_self_, task_flavor_t(TASK_AUDIT_TOKEN), reboundPtr, &tokenSize)
            }
        }

        let ret = es_mute_process(client, &token)
        if ret != ES_RETURN_SUCCESS {
            Self.logger.warning("es_mute_process failed: \(ret.rawValue) — self-events may appear")
        }
    }
}
