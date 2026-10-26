// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation

final class ProtectionContinuityLedger: @unchecked Sendable {
    private struct State: Codable {
        var heartbeat: ProtectionHeartbeat?
        var cleanStop: ProtectionCleanStop?
        var reportedTransitionKeys: Set<String> = []
        var appObservations: [AppObservedProtectionGap] = []
    }

    private let url: URL
    private let lock = NSLock()
    private var state: State

    init(url: URL) {
        self.url = url
        state = (try? Data(contentsOf: url))
            .flatMap { try? JSONDecoder().decode(State.self, from: $0) } ?? State()
    }

    func recordHeartbeat(now: Date, bootSessionUUID: String) -> ProtectionHeartbeat? {
        lock.withLock {
            let next = (state.heartbeat?.sequence ?? 0) &+ 1
            guard next > (state.heartbeat?.sequence ?? 0) else { return nil }
            let heartbeat = ProtectionHeartbeat(
                sequence: next, wallTime: now, bootSessionUUID: bootSessionUUID
            )
            state.heartbeat = heartbeat
            return persistLocked() ? heartbeat : nil
        }
    }

    /// Used by tests and migrations. A root heartbeat is accepted only when its
    /// sequence advances; replay and rollback can never replace newer evidence.
    func acceptHeartbeat(_ heartbeat: ProtectionHeartbeat) -> Bool {
        lock.withLock {
            guard ProtectionContinuityPolicy.acceptsSequence(
                current: state.heartbeat?.sequence,
                proposed: heartbeat.sequence
            ) else { return false }
            state.heartbeat = heartbeat
            return persistLocked()
        }
    }

    func markAuthorizedStop(now: Date, bootSessionUUID: String, reason: String) -> Bool {
        lock.withLock {
            let sequence = state.heartbeat?.sequence ?? 0
            state.cleanStop = ProtectionCleanStop(
                heartbeatSequence: sequence,
                wallTime: now,
                bootSessionUUID: bootSessionUUID,
                reason: String(reason.prefix(160))
            )
            return persistLocked()
        }
    }

    func ingestAppObservation(_ observation: AppObservedProtectionGap) -> Bool {
        lock.withLock {
            guard !state.appObservations.contains(where: { $0.id == observation.id }) else {
                return false
            }
            state.appObservations.append(observation)
            state.appObservations = Array(state.appObservations.suffix(32))
            return persistLocked()
        }
    }

    func evaluateStart(
        now: Date,
        bootSessionUUID: String,
        bootTime: Date
    ) -> ProtectionContinuityIncident? {
        lock.withLock {
            guard let previous = state.heartbeat else { return nil }
            let observations = state.appObservations
            state.appObservations.removeAll()

            if let clean = state.cleanStop,
               clean.bootSessionUUID == previous.bootSessionUUID,
               clean.heartbeatSequence <= previous.sequence,
               previous.wallTime <= clean.wallTime.addingTimeInterval(60) {
                state.cleanStop = nil
                _ = persistLocked()
                return nil
            }

            guard let decision = ProtectionContinuityPolicy.evaluate(
                previous: previous,
                currentBootSessionUUID: bootSessionUUID,
                bootTime: bootTime
            ) else { return nil }
            let kind = decision.kind
            let key = decision.transitionKey
            guard state.reportedTransitionKeys.insert(key).inserted else {
                _ = persistLocked()
                return nil
            }
            _ = persistLocked()

            let detail: String
            switch kind {
            case .interrupted:
                detail = "Protection was interrupted; events in this window were not observed."
            case .resumedAfterRestart:
                detail = "Protection resumed after the Mac restarted."
            case .authorizedStop:
                detail = "Protection was turned off by the user with authorization."
            }
            return ProtectionContinuityIncident(
                kind: kind,
                startedAt: previous.wallTime,
                endedAt: now,
                detail: detail,
                appObservations: observations
            )
        }
    }

    func snapshot() -> (ProtectionHeartbeat?, ProtectionCleanStop?, [AppObservedProtectionGap]) {
        lock.withLock { (state.heartbeat, state.cleanStop, state.appObservations) }
    }

    private func persistLocked() -> Bool {
        do {
            try FileManager.default.createDirectory(
                at: url.deletingLastPathComponent(),
                withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o700]
            )
            let data = try JSONEncoder().encode(state)
            try data.write(to: url, options: .atomic)
            try FileManager.default.setAttributes(
                [.posixPermissions: 0o600], ofItemAtPath: url.path
            )
            return true
        } catch {
            return false
        }
    }
}

final class IntentionalAppExitRegistry: @unchecked Sendable {
    struct SignalContext: Sendable {
        let senderPID: Int32
        let senderPath: String
        let signal: Int32
        let observedAt: Date
    }
    private let lock = NSLock()
    private var intentional: [Int32: Date] = [:]
    private var signals: [Int32: SignalContext] = [:]

    func authorize(pid: Int32, now: Date = Date(), lifetime: TimeInterval = 120) {
        lock.withLock { intentional[pid] = now.addingTimeInterval(lifetime) }
    }

    func recordSignal(targetPID: Int32, context: SignalContext) {
        lock.withLock {
            signals[targetPID] = context
            signals = signals.filter { Date().timeIntervalSince($0.value.observedAt) < 300 }
        }
    }

    func consume(pid: Int32, now: Date = Date()) -> (intentional: Bool, signal: SignalContext?) {
        lock.withLock {
            let allowed = intentional.removeValue(forKey: pid).map { $0 >= now } ?? false
            return (allowed, signals.removeValue(forKey: pid))
        }
    }
}
