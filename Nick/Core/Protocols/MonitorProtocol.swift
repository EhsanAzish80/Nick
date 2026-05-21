// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation

// MARK: - MonitorProtocol

/// The base contract for all Nick detection-engine monitors.
///
/// Each monitor in `Core/` conforms to this protocol. Conforming types are
/// `@Observable` classes; their `isRunning` property is observed by the
/// `SecurityEngine` to drive UI status indicators.
///
/// Lifecycle contract:
/// 1. Call `start()` once to begin monitoring.
/// 2. Collect signals via `latestSignals()` at any time.
/// 3. Call `stop()` to release resources. `stop()` must be idempotent.
///
/// - Important: No monitor may import `SwiftUI` or `AppKit`. All monitors
///              live entirely in `Core/` and are UI-layer agnostic.
@MainActor
protocol MonitorProtocol: ThreatSignalSource {

    /// Identifies this monitor in signals and UI.
    var monitorType: MonitorType { get }

    /// Whether the monitor is currently active (polling or watching).
    var isRunning: Bool { get }

    /// Starts the monitor. May throw if required system resources are unavailable.
    ///
    /// - Throws: A typed error specific to the monitor (e.g. `SystemAuditorError`).
    func start() async throws

    /// Stops the monitor and releases any held resources.
    ///
    /// Must be safe to call when the monitor is already stopped.
    func stop() async
}
