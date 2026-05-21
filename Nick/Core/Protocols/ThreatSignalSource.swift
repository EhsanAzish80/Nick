// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation

// MARK: - ThreatSignalSource

/// Implemented by any object that can produce `ThreatSignal` events.
///
/// The `ThreatCorrelator` accepts any `ThreatSignalSource` when ingesting
/// signals. All Nick monitor types conform to this protocol via `MonitorProtocol`.
///
/// - Note: The protocol is `Sendable` to allow conforming types to pass
///         their signals across actor boundaries safely.
@MainActor
protocol ThreatSignalSource {

    /// Returns the most recent batch of signals produced since the last call,
    /// or since the monitor started if never previously called.
    ///
    /// - Returns: An array of `ThreatSignal` values in chronological order.
    func latestSignals() async -> [ThreatSignal]
}
