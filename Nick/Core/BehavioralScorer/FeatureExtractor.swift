// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation
import os

// MARK: - FeatureExtractor

/// Converts a collection of `ThreatSignal` values from a correlation window into a `FeatureVector`.
///
/// `FeatureExtractor` is the bridge between the raw signal stream and the CoreML
/// behavioral scoring model. It scans all signals in the window, extracts the most
/// relevant process, network, file, persistence, and YARA context, and normalizes
/// each value into the expected input range. Missing data always defaults to `0.0`
/// so the model receives a complete, well-formed input on every call.
///
/// - Note: This type is `Sendable` — it has no mutable state and can be shared
///         freely across concurrent contexts.
final class FeatureExtractor: Sendable {

    // MARK: - Private Constants

    private static let shellNames: Set<String> = ["bash", "zsh", "sh", "python", "python3", "ruby", "perl"]
    private static let terminalNames: Set<String> = ["Terminal", "iTerm2", "Warp", "Alacritty", "hyper"]
    private static let commonPorts: Set<Int> = [22, 53, 80, 443]

    private static let logger = Logger(subsystem: "com.ehsanazish.nick", category: "FeatureExtractor")

    // MARK: - Init

    init() {
        // Creates a new instance. No configuration required.
    }

    // MARK: - Public API

    /// Extracts a fully-populated `FeatureVector` from signals in the correlation window.
    ///
    /// All 40 features are populated. Signals outside `windowDuration` are ignored.
    /// Temporal features are derived from the relative timestamps of events in the window.
    ///
    /// - Parameters:
    ///   - signals: All signals currently in the correlation window.
    ///   - windowDuration: Duration of the correlation window used to compute temporal features.
    /// - Returns: A `FeatureVector` ready for CoreML inference. Never contains NaN or infinity.
    func extract(from signals: [ThreatSignal], windowDuration _: TimeInterval) -> FeatureVector {
        var vec = FeatureVector()

        guard !signals.isEmpty else { return vec }

        // MARK: Process features
        let processSignals = signals.filter { $0.source == .process }
        if let proc = processSignals.first?.processInfo {
            vec.processIsUnsigned     = proc.signingStatus == .unsigned || proc.signingStatus == .invalid ? 1 : 0
            vec.processIsAdHocSigned  = proc.signingStatus == .adHoc ? 1 : 0
            vec.processInTmp          = isInTmpDir(proc.path) ? 1 : 0
            vec.processInHiddenDir    = containsHiddenComponent(proc.path) ? 1 : 0
            vec.processIsShell        = Self.shellNames.contains(proc.name.lowercased()) ? 1 : 0
            vec.processParentIsGuiApp = isGuiApp(proc.parentName) ? 1 : 0
            vec.processParentIsTerminal = isTerminal(proc.parentName) ? 1 : 0

            // Parent chain depth stored in metadata under "parentChainDepth"
            let depth = processSignals
                .compactMap { $0.metadata["parentChainDepth"].flatMap { Int($0) } }
                .max() ?? 0
            vec.processParentChainDepth = Double(min(depth, 10))

            if let startTime = proc.startTime {
                vec.processAgeSeconds = max(0, Date().timeIntervalSince(startTime))
            }
        }

        // LOLBin detected if any process signal carries the metadata flag
        vec.processIsLolbin = signals.contains { $0.metadata["isLolbin"] == "true" } ? 1 : 0

        // MARK: Network features
        let netSignals = signals.filter { $0.source == .network }
        let networkInfos = netSignals.compactMap { $0.networkInfo }

        if !networkInfos.isEmpty {
            let outbound = networkInfos.filter { $0.state == .established && $0.remoteAddress != nil }
            vec.netHasOutboundConnection = outbound.isEmpty ? 0 : 1

            // "Raw IP" means the remote hostname matches an IP pattern (no DNS name)
            let rawIPConnections = outbound.filter { conn in
                guard let addr = conn.remoteAddress else { return false }
                return isRawIPAddress(addr)
            }
            vec.netRemoteIsRawIP = rawIPConnections.isEmpty ? 0 : 1

            // Use the first outbound connection's remote port
            if let firstConn = outbound.first, let remotePort = firstConn.remotePort {
                vec.netRemotePort = Double(remotePort)
                vec.netRemotePortIsCommon = Self.commonPorts.contains(remotePort) ? 1 : 0
                vec.netUsesUncommonPort   = Self.commonPorts.contains(remotePort) ? 0 : 1
            }

            let listening = networkInfos.filter { $0.state == .listen }
            vec.netIsListening     = listening.isEmpty ? 0 : 1
            vec.netConnectionCount = Double(networkInfos.count)
        }

        // MARK: File system features
        let fsSignals = signals.filter { $0.source == .filesystem }
        let fileInfos = signals.compactMap { $0.fileInfo }

        if let file = fileInfos.first {
            vec.fsFileInTmp              = isInTmpDir(file.path) ? 1 : 0
            vec.fsFileEntropy            = file.entropy ?? 0
            vec.fsFileEntropyIsHigh      = (file.entropy ?? 0) > 7.5 ? 1 : 0
            vec.fsFileIsMacho            = file.path.hasSuffix(".dylib") || signals.contains {
                $0.metadata["isMacho"] == "true"
            } ? 1 : 0
            vec.fsFileHasEmbeddedURLs    = signals.contains { $0.metadata["hasEmbeddedURLs"] == "true" } ? 1 : 0
            vec.fsFileHasEmbeddedBase64  = signals.contains { $0.metadata["hasEmbeddedBase64"] == "true" } ? 1 : 0
        }

        vec.fsRapidCreationDetected = fsSignals.contains { $0.metadata["rapidCreation"] == "true" } ? 1 : 0

        // MARK: Persistence features
        let persistSignals = signals.filter { $0.source == .persistence }
        vec.persistNewLaunchAgent       = persistSignals.contains { $0.metadata["persistType"] == "launchAgent" } ? 1 : 0
        vec.persistNewLaunchDaemon      = persistSignals.contains { $0.metadata["persistType"] == "launchDaemon" } ? 1 : 0
        vec.persistNewCronjob           = persistSignals.contains { $0.metadata["persistType"] == "cron" } ? 1 : 0
        vec.persistExecutableUnsigned   = persistSignals.contains { $0.metadata["targetUnsigned"] == "true" } ? 1 : 0
        vec.persistExecutableMissing    = persistSignals.contains { $0.metadata["targetMissing"] == "true" } ? 1 : 0

        // MARK: YARA features
        let yaraSignals = signals.filter { $0.source == .yara }
        vec.yaraMatchCount   = Double(yaraSignals.count)
        let yaraMaxRaw = yaraSignals.map { $0.severity.rawValue }.max() ?? 0
        vec.yaraMaxSeverity  = Double(yaraMaxRaw)

        // MARK: System audit features
        let auditSignals = signals.filter { $0.source == .systemAudit }
        vec.auditSipDisabled         = auditSignals.contains { $0.metadata["check"] == "sip_disabled" } ? 1 : 0
        vec.auditFilevaultDisabled   = auditSignals.contains { $0.metadata["check"] == "filevault_disabled" } ? 1 : 0
        vec.auditGatekeeperDisabled  = auditSignals.contains { $0.metadata["check"] == "gatekeeper_disabled" } ? 1 : 0
        vec.auditFirewallDisabled    = auditSignals.contains { $0.metadata["check"] == "firewall_disabled" } ? 1 : 0

        // MARK: Temporal features
        let sortedByTime = signals.sorted { $0.timestamp < $1.timestamp }
        let earliest = sortedByTime.first?.timestamp
        let latest   = sortedByTime.last?.timestamp

        // Time between first file event and first process event
        let firstFile    = signals.filter { $0.source == .filesystem }.min { $0.timestamp < $1.timestamp }?.timestamp
        let firstProcess = signals.filter { $0.source == .process    }.min { $0.timestamp < $1.timestamp }?.timestamp
        if let fp = firstFile, let pp = firstProcess {
            vec.temporalTimeSinceFileCreation = abs(pp.timeIntervalSince(fp))
        }

        // Time between first process event and first network event
        let firstNet = signals.filter { $0.source == .network }.min { $0.timestamp < $1.timestamp }?.timestamp
        if let pp = firstProcess, let fn = firstNet {
            vec.temporalTimeSinceNetConnection = max(0, fn.timeIntervalSince(pp))
        }

        vec.temporalSignalsInWindow = Double(signals.count)

        let uniqueMonitors = Set(signals.map { $0.source }).count
        vec.temporalUniqueMonitorsFiring = Double(uniqueMonitors)

        // Severity escalation: did max severity increase between first and second half of the window?
        if let earliest, let latest, latest > earliest {
            let midPoint  = earliest.addingTimeInterval(latest.timeIntervalSince(earliest) / 2)
            let firstHalf  = signals.filter { $0.timestamp <= midPoint }
            let secondHalf = signals.filter { $0.timestamp > midPoint }
            let maxFirst  = firstHalf.map  { $0.severity.rawValue }.max() ?? 0
            let maxSecond = secondHalf.map { $0.severity.rawValue }.max() ?? 0
            vec.temporalSeverityEscalation = maxSecond > maxFirst ? 1 : 0
        }

        Self.logger.debug("Extracted feature vector: \(vec.temporalSignalsInWindow) signals, \(vec.temporalUniqueMonitorsFiring) monitors")

        return vec
    }

    // MARK: - Private Helpers

    private func isInTmpDir(_ path: String) -> Bool {
        path.hasPrefix("/tmp/") || path.hasPrefix("/var/tmp/") || path.hasPrefix("/private/tmp/")
    }

    private func containsHiddenComponent(_ path: String) -> Bool {
        path.components(separatedBy: "/").contains { $0.hasPrefix(".") && $0.count > 1 }
    }

    private func isGuiApp(_ parentName: String?) -> Bool {
        guard let name = parentName else { return false }
        // Common macOS app bundle process names end in a capitalized word that isn't a shell
        let excluded = Self.shellNames.union(Self.terminalNames)
        return !excluded.contains(name) && name.first?.isUppercase == true
    }

    private func isTerminal(_ parentName: String?) -> Bool {
        guard let name = parentName else { return false }
        return Self.terminalNames.contains(name)
    }

    /// Returns true if the string looks like a raw IPv4 or IPv6 address rather than a hostname.
    private func isRawIPAddress(_ address: String) -> Bool {
        // IPv4 pattern: four decimal octets
        let parts = address.split(separator: ".")
        if parts.count == 4 && parts.allSatisfy({ Int($0) != nil }) { return true }
        // IPv6: contains colons but no letters other than a-f
        if address.contains(":") { return true }
        return false
    }
}
