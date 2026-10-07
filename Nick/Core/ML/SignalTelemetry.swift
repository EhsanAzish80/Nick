// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation
import os

// MARK: - UserVerdict

/// The user's assessment of whether a threat alert was accurate.
enum UserVerdict: String, Codable {
    case truePositive   // user confirmed threat
    case falsePositive  // user dismissed as not a threat
}

// MARK: - SignalTelemetry

/// Records signal features and user verdicts in a local, user-controlled export.
///
/// This user-writable JSONL is never read by Nick's detection, trust, scoring,
/// suppression, or learning paths. It is an optional export only. No data is
/// transmitted automatically.
///
/// Controlled by the `telemetryEnabled` UserDefaults key (default: false).
final class SignalTelemetry: @unchecked Sendable {

    // MARK: - Shared Instance

    static let shared = SignalTelemetry()

    // MARK: - Private

    private let storageURL: URL
    private let isEnabled: () -> Bool
    private let maximumStorageBytes: Int
    private let queue = DispatchQueue(label: "com.ehsanazish.nick.telemetry", qos: .utility)
    private static let logger = Logger(subsystem: "com.ehsanazish.nick", category: "SignalTelemetry")
    static let defaultMaximumStorageBytes = 5 * 1_024 * 1_024

    // MARK: - Init

    private init() {
        let appSupport = URL(fileURLWithPath: NSHomeDirectory())
            .appendingPathComponent("Library/Application Support/com.ehsanazish.nick")
        storageURL = appSupport.appendingPathComponent("telemetry.jsonl")
        isEnabled = { UserDefaults.standard.bool(forKey: "telemetryEnabled") }
        maximumStorageBytes = Self.defaultMaximumStorageBytes
    }

    init(storageURL: URL, maximumStorageBytes: Int, isEnabled: @escaping () -> Bool) {
        self.storageURL = storageURL
        self.maximumStorageBytes = max(1, maximumStorageBytes)
        self.isEnabled = isEnabled
    }

    // MARK: - Public API

    /// Records signal features and a user verdict.
    ///
    /// Writes one JSONL line per call. No-ops if `telemetryEnabled` is false.
    ///
    /// - Parameters:
    ///   - signals: The contributing signals from the alert.
    ///   - verdict: Whether the user considered this a real threat or a false positive.
    func record(signals: [ThreatSignal], verdict: UserVerdict) {
        guard isEnabled() else { return }

        let record = TelemetryRecord(signals: signals, verdict: verdict)
        queue.async { [weak self] in
            self?.appendRecord(record)
        }
    }

    /// Exports the local telemetry file as Data for the user to save or submit.
    ///
    /// - Returns: The raw JSONL bytes, or `nil` if the file doesn't exist or can't be read.
    func exportData() -> Data? {
        try? Data(contentsOf: storageURL)
    }

    /// Deletes the local telemetry file.
    func clearTelemetry() {
        queue.async { [weak self] in
            guard let self else { return }
            try? FileManager.default.removeItem(at: storageURL)
        }
    }

    // MARK: - Private

    private func appendRecord(_ record: TelemetryRecord) {
        let dir = storageURL.deletingLastPathComponent()
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)

        guard let line = (try? JSONEncoder().encode(record)).flatMap({ String(data: $0, encoding: .utf8) }) else {
            Self.logger.error("Failed to encode telemetry record")
            return
        }

        guard let newLine = (line + "\n").data(using: .utf8) else { return }
        let existing = (try? Data(contentsOf: storageURL)) ?? Data()
        let capped = Self.cappedJSONL(existing + newLine, maximumBytes: maximumStorageBytes)
        do {
            try capped.write(to: storageURL, options: .atomic)
        } catch {
            Self.logger.error("Failed to write telemetry export: \(error.localizedDescription)")
        }
    }

    /// Keeps the newest complete JSONL records within the configured cap.
    static func cappedJSONL(_ data: Data, maximumBytes: Int) -> Data {
        guard data.count > maximumBytes else { return data }
        let start = data.count - maximumBytes
        guard let newline = data[start...].firstIndex(of: 0x0A) else { return Data() }
        let recordStart = data.index(after: newline)
        return Data(data[recordStart...])
    }
}

// MARK: - TelemetryRecord

private struct TelemetryRecord: Codable {
    let timestamp: Date
    let verdict: UserVerdict
    let signalFeatures: [SignalFeature]

    struct SignalFeature: Codable {
        let source: String
        let severity: Int
        let title: String
        let hasProcessInfo: Bool
        let hasNetworkInfo: Bool
        let hasFileInfo: Bool
    }

    init(signals: [ThreatSignal], verdict: UserVerdict) {
        self.timestamp = Date()
        self.verdict = verdict
        self.signalFeatures = signals.map { signal in
            SignalFeature(
                source: signal.source.rawValue,
                severity: signal.severity.rawValue,
                title: signal.title,
                hasProcessInfo: signal.processInfo != nil,
                hasNetworkInfo: signal.networkInfo != nil,
                hasFileInfo: signal.fileInfo != nil
            )
        }
    }
}
