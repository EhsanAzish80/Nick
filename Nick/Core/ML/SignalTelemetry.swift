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

/// Records signal features and user verdicts locally for optional CoreML training data export.
///
/// Data is written to a local JSONL file in the app's Application Support directory.
/// **No data is ever transmitted.** Users who want to contribute can export the JSONL
/// file and submit it manually to the GitHub repo.
///
/// Controlled by the `telemetryEnabled` UserDefaults key (default: false).
final class SignalTelemetry: @unchecked Sendable {

    // MARK: - Shared Instance

    static let shared = SignalTelemetry()

    // MARK: - Private

    private let storageURL: URL
    private let queue = DispatchQueue(label: "com.ehsanazish.nick.telemetry", qos: .utility)
    private static let logger = Logger(subsystem: "com.ehsanazish.nick", category: "SignalTelemetry")

    // MARK: - Init

    private init() {
        let appSupport = URL(fileURLWithPath: NSHomeDirectory())
            .appendingPathComponent("Library/Application Support/com.ehsanazish.nick")
        storageURL = appSupport.appendingPathComponent("telemetry.jsonl")
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
        guard UserDefaults.standard.bool(forKey: "telemetryEnabled") else { return }

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

        let lineWithNewline = line + "\n"
        if FileManager.default.fileExists(atPath: storageURL.path) {
            guard let handle = try? FileHandle(forWritingTo: storageURL) else { return }
            handle.seekToEndOfFile()
            handle.write(lineWithNewline.data(using: .utf8) ?? Data())
            try? handle.close()
        } else {
            FileManager.default.createFile(atPath: storageURL.path, contents: lineWithNewline.data(using: .utf8))
        }
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
