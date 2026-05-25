// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation
import os

// MARK: - Pipeline Types

/// Converts a `ThreatAlert` into a formatted string ready for output.
typealias AlertFormatter = @Sendable (ThreatAlert) -> String

/// Sends a pre-formatted alert string to a destination (file, network, stdout).
typealias AlertOutput = @Sendable (String) async -> Void

// MARK: - AlertFormatters

/// Built-in formatter implementations.
enum AlertFormatters: Sendable {

    /// Structured key=value line, compatible with Splunk's KV extract and most SIEM ingest parsers.
    static let kv: AlertFormatter = { alert in
        let ts = ISO8601DateFormatter().string(from: alert.timestamp)
        let signals = alert.contributingSignals
            .map { $0.title.replacingOccurrences(of: " ", with: "_") }
            .joined(separator: ",")
        return "timestamp=\(ts) severity=\(alert.severity.displayName.uppercased()) score=\(String(format: "%.2f", alert.score)) rule=\(alert.title.replacingOccurrences(of: " ", with: "_")) signals=\(signals)"
    }

    /// JSON object. Suitable for Elastic/OpenSearch, HTTP Event Collector, and webhook receivers.
    static let json: AlertFormatter = { alert in
        let payload: [String: Any] = [
            "timestamp": ISO8601DateFormatter().string(from: alert.timestamp),
            "severity": alert.severity.rawValue,
            "score": alert.score,
            "title": alert.title,
            "signals": alert.contributingSignals.map { $0.title }
        ]
        let data = (try? JSONSerialization.data(withJSONObject: payload, options: [])) ?? Data()
        return String(data: data, encoding: .utf8) ?? ""
    }

    /// Common Event Format (CEF) compatible with ArcSight and many other SIEMs.
    static let cef: AlertFormatter = { alert in
        "CEF:0|3nsofts|Nick|1.2|detection|\(alert.title)|\(alert.severity.cefSeverity)| ts=\(alert.timestamp.timeIntervalSince1970) score=\(alert.score)"
    }
}

// MARK: - AlertOutputs

/// Built-in output sink implementations.
enum AlertOutputs: Sendable {

    /// Appends the formatted line to a file, creating it if absent.
    static func file(url: URL) -> AlertOutput {
        return { message in
            let line = message + "\n"
            guard let data = line.data(using: .utf8) else { return }
            if FileManager.default.fileExists(atPath: url.path) {
                if let handle = try? FileHandle(forWritingTo: url) {
                    handle.seekToEndOfFile()
                    handle.write(data)
                    try? handle.close()
                }
            } else {
                try? data.write(to: url, options: .atomic)
            }
        }
    }

    /// HTTP-POSTs the formatted string to an endpoint.
    ///
    /// The formatter is responsible for producing valid content — use `AlertFormatters.json`
    /// for endpoints that expect JSON (e.g. Splunk HEC), or `AlertFormatters.cef` for CEF.
    static func http(url: URL) -> AlertOutput {
        return { message in
            var request = URLRequest(url: url)
            request.httpMethod = "POST"
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
            request.setValue("Nick/1.2", forHTTPHeaderField: "User-Agent")
            request.httpBody = message.data(using: .utf8)
            _ = try? await URLSession.shared.data(for: request)
        }
    }

    /// Prints to stdout. Useful for debugging and pipe-based integrations.
    static let stdout: AlertOutput = { message in
        print(message)
    }
}

// MARK: - Pipeline Assembly

/// Emits `alert` through the given formatter and every configured output.
func emitAlert(_ alert: ThreatAlert, formatter: AlertFormatter, outputs: [AlertOutput]) async {
    guard !outputs.isEmpty else { return }
    let formatted = formatter(alert)
    for output in outputs {
        await output(formatted)
    }
}

/// Builds the active formatter + output list from `UserDefaults`.
///
/// Keys read:
/// - `logFormatter`          String  "kv" | "json" | "cef"   (default "kv")
/// - `fileLoggingEnabled`    Bool    (default false)
/// - `webhookURL`            String  optional URL
/// - `stdoutLoggingEnabled`  Bool    (default false)
func buildPipeline() -> (AlertFormatter, [AlertOutput]) {
    let formatter: AlertFormatter
    switch UserDefaults.standard.string(forKey: "logFormatter") ?? "kv" {
    case "json": formatter = AlertFormatters.json
    case "cef":  formatter = AlertFormatters.cef
    default:     formatter = AlertFormatters.kv
    }

    var outputs: [AlertOutput] = []

    if UserDefaults.standard.bool(forKey: "fileLoggingEnabled") {
        let url = currentLogFileURL()
        outputs.append(AlertOutputs.file(url: url))
    }

    if let webhookString = UserDefaults.standard.string(forKey: "webhookURL"),
       let url = URL(string: webhookString),
       url.scheme == "https" || url.scheme == "http" {
        outputs.append(AlertOutputs.http(url: url))
    }

    if UserDefaults.standard.bool(forKey: "stdoutLoggingEnabled") {
        outputs.append(AlertOutputs.stdout)
    }

    return (formatter, outputs)
}

// MARK: - Log File Management

/// Returns a `URL` for today's log file, creating the directory if needed.
/// Prunes log files older than 30 days as a side-effect (at most once per session).
func currentLogFileURL() -> URL {
    let logDirectory = URL(fileURLWithPath: NSHomeDirectory())
        .appendingPathComponent("Library/Logs/Nick")
    try? FileManager.default.createDirectory(at: logDirectory, withIntermediateDirectories: true)

    let formatter = DateFormatter()
    formatter.dateFormat = "yyyy-MM-dd"
    let fileURL = logDirectory.appendingPathComponent("nick-\(formatter.string(from: Date())).log")

    NickLogFilePruner.pruneIfNeeded(in: logDirectory)
    return fileURL
}

// MARK: - NickLogFilePruner

/// Prunes log files older than 30 days, at most once per calendar day.
enum NickLogFilePruner {
    nonisolated(unsafe) private static var lastPruneDate: Date?

    static func pruneIfNeeded(in directory: URL) {
        let today = Calendar.current.startOfDay(for: Date())
        guard lastPruneDate != today else { return }
        lastPruneDate = today

        guard let files = try? FileManager.default.contentsOfDirectory(
            at: directory, includingPropertiesForKeys: [.creationDateKey]
        ) else { return }

        let cutoff = Date(timeIntervalSinceNow: -30 * 86_400)
        for file in files where file.pathExtension == "log" {
            if let attrs = try? file.resourceValues(forKeys: [.creationDateKey]),
               let created = attrs.creationDate,
               created < cutoff {
                try? FileManager.default.removeItem(at: file)
            }
        }
    }
}
