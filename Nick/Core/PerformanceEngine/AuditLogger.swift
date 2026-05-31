// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation

/// Appends cleanup actions to `~/Library/Logs/Nick/cleanup-audit.log`.
final class AuditLogger: Sendable {
    private let logURL: URL
    private let lock = NSLock()

    init() {
        let logsDir = ScanRuleHelpers.homeURL("Library", "Logs", "Nick")
        try? FileManager.default.createDirectory(at: logsDir, withIntermediateDirectories: true)
        logURL = logsDir.appendingPathComponent("cleanup-audit.log")
    }

    func log(action: String, url: URL, size: Int64) {
        let iso = ISO8601DateFormatter().string(from: Date())
        let line = "[\(iso)] action=\(action) size=\(size) path=\(url.path)\n"
        lock.withLock {
            if let data = line.data(using: .utf8) {
                if FileManager.default.fileExists(atPath: logURL.path) {
                    if let handle = try? FileHandle(forWritingTo: logURL) {
                        handle.seekToEndOfFile()
                        handle.write(data)
                        try? handle.close()
                    }
                } else {
                    try? data.write(to: logURL, options: .atomic)
                }
            }
        }
    }
}
