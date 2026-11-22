// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import CryptoKit
import Foundation

/// Shared with the app test host so tests exercise the extension's actual reader.
enum StreamingFileHasher {
    static let chunkSize = 1_024 * 1_024

    static func sha256(path: String, onChunk: (Int) -> Void = { _ in }) -> String? {
        guard let handle = FileHandle(forReadingAtPath: path) else { return nil }
        defer { try? handle.close() }

        var hasher = SHA256()
        while true {
            // Foundation's read buffers can remain autoreleased until the outer
            // scan work item ends. Consume each chunk before draining its pool;
            // only the continuation flag escapes, never the Data buffer.
            let shouldContinue: Bool = autoreleasepool {
                let chunk: Data
                if #available(macOS 10.15.4, *) {
                    guard let data = try? handle.read(upToCount: chunkSize), !data.isEmpty else { return false }
                    chunk = data
                } else {
                    chunk = handle.readData(ofLength: chunkSize)
                    if chunk.isEmpty { return false }
                }
                onChunk(chunk.count)
                hasher.update(data: chunk)
                return true
            }
            if !shouldContinue { break }
        }
        return hasher.finalize().map { String(format: "%02x", $0) }.joined()
    }
}
