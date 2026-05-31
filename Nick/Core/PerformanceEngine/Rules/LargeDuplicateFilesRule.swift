// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation
import CryptoKit

/// Finds duplicate files ≥ 10 MB by SHA-256 hash, keeping the newest copy and flagging the rest.
struct LargeDuplicateFilesRule: ScanRule {
    let category = JunkCategory.duplicates
    let displayName = "Large Duplicate Files"

    private static let minSize: Int64 = 10_000_000 // 10 MB

    private static let searchRoots: [URL] = [
        ScanRuleHelpers.homeURL("Desktop"),
        ScanRuleHelpers.homeURL("Downloads"),
        ScanRuleHelpers.homeURL("Documents"),
        ScanRuleHelpers.homeURL("Pictures"),
        ScanRuleHelpers.homeURL("Movies"),
    ]

    func scan() async -> [JunkItem] {
        var sizeGroups: [Int64: [URL]] = [:]

        for root in Self.searchRoots {
            guard ScanRuleHelpers.exists(root) else { continue }
            guard let enumerator = FileManager.default.enumerator(
                at: root,
                includingPropertiesForKeys: [.fileSizeKey, .isDirectoryKey],
                options: [.skipsHiddenFiles, .skipsPackageDescendants]
            ) else { continue }

            while let item = enumerator.nextObject(), let url = item as? URL {
                guard let rv = try? url.resourceValues(forKeys: [.fileSizeKey, .isDirectoryKey]),
                      rv.isDirectory == false else { continue }
                let size = Int64(rv.fileSize ?? 0)
                guard size >= Self.minSize else { continue }
                sizeGroups[size, default: []].append(url)
            }
            await Task.yield()
        }

        // For size groups with > 1 file, hash them
        var items: [JunkItem] = []

        for (size, candidates) in sizeGroups where candidates.count > 1 {
            var hashGroups: [String: [URL]] = [:]
            for url in candidates {
                if let hash = sha256(url) {
                    hashGroups[hash, default: []].append(url)
                }
            }
            for (_, dupes) in hashGroups where dupes.count > 1 {
                // Keep newest; flag the rest
                let sorted = dupes.sorted {
                    (ScanRuleHelpers.lastModified($0) ?? .distantPast) > (ScanRuleHelpers.lastModified($1) ?? .distantPast)
                }
                for dupe in sorted.dropFirst() {
                    items.append(JunkItem(url: dupe, size: size, category: category,
                                          riskLevel: .review, name: dupe.lastPathComponent,
                                          reason: "Duplicate file — identical content found elsewhere on disk."))
                }
            }
            await Task.yield()
        }

        return items
    }

    private func sha256(_ url: URL) -> String? {
        guard let stream = InputStream(url: url) else { return nil }
        stream.open()
        defer { stream.close() }
        var hasher = SHA256()
        let bufferSize = 65536
        let buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: bufferSize)
        defer { buffer.deallocate() }
        while stream.hasBytesAvailable {
            let read = stream.read(buffer, maxLength: bufferSize)
            guard read > 0 else { break }
            hasher.update(data: Data(bytesNoCopy: buffer, count: read, deallocator: .none))
        }
        return hasher.finalize().map { String(format: "%02x", $0) }.joined()
    }
}
