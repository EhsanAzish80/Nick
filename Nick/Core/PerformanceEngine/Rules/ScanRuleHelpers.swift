// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation

// MARK: - ScanRuleHelpers

/// Shared FileManager utilities used by multiple `ScanRule` implementations.
enum ScanRuleHelpers {

    static let fm = FileManager.default
    static let home = URL(fileURLWithPath: NSHomeDirectory(), isDirectory: true)

    /// Resolves a path relative to `~` and returns a URL.
    static func homeURL(_ components: String...) -> URL {
        components.reduce(home) { $0.appending(path: $1) }
    }

    /// Returns direct child URLs of `parent`, sorted by name.
    /// Returns empty array if `parent` does not exist.
    static func children(of parent: URL) -> [URL] {
        (try? fm.contentsOfDirectory(
            at: parent,
            includingPropertiesForKeys: [.fileSizeKey, .isRegularFileKey],
            options: [.skipsHiddenFiles]
        )) ?? []
    }

    /// Returns all descendants of `url` matching any extension in `extensions`.
    static func files(under url: URL, withExtensions extensions: Set<String>, maxDepth: Int = 3) -> [URL] {
        guard let enumerator = fm.enumerator(
            at: url,
            includingPropertiesForKeys: [.fileSizeKey],
            options: [.skipsHiddenFiles]
        ) else { return [] }

        var result: [URL] = []
        for case let fileURL as URL in enumerator {
            if (enumerator.level) > maxDepth { enumerator.skipDescendants() ; continue }
            if extensions.contains(fileURL.pathExtension.lowercased()) {
                result.append(fileURL)
            }
        }
        return result
    }

    /// Returns all direct children of `url` that are directories.
    static func subdirectories(of url: URL) -> [URL] {
        children(of: url).filter { url in
            var isDir: ObjCBool = false
            fm.fileExists(atPath: url.path, isDirectory: &isDir)
            return isDir.boolValue
        }
    }

    /// Recursive size of a URL (file or directory).
    static func size(of url: URL) -> Int64 {
        var isDir: ObjCBool = false
        guard fm.fileExists(atPath: url.path, isDirectory: &isDir) else { return 0 }
        if isDir.boolValue {
            guard let enumerator = fm.enumerator(
                at: url, includingPropertiesForKeys: [.fileSizeKey], options: []
            ) else { return 0 }
            var total: Int64 = 0
            for case let f as URL in enumerator {
                total += (try? f.resourceValues(forKeys: [.fileSizeKey]))?.fileSize.map(Int64.init) ?? 0
            }
            return total
        }
        return (try? url.resourceValues(forKeys: [.fileSizeKey]))?.fileSize.map(Int64.init) ?? 0
    }

    /// Returns the `Date` a file was last accessed (`.contentAccessDateKey`).
    static func lastAccessed(_ url: URL) -> Date? {
        try? url.resourceValues(forKeys: [.contentAccessDateKey]).contentAccessDate
    }

    /// Returns the `Date` a file was last modified.
    static func lastModified(_ url: URL) -> Date? {
        try? url.resourceValues(forKeys: [.contentModificationDateKey]).contentModificationDate
    }

    /// True when `url` exists on disk.
    static func exists(_ url: URL) -> Bool {
        fm.fileExists(atPath: url.path)
    }
}
