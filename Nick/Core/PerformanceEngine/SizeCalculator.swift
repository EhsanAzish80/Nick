// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation

// MARK: - SizeCalculator

/// Computes the on-disk size of files and directories using `FileManager`.
///
/// Declared as an `actor` so size computations from multiple concurrent scan
/// rules don't contend on shared state. The file-system calls themselves are
/// thread-safe, but the actor boundary makes it easy to batch them safely.
actor SizeCalculator {

    private let fm = FileManager.default

    // MARK: - Public API

    /// Returns the total size (in bytes) of a single URL.
    ///
    /// For directories this recursively sums all contained files.
    /// Returns 0 if the URL does not exist or cannot be read.
    func size(of url: URL) -> Int64 {
        var isDir: ObjCBool = false
        guard fm.fileExists(atPath: url.path, isDirectory: &isDir) else { return 0 }

        if isDir.boolValue {
            return directorySize(url)
        } else {
            return fileSize(url)
        }
    }

    /// Returns the total size (in bytes) for an array of URLs.
    func sizes(of urls: [URL]) -> Int64 {
        urls.reduce(0) { $0 + size(of: $1) }
    }

    // MARK: - Private

    private func fileSize(_ url: URL) -> Int64 {
        (try? url.resourceValues(forKeys: [.fileSizeKey]))?.fileSize.map(Int64.init) ?? 0
    }

    private func directorySize(_ url: URL) -> Int64 {
        guard let enumerator = fm.enumerator(
            at: url,
            includingPropertiesForKeys: [.fileSizeKey],
            options: [.skipsHiddenFiles, .skipsPackageDescendants]
        ) else { return 0 }

        var total: Int64 = 0
        for case let fileURL as URL in enumerator {
            total += fileSize(fileURL)
        }
        return total
    }
}
