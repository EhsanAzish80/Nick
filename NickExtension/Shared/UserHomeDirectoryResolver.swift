// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation

/// Resolves real local-user home directories from a root system extension.
/// `NSHomeDirectory()` and tilde expansion point at `/var/root` in that
/// process and must never be used for user-facing protection locations.
enum UserHomeDirectoryResolver {
    static func humanHomeDirectories(
        usersDirectory: URL = URL(fileURLWithPath: "/Users", isDirectory: true),
        fileManager: FileManager = .default
    ) -> [URL] {
        guard let entries = try? fileManager.contentsOfDirectory(
            at: usersDirectory,
            includingPropertiesForKeys: [.isDirectoryKey, .isSymbolicLinkKey],
            options: [.skipsHiddenFiles]
        ) else { return [] }

        let excludedNames: Set<String> = ["Shared", "Guest", "Deleted Users"]
        return entries.compactMap { url in
            guard !excludedNames.contains(url.lastPathComponent),
                  let values = try? url.resourceValues(forKeys: [.isDirectoryKey, .isSymbolicLinkKey]),
                  values.isDirectory == true,
                  values.isSymbolicLink != true
            else { return nil }
            return url.standardizedFileURL
        }.sorted { $0.path < $1.path }
    }
}
