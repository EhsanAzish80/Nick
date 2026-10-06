// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation
import os

// MARK: - TrustedProcessList

/// Stores display-name catalogs and exact signing identities approved by the user.
///
/// `TrustedProcessList` solves the false positive problem for known-good software on the
/// developer, creative, enterprise, and power-user configurations documented in
/// `docs/FALSE_POSITIVE_MATRIX.md`. It combines a hardcoded built-in set with a
/// user-configurable set that persists via `AppSettings`.
///
/// Only `UserEntry.identity` participates in security decisions. Legacy and
/// built-in names remain available for migration and display, but never grant
/// a severity downgrade by themselves.
///
/// - Note: Trusting a process suppresses Nick's behavioural alerts for that process.
///   Users should only add processes they have personally verified. Legitimate software
///   does not typically need to be added — the built-in list covers common cases.
struct TrustedProcessList {

    struct UserEntry: Codable, Hashable, Sendable {
        let displayName: String
        let identity: SigningIdentity
    }

    // MARK: - Built-in List

    /// Processes that are pre-approved as part of the default Nick installation.
    ///
    /// This list is conservative. It covers terminal emulators, developer tools,
    /// package managers, known system processes, and a handful of popular apps
    /// that legitimately perform operations Nick would otherwise flag.
    ///
    /// - Note: SECURITY: Every entry here permanently suppresses alerts for the named
    ///   process. Review each addition against the false positive data in
    ///   `docs/FALSE_POSITIVE_MATRIX.md` before merging.
    static let builtIn: Set<String> = [
        // Terminal emulators — shell-spawn from these is expected, not malicious.
        "Terminal", "iTerm2", "iTerm", "Alacritty", "Warp", "Kitty", "Hyper",
        "xterm", "WezTerm",

        // macOS terminal session infrastructure — login is the intermediate
        // process in every Terminal.app session (Terminal → login → shell).
        // tmux and screen also legitimately spawn shells as session managers.
        "login",
        "tmux", "tmux-client", "tmux: server",
        "screen",

        // VS Code and derivatives
        "Code Helper", "Code Helper (Plugin)", "Code Helper (Renderer)",
        "Code Helper (GPU)", "Cursor Helper", "Cursor Helper (Plugin)",
        "Claude Helper", "Claude Helper (Renderer)",

        // Xcode and Apple development tools
        "Xcode", "SourceKit-LSP", "xcrun", "xcodebuild", "simctl",
        "lldb", "lldb-rpc-server",

        // Compilers and build tools
        "swift", "swiftc", "clang", "clang++", "ld", "lld", "ar", "make",
        "cmake", "ninja", "meson",

        // Version control
        "git", "git-credential-osxkeychain",

        // Package managers
        "brew", "npm", "node", "yarn", "pnpm", "bun",
        "python3", "python", "pip3", "pip",
        "ruby", "gem", "bundler",
        "cargo", "rustc",
        "go",

        // SSH and remote access (standard Apple-signed sshd)
        "sshd", "ssh", "scp", "sftp",

        // macOS system background processes known to generate benign signals
        "mdworker", "mdworker_shared", "mds", "mds_stores",
        "cloudd", "nsurlsessiond", "nsurlstoraged",
        "trustd", "syspolicyd", "opendirectoryd",
        "securityd", "coreauthd", "authd",
        "softwareupdated", "storedownloadd", "storeassetd",
        "Spotlight", "SpotlightNetHelper",
        "com.apple.TimeMachine",
        "backupd", "backupd-helper",
        "launchd", "kernel_task",

        // Common productivity apps with legitimate background activity
        "Finder",
    ]

    // MARK: - Private State

    /// User-added process names, loaded from `AppSettings`.
    var userTrusted: Set<String>
    var userEntries: Set<UserEntry>

    private static let logger = Logger(
        subsystem: "com.ehsanazish.nick",
        category: "TrustedProcessList"
    )

    // MARK: - Init

    /// Creates a `TrustedProcessList` with the given user-trusted set.
    ///
    /// In production, pass the value from `AppSettings.shared.userTrustedProcesses`.
    ///
    /// - Parameter userTrusted: User-supplied process names to add to the built-in list.
    init(userTrusted: Set<String> = [], userEntries: Set<UserEntry> = []) {
        self.userTrusted = userTrusted
        self.userEntries = userEntries
    }

    // MARK: - Public API

    /// Returns `true` if `processName` is in either the built-in or user-trusted list.
    ///
    /// Matching is case-insensitive to handle process names that differ in capitalisation
    /// between macOS versions. The check also handles `p_comm` truncation: because the
    /// kernel caps process names at `MAXCOMLEN` (16 characters), a name such as
    /// `"Code Helper (Plugin)"` may arrive as `"Code Helper (Plu"`. Any supplied name
    /// of at least 8 characters that is a case-insensitive prefix of a trusted entry is
    /// still considered trusted.
    ///
    /// - Parameter processName: The process name to check (e.g. `"bash"`, `"Xcode"`).
    /// - Returns: `true` if the process is in the built-in or user-configured trusted list.
    func isTrusted(_ processName: String) -> Bool {
        let name = processName.trimmingCharacters(in: .whitespaces)
        guard !name.isEmpty else { return false }
        // Fast case-insensitive exact match
        if Self.builtIn.contains(where: { $0.caseInsensitiveCompare(name) == .orderedSame })
            || userTrusted.contains(where: { $0.caseInsensitiveCompare(name) == .orderedSame }) {
            return true
        }
        // Handle p_comm truncation: "Code Helper (Plu" should match "Code Helper (Plugin)"
        guard name.count >= 8 else { return false }
        let nameLower = name.lowercased()
        return Self.builtIn.contains { $0.lowercased().hasPrefix(nameLower) }
            || userTrusted.contains { $0.lowercased().hasPrefix(nameLower) }
    }

    /// Security-sensitive trust requires both stable signing fields. Names are
    /// display labels only and never grant a severity downgrade.
    func isTrusted(_ process: NickProcessInfo) -> Bool {
        guard let identity = SigningIdentity(status: process.signingStatus) else { return false }
        return userEntries.contains { $0.identity == identity }
    }

    mutating func addUserTrusted(_ process: NickProcessInfo) -> Bool {
        guard let identity = SigningIdentity(status: process.signingStatus) else { return false }
        userEntries.insert(UserEntry(displayName: process.name, identity: identity))
        userTrusted.remove(process.name)
        return true
    }

    mutating func removeUserEntry(_ entry: UserEntry) {
        userEntries.remove(entry)
    }

    func userTrustedEntries() -> [UserEntry] {
        userEntries.sorted {
            if $0.displayName == $1.displayName { return $0.identity.signingID < $1.identity.signingID }
            return $0.displayName < $1.displayName
        }
    }

    /// Adds `processName` to the user-trusted set.
    ///
    /// Changes are not automatically persisted — call `AppSettings.shared.save()` after.
    ///
    /// - Parameter processName: The process name to trust.
    mutating func addUserTrusted(_ processName: String) {
        guard !processName.isEmpty else { return }
        userTrusted.insert(processName)
        Self.logger.info("User added trusted process: \(processName, privacy: .public)")
    }

    /// Removes `processName` from the user-trusted set.
    ///
    /// Has no effect if `processName` is not in the user-trusted set.
    /// Cannot remove built-in trusted processes.
    ///
    /// - Parameter processName: The process name to remove from user trust.
    mutating func removeUserTrusted(_ processName: String) {
        userTrusted.remove(processName)
        userEntries = userEntries.filter { $0.displayName != processName }
        Self.logger.info("User removed trusted process: \(processName, privacy: .public)")
    }

    // MARK: - Internal Helpers

    /// Returns all trusted process names from both lists, sorted alphabetically.
    ///
    /// Used by the Settings UI to display the full trusted list.
    func allTrustedNames() -> [String] {
        let all = Self.builtIn.union(userTrusted)
        return all.sorted()
    }

    /// Returns only the user-configured names, sorted alphabetically.
    ///
    /// Used by the Settings UI to display the editable portion of the list.
    func userTrustedNames() -> [String] {
        userTrusted.sorted()
    }
}
