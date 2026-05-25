// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation
import os

// MARK: - TrustedProcessList

/// A two-tier list of processes that are pre-approved as safe and should not trigger alerts.
///
/// `TrustedProcessList` solves the false positive problem for known-good software on the
/// developer, creative, enterprise, and power-user configurations documented in
/// `docs/FALSE_POSITIVE_MATRIX.md`. It combines a hardcoded built-in set with a
/// user-configurable set that persists via `AppSettings`.
///
/// Processes in this list are excluded from:
/// - Shell-spawn alerts (LOLBin detector, parent-chain analyzer)
/// - Reverse-shell detection when the parent is a known terminal
/// - High-severity signal emission (downgraded to `.info` for correlation only)
///
/// - Note: Trusting a process suppresses Nick's behavioural alerts for that process.
///   Users should only add processes they have personally verified. Legitimate software
///   does not typically need to be added — the built-in list covers common cases.
struct TrustedProcessList {

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
    init(userTrusted: Set<String> = []) {
        self.userTrusted = userTrusted
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

    /// Returns `true` only when `processName` is in the trusted list **and** the running
    /// process at `pid` carries a valid code signature.
    ///
    /// This overload prevents impersonation attacks where a malicious binary uses the name
    /// of a trusted process (e.g. "Code Helper") to bypass behavioural detection.
    /// If the process has already exited and its path cannot be resolved, this returns
    /// `false` — callers that need a softer fallback should use `isTrusted(_:)`.
    ///
    /// - Parameters:
    ///   - processName: Process name to check (e.g. `"bash"`, `"Xcode"`).
    ///   - pid:         PID of the running process to verify.
    /// - Returns: `true` if the name is trusted **and** the binary is signed.
    func isTrusted(_ processName: String, pid: pid_t) -> Bool {
        // PID 1 is exclusively launchd on macOS. SecCodeCopyGuestWithAttributes cannot
        // validate PID 1, so skip the signature check and fall back to name-only trust.
        // We do NOT grant blanket trust to every process whose parentPID happens to be 1 —
        // only names that are in the trusted list are accepted.
        if pid == 1 { return isTrusted(processName) }
        // Name must be in the trusted list first.
        guard isTrusted(processName) else { return false }
        // Resolve the on-disk path of the running process.
        let maxSize = 4096
        var buffer = [CChar](repeating: 0, count: maxSize)
        let ret = proc_pidpath(pid, &buffer, UInt32(maxSize))
        guard ret > 0 else { return false }
        let path = buffer.withUnsafeBufferPointer { bp in
            String(decoding: UnsafeRawBufferPointer(bp).prefix(while: { $0 != 0 }), as: UTF8.self)
        }
        guard !path.isEmpty else { return false }
        // Verify the binary is actually signed — reject unsigned impersonators.
        let status = SignatureValidator.shared.evaluate(binaryPath: path)
        if case .signed = status { return true }
        Self.logger.warning(
            "Trusted-name process '\(processName, privacy: .public)' (PID \(pid)) failed signature check — treating as untrusted"
        )
        return false
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
