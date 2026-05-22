// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation

// MARK: - HelperPathAllowlist

/// Validates file paths before they are sent to the privileged helper over XPC.
///
/// This allowlist exists in the main app as a pre-validation layer (defense in depth).
/// An identical copy lives in `NickHelper/HelperProtocol.swift` where the helper itself
/// re-validates every path it receives — it never trusts the caller, even if it's Nick.
///
/// Keeping both copies in sync is intentional and documented here so future maintainers
/// understand the duplication. If you change the allowlist, update both files.
///
/// Validation steps (applied in order):
/// 1. Reject null bytes — filesystem APIs stop at the first null, creating a mismatch.
/// 2. Reject paths longer than 4 096 bytes — prevents stack-allocation attacks.
/// 3. Reject relative paths — the helper only reads from known absolute locations.
/// 4. Reject percent-encoded path separators (`%2F`, `%2f`) — URL-decode bypass.
/// 5. Normalise unicode to NFC — prevents look-alike character bypass.
/// 6. Resolve symlinks — prevents symlinks that escape an allowed directory.
/// 7. Confirm the resolved path starts with an allowed prefix.
///
/// - Note: SECURITY: Adding a prefix to `allowedPrefixes` expands the helper's
///   read surface. Review every addition against the principle of least privilege.
public enum HelperPathAllowlist {

    /// Directories the helper is permitted to read plist files from.
    /// Each entry must end with `/` to prevent prefix-bypass (e.g. `/Library/LaunchDaemonsEvil`).
    public static let allowedPrefixes: [String] = [
        "/Library/LaunchDaemons/",
        "/Library/LaunchAgents/",
        "/Library/Preferences/",
        "/System/Library/LaunchDaemons/",
        "/System/Library/LaunchAgents/",
    ]

    /// Maximum accepted byte length for a path string.
    public static let maxPathLength = 4_096

    /// Returns `true` if `path` passes all validation checks.
    ///
    /// - Parameter path: The caller-supplied path string.
    /// - Returns: `true` only when the path resolves to an allowed directory.
    public static func validate(_ path: String) -> Bool {
        // 1. Reject null bytes.
        // SECURITY: A null byte terminates C strings; a path "a\0../etc/passwd"
        // looks valid to String but truncates at the null in C file APIs.
        guard !path.contains("\0") else { return false }

        // 2. Reject oversized paths.
        guard path.utf8.count <= maxPathLength else { return false }

        // 3. Require an absolute path.
        guard path.hasPrefix("/") else { return false }

        // 4. Reject percent-encoded separators.
        // SECURITY: "%2F" and "%2f" represent '/' in URL encoding. A caller could
        // use them to confuse a naive prefix check before URL decoding is applied.
        let lower = path.lowercased()
        guard !lower.contains("%2f") else { return false }

        // 5. Reject any path containing a '..' traversal component.
        // SECURITY: /Library/LaunchDaemons/../../etc/passwd resolves to /etc/passwd.
        // Reject '..' in the raw input so traversal attacks never reach step 6.
        let rawComponents = path.components(separatedBy: "/")
        guard !rawComponents.contains("..") else { return false }

        // 6. Normalise unicode to NFC.
        // SECURITY: Two visually identical strings can differ in byte representation
        // (composed vs. decomposed form). Normalise before comparing.
        let normalised = path.precomposedStringWithCanonicalMapping

        // 7. Resolve symlinks.
        // SECURITY: A symlink inside /Library/LaunchDaemons/ could point to /etc/passwd.
        // Resolving symlinks before the prefix check prevents this.
        let resolved = URL(fileURLWithPath: normalised).resolvingSymlinksInPath().path

        // 8. Check against the allowlist.
        return allowedPrefixes.contains { resolved.hasPrefix($0) }
    }
}
