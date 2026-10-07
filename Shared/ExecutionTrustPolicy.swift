// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation

/// Decides when an executable's code signature is strong enough to skip a
/// content scan, and which locations are always worth scanning.
///
/// `CS_VALID` alone is not trust: every arm64 binary is at least ad-hoc signed,
/// and ad-hoc signatures carry no identity. Only platform binaries and
/// platform-binary status establishes who produced the code at this boundary.
/// A Team ID copied from the executable is only a claim until Security.framework
/// validates its certificate chain and revocation state.
enum ExecutionTrustPolicy {

    // <kern/cs_blobs.h>
    static let csValid: UInt32 = 0x0000_0001
    static let csAdhoc: UInt32 = 0x0000_0002
    static let csPlatformBinary: UInt32 = 0x0400_0000

    /// Identity-bearing signature as reported by Endpoint Security for a
    /// process image (`codesigning_flags`, `is_platform_binary`, `team_id`).
    static func hasTrustedSigner(codesigningFlags flags: UInt32, isPlatformBinary: Bool, teamID: String?) -> Bool {
        guard flags & csValid != 0, flags & csAdhoc == 0 else { return false }
        _ = teamID // never trust a self-asserted Team ID at the ES fast path
        return isPlatformBinary || flags & csPlatformBinary != 0
    }

    /// Paths on the sealed system volume. They cannot be modified without
    /// disabling SIP, so they never need a real-time content scan.
    static func isSealedSystemPath(_ path: String) -> Bool {
        let prefixes = ["/System/", "/usr/bin/", "/usr/sbin/", "/usr/lib/", "/usr/libexec/", "/bin/", "/sbin/"]
        return prefixes.contains { path.hasPrefix($0) }
    }

    /// Locations malware uses for staging and persistence. Code executed from
    /// here is scanned even when it carries a Developer ID signature, because
    /// signed-then-revoked droppers routinely run from these paths.
    static func isHighRiskLocation(_ path: String) -> Bool {
        if isSealedSystemPath(path) { return false }

        let prefixes = [
            "/tmp/", "/private/tmp/", "/var/tmp/", "/private/var/tmp/",
            "/var/folders/", "/private/var/folders/",
            "/Users/Shared/", "/Volumes/",
            "/Library/LaunchAgents/", "/Library/LaunchDaemons/",
            "/Library/PrivilegedHelperTools/", "/Library/Application Support/",
            "/Library/Scripts/",
        ]
        if prefixes.contains(where: { path.hasPrefix($0) }) { return true }

        if path.hasPrefix("/Users/") {
            let markers = [
                "/Downloads/", "/Desktop/", "/Library/LaunchAgents/",
                "/Library/Application Support/", "/Library/Application Scripts/",
                "/Library/Scripts/", "/Library/Caches/", "/.local/", "/.config/",
            ]
            if markers.contains(where: { path.contains($0) }) { return true }
        }

        return hasHiddenComponent(path)
    }

    /// Whether AUTH_EXEC should content-scan the image (after responding).
    static func shouldScanOnExec(path: String, hasTrustedSigner: Bool) -> Bool {
        if isSealedSystemPath(path) { return false }
        return !hasTrustedSigner || isHighRiskLocation(path)
    }

    /// A dot-prefixed directory or file anywhere below the root. Hidden
    /// staging directories are a hallmark of macOS stealers and loaders.
    static func hasHiddenComponent(_ path: String) -> Bool {
        path.split(separator: "/").contains { component in
            component.hasPrefix(".") && component != "." && component != ".."
        }
    }
}
