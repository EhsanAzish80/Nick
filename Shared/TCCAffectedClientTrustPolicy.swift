// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation

/// Decides whether a TCC change affected validated Apple code. The identity
/// belongs to the client whose TCC record changed, not merely the process that
/// caused the change.
enum TCCAffectedClientTrustPolicy {
    static func isValidatedAppleClient(
        appBundleID: String,
        appPath: String,
        liveBundleID: String?,
        livePath: String?,
        liveIsValidatedApple: Bool,
        validateApplePath: (String) -> Bool
    ) -> Bool {
        if liveIsValidatedApple {
            if !appBundleID.isEmpty, liveBundleID == appBundleID {
                return true
            }
            if !appPath.isEmpty,
               let livePath,
               canonicalPath(livePath) == canonicalPath(appPath) {
                return true
            }
        }

        guard appPath.hasPrefix("/") else { return false }
        return validateApplePath(appPath)
    }

    private static func canonicalPath(_ path: String) -> String {
        URL(fileURLWithPath: path).resolvingSymlinksInPath().standardizedFileURL.path
    }
}
