// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Darwin
import Foundation

struct TamperActorIdentity: Sendable, Equatable {
    let teamID: String?
    let signingID: String?
    let codesigningFlags: UInt32
    let isPlatformBinary: Bool

    var isValidIdentitySignature: Bool {
        codesigningFlags & ExecutionTrustPolicy.csValid != 0
            && codesigningFlags & ExecutionTrustPolicy.csAdhoc == 0
    }
}

struct TamperConsoleUser: Sendable, Equatable {
    let uid: uid_t
    let homeDirectory: String
}

/// Pure, testable authorization policy for Nick's protected installation paths.
enum TamperProtectionPolicy {
    static let nickTeamID = "UXGW5V3BY6"

    static func isTrustedMaintenanceActor(
        _ identity: TamperActorIdentity,
        nickIdentityValidated: Bool
    ) -> Bool {
        guard identity.isValidIdentitySignature, let signingID = identity.signingID else { return false }
        if identity.teamID == nickTeamID {
            return nickIdentityValidated && nickMaintenanceSigningIDs.contains(signingID)
        }
        return identity.isPlatformBinary && appleInstallerSigningIDs.contains(signingID)
    }

    static func isDocumentedFinderUninstall(
        sourcePath: String,
        destinationPath: String,
        identity: TamperActorIdentity,
        consoleUser: TamperConsoleUser?
    ) -> Bool {
        guard identity.isValidIdentitySignature,
              identity.isPlatformBinary,
              identity.signingID == "com.apple.finder",
              standardized(sourcePath) == "/Applications/Nick.app",
              let consoleUser
        else { return false }
        let destination = standardized(destinationPath)
        let homeTrash = standardized(consoleUser.homeDirectory) + "/.Trash"
        let homePattern = "^" + NSRegularExpression.escapedPattern(for: homeTrash)
            + #"/Nick(?: [0-9]+)?\.app$"#
        if destination.range(of: homePattern, options: .regularExpression) != nil {
            return true
        }
        let volumePattern = #"^/Volumes/[^/]+/\.Trashes/"#
            + String(consoleUser.uid)
            + #"/Nick(?: [0-9]+)?\.app$"#
        return destination.range(of: volumePattern, options: .regularExpression) != nil
    }

    private static func standardized(_ path: String) -> String {
        URL(fileURLWithPath: path).standardizedFileURL.path
    }

    static let nickMaintenanceSigningIDs: Set<String> = [
        "com.ehsanazish.nick",
        "com.ehsanazish.nick.NickExtension",
        "com.ehsanazish.nick.NickNetFilter",
        "com.ehsanazish.nick.helper",
        "com.ehsanazish.nick.uninstaller",
        "Autoupdate",
        "org.sparkle-project.InstallerLauncher",
        "org.sparkle-project.Sparkle.Updater",
    ]

    private static let appleInstallerSigningIDs: Set<String> = [
        "com.apple.installer",
        "com.apple.installd",
        "com.apple.package_script_service",
    ]
}
