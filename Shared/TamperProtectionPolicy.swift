// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Darwin
import Foundation

struct ProtectionHeartbeat: Codable, Equatable, Sendable {
    let sequence: UInt64
    let wallTime: Date
    let bootSessionUUID: String
    let extensionBuild: String?

    init(sequence: UInt64, wallTime: Date, bootSessionUUID: String, extensionBuild: String? = nil) {
        self.sequence = sequence
        self.wallTime = wallTime
        self.bootSessionUUID = bootSessionUUID
        self.extensionBuild = extensionBuild
    }
}

struct ProtectionCleanStop: Codable, Equatable, Sendable {
    let heartbeatSequence: UInt64
    let wallTime: Date
    let bootSessionUUID: String
    let reason: String
}

struct AppObservedProtectionGap: Codable, Equatable, Sendable {
    let id: UUID
    let observedAt: Date
    let lastHealthyAt: Date?
    let reason: String
}

struct ProtectionContinuityIncident: Equatable, Sendable {
    enum Kind: String, Equatable, Sendable {
        case interrupted, resumedAfterRestart, authorizedStop, updated
    }
    let kind: Kind
    let startedAt: Date?
    let endedAt: Date
    let detail: String
    let appObservations: [AppObservedProtectionGap]
}

enum ProtectionContinuityPolicy {
    struct Decision: Equatable, Sendable {
        let kind: ProtectionContinuityIncident.Kind
        let transitionKey: String
    }

    static func evaluate(
        previous: ProtectionHeartbeat,
        currentBootSessionUUID: String,
        bootTime: Date,
        currentExtensionBuild: String? = nil,
        previousObservedExtensionBuild: String? = nil,
        extensionRestarted: Bool = true
    ) -> Decision? {
        // Sleep and wake do not restart the extension. Treating a long wall-clock
        // interval alone as a gap would turn every normal sleep into an alert.
        guard extensionRestarted else { return nil }
        if previous.bootSessionUUID == currentBootSessionUUID,
           let previousBuild = previous.extensionBuild ?? previousObservedExtensionBuild,
           let currentExtensionBuild,
           previousBuild != currentExtensionBuild {
            return Decision(
                kind: .updated,
                transitionKey: "update:\(previousBuild):\(currentExtensionBuild):\(previous.sequence)"
            )
        }
        if previous.bootSessionUUID == currentBootSessionUUID {
            return Decision(
                kind: .interrupted,
                transitionKey: "gap:\(previous.bootSessionUUID):\(previous.sequence)"
            )
        }
        let kind: ProtectionContinuityIncident.Kind = previous.wallTime < bootTime.addingTimeInterval(-120)
            ? .interrupted : .resumedAfterRestart
        return Decision(
            kind: kind,
            transitionKey: "boot:\(currentBootSessionUUID):\(previous.sequence):\(kind.rawValue)"
        )
    }

    static func acceptsSequence(current: UInt64?, proposed: UInt64) -> Bool {
        proposed > (current ?? 0)
    }
}

enum NickSignalProtectionPolicy {
    static let protectedSignals: Set<Int32> = [SIGKILL, SIGTERM, SIGSTOP, SIGINT, SIGHUP, SIGQUIT]
    static let endpointExtensionSigningID = "com.ehsanazish.nick.NickExtension"

    static func protectsTarget(_ identity: TamperActorIdentity) -> Bool {
        identity.teamID == TamperProtectionPolicy.nickTeamID
            && identity.isValidIdentitySignature
            && identity.signingID == endpointExtensionSigningID
    }

    static func shouldDeny(
        signal: Int32,
        targetIdentity: TamperActorIdentity,
        senderIdentity: TamperActorIdentity,
        senderNickIdentityValidated: Bool
    ) -> Bool {
        guard protectedSignals.contains(signal), protectsTarget(targetIdentity) else { return false }
        if senderNickIdentityValidated { return false }
        return !senderIdentity.isPlatformBinary
    }
}

enum ProtectionBootIdentity {
    static func sessionUUID() -> String {
        sysctlString("kern.bootsessionuuid") ?? "unknown-boot"
    }

    static func bootTime() -> Date {
        var value = timeval()
        var size = MemoryLayout<timeval>.size
        if sysctlbyname("kern.boottime", &value, &size, nil, 0) == 0 {
            return Date(timeIntervalSince1970: TimeInterval(value.tv_sec))
        }
        return Date()
    }

    private static func sysctlString(_ name: String) -> String? {
        var size = 0
        guard sysctlbyname(name, nil, &size, nil, 0) == 0, size > 1 else { return nil }
        var bytes = [CChar](repeating: 0, count: size)
        guard sysctlbyname(name, &bytes, &size, nil, 0) == 0 else { return nil }
        let content = bytes.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }
        return String(decoding: content, as: UTF8.self)
    }
}

enum TamperProtectedOperation: String, Codable, CaseIterable, Sendable {
    case unlink
    case renameSource = "rename-source"
    case renameDestination = "rename-destination"
    case openWrite = "open-for-write"
    case create
    case truncate
    case link
    case clone
    case copyfile
}

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

struct NickUpdateLease: Codable, Sendable, Equatable {
    let id: UUID
    let consoleUID: UInt32
    let expectedTeamID: String
    let sourceBuild: Int
    let destinationBuild: Int
    let createdAt: Date
    let expiresAtUptime: TimeInterval
}

enum NickUpdateLeaseOperation: String, Codable, Sendable {
    case write
    case rename
    case unlink
}

enum NickUpdateLeasePolicy {
    enum Decision: Equatable {
        case allowed(consume: Bool)
        case expired
        case rejected
    }
    static let maximumDuration: TimeInterval = 10 * 60
    static let applicationPath = "/Applications/Nick.app"

    static func makeLease(
        consoleUID: uid_t,
        sourceBuild: Int,
        destinationBuild: Int,
        duration: TimeInterval,
        now: Date,
        uptime: TimeInterval
    ) -> NickUpdateLease? {
        guard sourceBuild > 0,
              destinationBuild > sourceBuild,
              duration > 0,
              duration <= maximumDuration else { return nil }
        return NickUpdateLease(
            id: UUID(),
            consoleUID: UInt32(consoleUID),
            expectedTeamID: TamperProtectionPolicy.nickTeamID,
            sourceBuild: sourceBuild,
            destinationBuild: destinationBuild,
            createdAt: now,
            expiresAtUptime: uptime + duration
        )
    }

    static func containsProtectedUpdateDestination(_ path: String) -> Bool {
        let standardized = URL(fileURLWithPath: path).standardizedFileURL.path
        return standardized == applicationPath
            || standardized.hasPrefix(applicationPath + "/")
    }

    static func isReplacementBoundary(
        sourcePath: String?,
        destinationPath: String,
        operation: NickUpdateLeaseOperation
    ) -> Bool {
        guard operation == .rename else { return false }
        let destination = URL(fileURLWithPath: destinationPath).standardizedFileURL.path
        guard destination == applicationPath else { return false }
        guard let sourcePath else { return true }
        return URL(fileURLWithPath: sourcePath).standardizedFileURL.path != applicationPath
    }

    static func isEligibleInstallerActor(
        identity: TamperActorIdentity,
        nickUpdateIdentityValidated: Bool,
        actorPath: String
    ) -> Bool {
        guard identity.isValidIdentitySignature else { return false }
        if identity.teamID == TamperProtectionPolicy.nickTeamID {
            return nickUpdateIdentityValidated
        }
        guard identity.isPlatformBinary else { return false }
        let standardized = URL(fileURLWithPath: actorPath).standardizedFileURL.path
        return standardized.hasPrefix("/System/Library/PrivateFrameworks/PackageKit.framework/")
            || standardized.hasPrefix("/System/Library/CoreServices/Installer.app/")
            || standardized == "/usr/sbin/installer"
            || standardized == "/usr/libexec/installd"
    }

    static func decision(
        lease: NickUpdateLease,
        uptime: TimeInterval,
        targetPath: String,
        sourcePath: String? = nil,
        operation: NickUpdateLeaseOperation,
        actorPath: String,
        identity: TamperActorIdentity,
        nickUpdateIdentityValidated: Bool
    ) -> Decision {
        guard uptime <= lease.expiresAtUptime else { return .expired }
        guard containsProtectedUpdateDestination(targetPath),
              isEligibleInstallerActor(
                  identity: identity,
                  nickUpdateIdentityValidated: nickUpdateIdentityValidated,
                  actorPath: actorPath
              ) else { return .rejected }
        return .allowed(consume: isReplacementBoundary(
            sourcePath: sourcePath,
            destinationPath: targetPath,
            operation: operation
        ))
    }
}

/// Pure, testable authorization policy for Nick's protected installation paths.
enum TamperProtectionPolicy {
    static let nickTeamID = "UXGW5V3BY6"

    /// Commands that can remove Nick's system extensions must remain
    /// actionable. Read-only inventory commands are audit history only.
    static func isSensitiveSystemExtensionCommand(arguments: [String]) -> Bool {
        let commands = Set(arguments.dropFirst().map { $0.lowercased() })
        return !commands.isDisjoint(with: ["uninstall", "reset"])
    }

    static func isTrustedMaintenanceActor(
        _ identity: TamperActorIdentity,
        nickIdentityValidated: Bool
    ) -> Bool {
        guard identity.isValidIdentitySignature, let signingID = identity.signingID else { return false }
        if identity.teamID == nickTeamID {
            return nickIdentityValidated && nickMaintenanceSigningIDs.contains(signingID)
        }
        return identity.isPlatformBinary && isAppleInstallerSigningID(signingID)
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
        "org.sparkle-project.InstallerLauncher",
        "org.sparkle-project.Sparkle.Updater",
    ]

    /// Update helpers that are deliberately not permanently trusted. They may
    /// change protected Nick files only while an authorised update lease is
    /// active, so a future helper identity cannot strand an otherwise valid
    /// signed update merely because an older extension lacks it in its list.
    static let nickLeasedUpdateSigningIDs: Set<String> = [
        "Autoupdate",
        "org.sparkle-project.InstallerLauncher",
        "org.sparkle-project.Sparkle.Updater",
    ]

    private static let appleInstallerSigningIDs: Set<String> = [
        "com.apple.installer",
        "com.apple.installd",
        "com.apple.package_script_service",
        // PackageKit performs the final atomic replacement through this
        // platform binary rather than installd itself.
        "com.apple.shove",
    ]

    static func isAppleInstallerSigningID(_ signingID: String) -> Bool {
        appleInstallerSigningIDs.contains(signingID)
    }

    static func isValidatedInstallerMaintenanceIdentity(_ identity: TamperActorIdentity) -> Bool {
        identity.isPlatformBinary
            && identity.isValidIdentitySignature
            && identity.signingID.map(isAppleInstallerSigningID) == true
    }
}
