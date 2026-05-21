// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation

// MARK: - PersistenceType

/// Categorises the macOS persistence mechanism represented by a `PersistenceItem`.
enum PersistenceType: String, Codable, Sendable, CaseIterable {

    /// `/Library/LaunchDaemons/` — runs as root, before login.
    case launchDaemon = "launchDaemon"

    /// `/Library/LaunchAgents/` or `~/Library/LaunchAgents/` — runs as user.
    case launchAgent = "launchAgent"

    /// Login Item registered via `SMAppService` or Legacy Login Items.
    case loginItem = "loginItem"

    /// Entry in `/etc/crontab` or a user's crontab.
    case cronJob = "cronJob"

    /// Script in `/etc/periodic/daily`, `weekly`, or `monthly`.
    case periodicScript = "periodicScript"

    /// Installed system extension in `/Library/SystemExtensions/`.
    case systemExtension = "systemExtension"

    /// Browser extension (Safari, Chrome, Firefox, Arc).
    case browserExtension = "browserExtension"

    /// Legacy startup item in `/Library/StartupItems/`.
    case startupItem = "startupItem"

    // MARK: - Display Helpers

    /// Human-readable label for UI presentation.
    var displayName: String {
        switch self {
        case .launchDaemon:    return "Launch Daemon"
        case .launchAgent:     return "Launch Agent"
        case .loginItem:       return "Login Item"
        case .cronJob:         return "Cron Job"
        case .periodicScript:  return "Periodic Script"
        case .systemExtension: return "System Extension"
        case .browserExtension:return "Browser Extension"
        case .startupItem:     return "Startup Item"
        }
    }
}

// MARK: - PersistenceScope

/// Whether a persistence item operates system-wide or for the current user.
enum PersistenceScope: String, Codable, Sendable, CaseIterable {
    /// Applies to all users; typically requires root privileges to install.
    case system = "system"
    /// Applies only to the current user's session.
    case user = "user"
}

// MARK: - PersistenceItem

/// Represents one persistence mechanism discovered on the system.
///
/// `PersistenceWatcher` creates these during its snapshot scan and compares
/// them to a stored baseline to detect additions or modifications. The
/// `ThreatCorrelator` uses `signingStatus` and `isEnabled` to score newly
/// discovered items.
struct PersistenceItem: Sendable, Codable, Identifiable, Equatable {

    // MARK: - Properties

    /// Stable identifier for this item within a scan session.
    let id: UUID

    /// Category of persistence mechanism.
    let type: PersistenceType

    /// Human-readable name — the plist `Label` key or filename.
    let name: String

    /// Absolute path to the plist file or item container on disk.
    let path: String

    /// Absolute path to the executable this item will launch, if resolvable.
    let executablePath: String?

    /// Whether the item is currently enabled (RunAtLoad, KeepAlive, or equivalent).
    let isEnabled: Bool

    /// Code-signing status of the executable at `executablePath`, if evaluated.
    let signingStatus: SigningStatus?

    /// Whether this item is system-wide or user-scoped.
    let scope: PersistenceScope

    /// Modification timestamp of the plist or item file.
    let lastModified: Date?
}
