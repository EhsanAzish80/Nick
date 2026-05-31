// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation

// MARK: - PrivacyAlert

/// A TCC permission change detected by the system extension.
///
/// `ES_EVENT_TYPE_NOTIFY_TCC_MODIFY` fires whenever an app gains or loses a
/// privacy permission (camera, microphone, full-disk access, etc.).
/// `PrivacyGuard` transforms the raw ES event into this typed, codable struct
/// and pushes it to the container app via XPC.
///
/// Compiled into **both** the NickExtension and Nick targets.
struct PrivacyAlert: Codable, Sendable, Identifiable {

    /// Stable identifier for de-duplication in the UI.
    let id: UUID

    /// When the permission change was observed.
    let timestamp: Date

    /// Human-readable service name (e.g., "Camera", "Full Disk Access").
    let service: String

    /// The bundle identifier of the app that gained or lost the permission.
    let appBundleID: String

    /// Absolute path to the app binary that triggered the TCC change.
    let appPath: String

    /// Whether the permission was granted or revoked.
    let changeType: ChangeType

    enum ChangeType: String, Codable, Sendable {
        case granted
        case revoked
        case modified
    }
}

// MARK: - USBThreat

/// A threat found on an external/removable volume during a background scan.
///
/// When `ES_EVENT_TYPE_NOTIFY_MOUNT` fires for an external volume, `USBScanner`
/// enumerates the volume in the background and reports any threat hits here.
///
/// Compiled into **both** the NickExtension and Nick targets.
struct USBThreat: Codable, Sendable, Identifiable {

    /// Stable identifier for de-duplication in the UI.
    let id: UUID

    /// When the threat was detected.
    let timestamp: Date

    /// Mount point of the external volume (e.g., `/Volumes/USB Drive`).
    let volumePath: String

    /// Absolute path to the threat file on the volume.
    let filePath: String

    /// Human-readable threat name from the signature database, if available.
    let threatName: String?

    /// Threat family / malware family name, if available.
    let threatFamily: String?

    /// SHA-256 hex digest of the threat file.
    let sha256: String?
}
