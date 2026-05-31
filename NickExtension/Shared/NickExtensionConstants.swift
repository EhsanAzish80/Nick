// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation

// MARK: - NickExtensionConstants

/// Bundle identifiers, Mach service names, and other constants shared between
/// the `Nick` container app and the `NickExtension` System Extension.
///
/// This file is compiled into **both** targets. Add both targets to this file's
/// "Target Membership" in Xcode.
public enum NickExtensionConstants {

    /// Bundle identifier of the `NickExtension` System Extension target.
    public static let extensionBundleID = "com.ehsanazish.nick.NickExtension"

    /// Mach service name used for XPC communication between the container app
    /// and the System Extension. Must match the name registered in the
    /// extension's Info.plist (if explicitly declared) and the container app's
    /// `NSXPCConnection` initialiser.
    public static let machServiceName = "com.ehsanazish.nick.NickExtension.xpc"

    /// Apple Developer Team ID used for code-signing validation.
    public static let teamID = "UXGW5V3BY6"
}
