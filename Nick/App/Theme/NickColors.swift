// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import AppKit
import SwiftUI

// MARK: - NickColors

/// Semantic color tokens for the Nick design system.
///
/// All tokens resolve to macOS system-native NSColor values so they automatically
/// adapt to Aqua (light) and Dark Aqua appearances without custom asset catalogs.
/// The app targets the Aqua appearance — use `.preferredColorScheme(.light)` on
/// the window content to enforce this.
extension Color {

    // MARK: - Backgrounds

    /// Main window background — NSColor.windowBackgroundColor (~#ECECEC Aqua)
    static let backgroundPrimary   = Color(NSColor.windowBackgroundColor)
    /// Panel / card background — NSColor.controlBackgroundColor (#FFFFFF Aqua)
    static let backgroundSecondary = Color(NSColor.controlBackgroundColor)
    /// Hover states and nested panels — NSColor.controlColor (~#F0F0F5 Aqua)
    static let backgroundTertiary  = Color(NSColor.controlColor)
    /// Elevated surfaces (popovers, sheets) — NSColor.underPageBackgroundColor
    static let backgroundElevated  = Color(NSColor.underPageBackgroundColor)

    // MARK: - Text

    /// Primary text — NSColor.labelColor (#1D1D1F Aqua)
    static let textPrimary    = Color(NSColor.labelColor)
    /// Secondary text — NSColor.secondaryLabelColor (~#6E6E73 Aqua)
    static let textSecondary  = Color(NSColor.secondaryLabelColor)
    /// Tertiary / metadata text — NSColor.tertiaryLabelColor (~#AEAEB2 Aqua)
    static let textTertiary   = Color(NSColor.tertiaryLabelColor)
    /// Text on colored fills (buttons, icon tiles)
    static let textInverse    = Color.white

    // MARK: - Borders & Separators

    /// Hairline dividers — NSColor.separatorColor
    static let borderSubtle  = Color(NSColor.separatorColor)
    /// Input field borders — NSColor.gridColor
    static let borderMedium  = Color(NSColor.gridColor)
    /// Strong borders / selection outlines — NSColor.controlColor
    static let borderStrong  = Color(NSColor.controlColor)

    // MARK: - Status (Apple system palette — light and dark adaptive)

    /// Safe / enabled / all clear  — system green (#34C759 Aqua)
    static let statusGreen  = Color.green
    /// Warning / medium severity  — system yellow (#FFCC00 Aqua)
    static let statusYellow = Color.yellow
    /// Elevated / needs attention  — system orange (#FF9500 Aqua)
    static let statusOrange = Color.orange
    /// Critical / action required  — system red (#FF3B30 Aqua)
    static let statusRed    = Color.red
    /// Informational / scanning    — system blue / accentColor (#007AFF Aqua)
    static let statusBlue   = Color.blue

    // MARK: - Status Backgrounds (12 % opacity fills for badges / chips)

    /// 12 % green fill
    static let statusGreenBg  = Color.green.opacity(0.12)
    /// 12 % yellow fill
    static let statusYellowBg = Color.yellow.opacity(0.12)
    /// 12 % orange fill
    static let statusOrangeBg = Color.orange.opacity(0.12)
    /// 12 % red fill
    static let statusRedBg    = Color.red.opacity(0.12)
    /// 12 % blue fill
    static let statusBlueBg   = Color.blue.opacity(0.12)
    /// 12 % purple fill
    static let statusPurpleBg = Color.purple.opacity(0.12)
}

// MARK: - Severity Color Helpers

extension SignalSeverity {

    /// The solid badge foreground color for this severity level.
    var statusColor: Color {
        switch self {
        case .info:     .statusBlue
        case .low:      .statusGreen
        case .medium:   .statusYellow
        case .high:     .statusOrange
        case .critical: .statusRed
        }
    }

    /// The 12%-opacity badge background for this severity level.
    var statusBackground: Color {
        switch self {
        case .info:     .statusBlueBg
        case .low:      .statusGreenBg
        case .medium:   .statusYellowBg
        case .high:     .statusOrangeBg
        case .critical: .statusRedBg
        }
    }
}
