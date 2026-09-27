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

    // MARK: - Status (Nick palette — light and dark adaptive)
    //
    // Pure system `.yellow` / `.green` text fails contrast on light
    // backgrounds, so status colours are tuned pairs: a dark text colour on a
    // pale fill in light mode and a bright text colour on a deep fill in dark
    // mode. Every pair meets 4.5:1 for text on its own background.

    /// Safe / enabled / all clear — the Nick accent green.
    static let statusGreen  = Color.nickAccent
    /// Warning / medium severity.
    static let statusYellow = Color.nickWarningText
    /// Elevated / needs attention.
    static let statusOrange = Color.nickDynamic(light: 0xB54708, dark: 0xFF9A3C)
    /// Critical / action required.
    static let statusRed    = Color.nickDangerText
    /// Informational / scanning.
    static let statusBlue   = Color.nickDynamic(light: 0x1D5FBF, dark: 0x6AA8FF)

    // MARK: - Status Backgrounds (badges / chips / icon tiles)

    static let statusGreenBg  = Color.nickAccentTint
    static let statusYellowBg = Color.nickWarningBackground
    static let statusOrangeBg = Color.nickDynamic(light: 0xFDEAD7, dark: 0x3B2412)
    static let statusRedBg    = Color.nickDangerBackground
    static let statusBlueBg   = Color.nickDynamic(light: 0xE5EEFB, dark: 0x16243A)
    static let statusPurpleBg = Color.purple.opacity(0.12)

    // MARK: - Nick 4.6.2 design tokens

    /// Accent (also `AccentColor` in the asset catalog, so `.tint` matches).
    static let nickAccent            = Color.nickDynamic(light: 0x15803D, dark: 0x34D17A)
    static let nickAccentTint        = Color.nickDynamic(light: 0xE6F4EC, dark: 0x16301F)
    /// The dark "guard" hero card. Stays dark in both appearances.
    static let nickGuardHero         = Color.nickDynamic(light: 0x0F1412, dark: 0x0B0F0D)
    static let nickWindow            = Color(nsColor: NSColor(name: "NickWindow") { appearance in
        appearance.isDarkAqua ? .windowBackgroundColor : NSColor(hex: 0xFAFAFA)
    })
    static let nickCard              = Color.nickDynamic(light: 0xFFFFFF, dark: 0x232624)
    static let nickInset             = Color.nickDynamic(light: 0xF6F7F6, dark: 0x1C1F1D)
    static let nickSecondaryText     = Color.nickDynamic(light: 0x6A6F6C, dark: 0xA3AAA6)
    static let nickWarningText       = Color.nickDynamic(light: 0x8A4B00, dark: 0xF5B13D)
    static let nickWarningBackground = Color.nickDynamic(light: 0xFBEFD9, dark: 0x3A2C14)
    static let nickDangerText        = Color.nickDynamic(light: 0xB42318, dark: 0xFF7A6B)
    static let nickDangerBackground  = Color.nickDynamic(light: 0xFDE8E6, dark: 0x3A1D1A)
    static let nickNeutralTile       = Color.nickDynamic(light: 0xEEF0EF, dark: 0x2C302E)

    // Hero ring colours (always on the dark hero, so one value each).
    static let nickRingProtected = Color(nsColor: NSColor(hex: 0x34D17A))
    static let nickRingAttention = Color(nsColor: NSColor(hex: 0xF5B13D))
    static let nickRingBlocked   = Color(nsColor: NSColor(hex: 0xFF7A6B))
    static let nickHeroEyebrow   = Color(nsColor: NSColor(hex: 0x8FA89A))
    static let nickHeroBody      = Color(nsColor: NSColor(hex: 0xB9C5BF))
    static let nickHeroMeta      = Color(nsColor: NSColor(hex: 0x93A39B))
    static let nickHeroOnRing    = Color(nsColor: NSColor(hex: 0x07120C))

    /// A light/dark pair resolved by the current appearance.
    static func nickDynamic(light: UInt32, dark: UInt32) -> Color {
        Color(nsColor: NSColor(name: nil) { appearance in
            NSColor(hex: appearance.isDarkAqua ? dark : light)
        })
    }
}

private extension NSAppearance {
    var isDarkAqua: Bool {
        bestMatch(from: [.aqua, .darkAqua, .accessibilityHighContrastAqua, .accessibilityHighContrastDarkAqua])
            .map { $0 == .darkAqua || $0 == .accessibilityHighContrastDarkAqua } ?? false
    }
}

extension NSColor {
    /// sRGB colour from a 0xRRGGBB literal.
    convenience init(hex: UInt32, alpha: CGFloat = 1) {
        self.init(
            srgbRed: CGFloat((hex >> 16) & 0xFF) / 255,
            green: CGFloat((hex >> 8) & 0xFF) / 255,
            blue: CGFloat(hex & 0xFF) / 255,
            alpha: alpha
        )
    }
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
