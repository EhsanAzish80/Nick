// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import SwiftUI

// MARK: - NickColors

/// Semantic color tokens for the Nick design system.
///
/// All color references in Nick views must go through this extension —
/// never use hardcoded hex values or system colors like `Color.green` directly.
/// Each token maps to a named color set in `Assets.xcassets/Colors/` that
/// provides both dark (default) and light mode values.
///
/// - Note: Nick ships dark-mode-first (`NSAppearanceNameDarkAqua` in Info.plist),
///   but every token has a light-mode counterpart for accessibility.
extension Color {

    // MARK: - Backgrounds

    /// Main window background. Dark: #1A1A1E / Light: #F5F5F7
    static let backgroundPrimary   = Color("BackgroundPrimary")
    /// Cards and panels. Dark: #232328 / Light: #FFFFFF
    static let backgroundSecondary = Color("BackgroundSecondary")
    /// Hover states and nested panels. Dark: #2C2C32 / Light: #F0F0F5
    static let backgroundTertiary  = Color("BackgroundTertiary")
    /// Popovers, modals, alert details. Dark: #303038 / Light: #E8E8F0
    static let backgroundElevated  = Color("BackgroundElevated")

    // MARK: - Text

    /// Headings and primary content. Dark: #EAEAEF / Light: #1D1D1F
    static let textPrimary    = Color("TextPrimary")
    /// Descriptions and secondary labels. Dark: #9898A0 / Light: #6E6E73
    static let textSecondary  = Color("TextSecondary")
    /// Timestamps, metadata, disabled states. Dark: #606068 / Light: #AEAEB2
    static let textTertiary   = Color("TextTertiary")
    /// Text rendered on colored badge backgrounds. Dark: #1A1A1E / Light: #1A1A1E
    static let textInverse    = Color("TextInverse")

    // MARK: - Borders & Separators

    /// Card edges and dividers. Dark: #2E2E36 / Light: #D1D1D6
    static let borderSubtle  = Color("BorderSubtle")
    /// Input fields and focused elements. Dark: #3A3A44 / Light: #C7C7CC
    static let borderMedium  = Color("BorderMedium")
    /// Active selection. Dark: #4A4A54 / Light: #AEAEB2
    static let borderStrong  = Color("BorderStrong")

    // MARK: - Status (semantic — never decorative)

    /// Safe / enabled / all clear. Apple system green: #34C759
    static let statusGreen  = Color("StatusGreen")
    /// Warning / medium severity. #FFD60A
    static let statusYellow = Color("StatusYellow")
    /// Elevated / needs attention. #FF9F0A
    static let statusOrange = Color("StatusOrange")
    /// Critical / high severity / action required. #FF453A
    static let statusRed    = Color("StatusRed")
    /// Informational / active scanning. #0A84FF
    static let statusBlue   = Color("StatusBlue")

    // MARK: - Status Backgrounds (12% opacity fills for badges/chips)

    /// 12% green fill for safe-state badges.
    static let statusGreenBg  = Color("StatusGreen").opacity(0.12)
    /// 12% yellow fill for warning badges.
    static let statusYellowBg = Color("StatusYellow").opacity(0.12)
    /// 12% orange fill for elevated badges.
    static let statusOrangeBg = Color("StatusOrange").opacity(0.12)
    /// 12% red fill for critical badges.
    static let statusRedBg    = Color("StatusRed").opacity(0.12)
    /// 12% blue fill for informational badges.
    static let statusBlueBg   = Color("StatusBlue").opacity(0.12)
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
