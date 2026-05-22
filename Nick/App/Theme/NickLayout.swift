// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import CoreGraphics

// MARK: - NickLayout

/// Layout constants for the Nick design system.
///
/// Nick is a fixed-width menu bar panel (420 × 560pt). All layout dimensions
/// are sourced here so they remain consistent and can be adjusted globally.
///
/// - Note: The window is not resizable. Never use flexible widths that assume
///   more than 420pt. Always test at exactly this width in previews.
enum NickLayout {
    /// Fixed MenuBarExtra panel width.
    static let windowWidth:      CGFloat = 420
    /// Maximum MenuBarExtra panel height.
    static let windowHeight:     CGFloat = 560
    /// Corner radius for cards and grouped sections.
    static let cardCornerRadius: CGFloat = 8
    /// Corner radius for badges, pills, and small chips.
    static let badgeCornerRadius: CGFloat = 4
    /// Standard icon size for row-level icons (16pt).
    static let iconSize:         CGFloat = 16
    /// Larger icon size for tab bar and header icons (20pt).
    static let iconSizeLarge:    CGFloat = 20
    /// Minimum row height for click/tap targets (44pt).
    static let rowHeight:        CGFloat = 44
    /// Vertical gap between major sections.
    static let sectionSpacing:   CGFloat = 16
    /// Internal padding for cards.
    static let cardPadding:      CGFloat = 12
    /// Leading inset for row separators (aligns with text, after icon).
    static let separatorInset:   CGFloat = 40
    /// Height of the bottom bar.
    static let bottomBarHeight:  CGFloat = 36
    /// Height of the tab bar.
    static let tabBarHeight:     CGFloat = 36
    /// Height of the score indicator bar below the gauge.
    static let scoreBarHeight:   CGFloat = 3
}
