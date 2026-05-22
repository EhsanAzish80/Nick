// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import CoreGraphics

// MARK: - NickSpacing

/// Spacing scale for the Nick design system.
///
/// All `padding()` values in Nick views must reference this enum.
/// The scale follows a 4pt base with 8pt preferred increments, consistent
/// with the macOS HIG and the 8pt grid recommended in the design spec.
///
/// - Note: Never write `.padding(8)` in a view — use `.padding(NickSpacing.md)`.
enum NickSpacing {
    /// 2pt — tight internal spacing (e.g., between icon and dot indicator).
    static let xs:   CGFloat = 2
    /// 4pt — small gaps (e.g., between badge elements).
    static let sm:   CGFloat = 4
    /// 8pt — standard intra-component spacing.
    static let md:   CGFloat = 8
    /// 12pt — row internal padding, card inner spacing.
    static let lg:   CGFloat = 12
    /// 16pt — standard section gaps, button horizontal padding.
    static let xl:   CGFloat = 16
    /// 24pt — major section separation.
    static let xxl:  CGFloat = 24
    /// 32pt — top-level layout separation.
    static let xxxl: CGFloat = 32
}
