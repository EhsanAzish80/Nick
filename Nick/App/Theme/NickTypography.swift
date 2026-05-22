// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import SwiftUI

// MARK: - NickTypography

/// Font scale for the Nick design system.
///
/// All `font()` calls in Nick views must reference this extension.
/// Never write `.font(.system(size: 12))` in a view file — use the named
/// token instead. This ensures consistent typographic hierarchy across the
/// entire app and makes global type adjustments a one-line change.
///
/// - Note: Nick uses system fonts only (SF Pro + SF Mono). No custom font loading.
extension Font {

    // MARK: - Display

    /// Large numeric display for the health score gauge (36pt bold rounded).
    static let nickGaugeValue = Font.system(size: 36, weight: .bold, design: .rounded)

    // MARK: - Headings

    /// View titles and panel headers (16pt semibold).
    static let nickTitle    = Font.system(size: 16, weight: .semibold)
    /// Section headers within views (13pt semibold).
    static let nickSubtitle = Font.system(size: 13, weight: .semibold)

    // MARK: - Body

    /// Primary body content (12pt regular).
    static let nickBody       = Font.system(size: 12, weight: .regular)
    /// Emphasized body text (12pt medium).
    static let nickBodyMedium = Font.system(size: 12, weight: .medium)
    /// Secondary descriptions and supporting text (11pt regular).
    static let nickBodySmall  = Font.system(size: 11, weight: .regular)

    // MARK: - Technical (Monospace)

    /// PIDs, IP addresses, paths, port numbers (11pt monospaced regular).
    static let nickMono      = Font.system(size: 11, weight: .regular, design: .monospaced)
    /// Timestamps and hashes (10pt monospaced regular).
    static let nickMonoSmall = Font.system(size: 10, weight: .regular, design: .monospaced)

    // MARK: - UI Elements

    /// Badge labels and status chips (10pt medium).
    static let nickCaption  = Font.system(size: 10, weight: .medium)
    /// Tab bar labels (12pt medium).
    static let nickTabLabel = Font.system(size: 12, weight: .medium)
    /// Buttons and actions (12pt semibold).
    static let nickButton   = Font.system(size: 12, weight: .semibold)
}
