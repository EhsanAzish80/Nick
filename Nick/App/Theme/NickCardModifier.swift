// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import SwiftUI

// MARK: - NickCardModifier

/// View modifier that applies the Nick card visual treatment.
///
/// Cards use `backgroundSecondary` fill, `cardCornerRadius` rounding,
/// and a `borderSubtle` stroke. Use for any grouped section of related
/// content — audit results, signal lists, connection groups.
///
/// Apply via the `.nickCard()` convenience modifier rather than calling
/// `modifier(NickCardModifier())` directly.
struct NickCardModifier: ViewModifier {

    func body(content: Content) -> some View {
        content
            .background(
                RoundedRectangle(cornerRadius: NickLayout.cardCornerRadius)
                    .fill(Color.backgroundSecondary)
                    .overlay(
                        RoundedRectangle(cornerRadius: NickLayout.cardCornerRadius)
                            .strokeBorder(Color.borderSubtle, lineWidth: 0.5)
                    )
            )
    }
}

// MARK: - NickElevatedCardModifier

/// Elevated card variant for modals and alert detail views.
///
/// Uses `backgroundElevated` fill with a subtle drop shadow to communicate
/// visual layering. The shadow replaces the border stroke.
struct NickElevatedCardModifier: ViewModifier {

    func body(content: Content) -> some View {
        content
            .background(Color.backgroundElevated)
            .clipShape(RoundedRectangle(cornerRadius: NickLayout.cardCornerRadius))
            .shadow(color: .black.opacity(0.35), radius: 10, x: 0, y: 3)
    }
}

// MARK: - View Extensions

extension View {

    /// Applies the standard Nick card background (secondary fill + subtle border).
    func nickCard() -> some View {
        modifier(NickCardModifier())
    }

    /// Applies the elevated Nick card background (elevated fill + drop shadow).
    func nickElevatedCard() -> some View {
        modifier(NickElevatedCardModifier())
    }
}
