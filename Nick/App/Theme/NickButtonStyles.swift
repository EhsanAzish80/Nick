// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import SwiftUI

// MARK: - NickPrimaryButtonStyle

/// Primary button style for main actions (e.g., "Scan Now", "Dismiss").
///
/// Renders with a `statusBlue` fill and `textInverse` label. Use for the single
/// most-important action in a given context. Do not use for destructive actions.
struct NickPrimaryButtonStyle: ButtonStyle {

    @Environment(\.isEnabled) private var isEnabled

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.nickButton)
            .foregroundStyle(Color.textInverse)
            .padding(.horizontal, NickSpacing.xl)
            .padding(.vertical, NickSpacing.md)
            .background(
                RoundedRectangle(cornerRadius: NickLayout.badgeCornerRadius)
                    .fill(Color.statusBlue.opacity(configuration.isPressed ? 0.7 : (isEnabled ? 1.0 : 0.4)))
            )
            .animation(.easeInOut(duration: 0.1), value: configuration.isPressed)
    }
}

// MARK: - NickSecondaryButtonStyle

/// Secondary button style for supporting actions (e.g., "Copy JSON", "Export").
///
/// Renders with a `backgroundTertiary` fill and `textSecondary` label.
/// Use when a primary button is already present in the same context.
struct NickSecondaryButtonStyle: ButtonStyle {

    @Environment(\.isEnabled) private var isEnabled

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.nickButton)
            .foregroundStyle(Color.textSecondary.opacity(isEnabled ? 1.0 : 0.5))
            .padding(.horizontal, NickSpacing.xl)
            .padding(.vertical, NickSpacing.md)
            .background(
                RoundedRectangle(cornerRadius: NickLayout.badgeCornerRadius)
                    .fill(Color.backgroundTertiary.opacity(configuration.isPressed ? 0.6 : 1.0))
            )
            .animation(.easeInOut(duration: 0.1), value: configuration.isPressed)
    }
}

// MARK: - ButtonStyle Extensions

extension ButtonStyle where Self == NickPrimaryButtonStyle {
    /// Nick primary button: blue fill, inverse text.
    static var nickPrimary: NickPrimaryButtonStyle { NickPrimaryButtonStyle() }
}

extension ButtonStyle where Self == NickSecondaryButtonStyle {
    /// Nick secondary button: tertiary fill, secondary text.
    static var nickSecondary: NickSecondaryButtonStyle { NickSecondaryButtonStyle() }
}

// MARK: - NickDestructiveButtonStyle

/// Destructive button style for irreversible actions (e.g., "Remove Helper", "Clear History").
///
/// Renders with a `statusRed` fill and `textInverse` label.
struct NickDestructiveButtonStyle: ButtonStyle {

    @Environment(\.isEnabled) private var isEnabled

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.nickButton)
            .foregroundStyle(Color.textInverse)
            .padding(.horizontal, NickSpacing.xl)
            .padding(.vertical, NickSpacing.md)
            .background(
                RoundedRectangle(cornerRadius: NickLayout.badgeCornerRadius)
                    .fill(Color.statusRed.opacity(configuration.isPressed ? 0.7 : (isEnabled ? 1.0 : 0.4)))
            )
            .animation(.easeInOut(duration: 0.1), value: configuration.isPressed)
    }
}

extension ButtonStyle where Self == NickDestructiveButtonStyle {
    /// Nick destructive button: red fill, inverse text.
    static var nickDestructive: NickDestructiveButtonStyle { NickDestructiveButtonStyle() }
}
