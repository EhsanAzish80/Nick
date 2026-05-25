// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import SwiftUI

// MARK: - IconTile

/// Rounded-square gradient app-icon-style badge.
///
/// Generates a gradient-filled tile with a white SF Symbol centered inside it,
/// with a soft drop shadow and an inset highlight overlay — all in code, no
/// raster assets needed.
///
/// Usage:
/// ```swift
/// IconTile(systemImage: "checkmark.shield.fill", tint: .green)
/// IconTile(systemImage: "network", tint: .blue, size: 48)
/// ```
struct IconTile: View {

    let systemImage: String
    let tint: Color
    var size: CGFloat = 36

    private var cornerRadius: CGFloat { size * 0.25 }
    private var symbolSize: CGFloat   { size * 0.5 }

    var body: some View {
        ZStack {
            // Gradient fill: light-tint top → tint bottom
            RoundedRectangle(cornerRadius: cornerRadius, style: .continuous)
                .fill(
                    LinearGradient(
                        colors: [tint.opacity(0.75), tint],
                        startPoint: .top,
                        endPoint: .bottom
                    )
                )

            // Inset highlight: bright top stroke, subtle bottom shade
            RoundedRectangle(cornerRadius: cornerRadius, style: .continuous)
                .strokeBorder(
                    LinearGradient(
                        colors: [
                            Color.white.opacity(0.35),
                            Color.black.opacity(0.10)
                        ],
                        startPoint: .top,
                        endPoint: .bottom
                    ),
                    lineWidth: 1
                )

            // White SF Symbol
            Image(systemName: systemImage)
                .font(.system(size: symbolSize, weight: .semibold))
                .foregroundStyle(Color.white)
        }
        .frame(width: size, height: size)
    }
}

// MARK: - StatusDot

/// A small colored dot indicating a status kind.
///
/// Kinds:
/// - `.ok`      — green (all clear, enabled, verified)
/// - `.warn`    — orange (needs attention)
/// - `.bad`     — red (critical, broken)
/// - `.neutral` — gray (disabled, unknown, informational)
struct StatusDot: View {

    enum Kind {
        case ok, warn, bad, neutral

        var color: Color {
            switch self {
            case .ok:      return .statusGreen
            case .warn:    return .statusOrange
            case .bad:     return .statusRed
            case .neutral: return .textTertiary
            }
        }
    }

    let kind: Kind
    var diameter: CGFloat = 7

    var body: some View {
        Circle()
            .fill(kind.color)
            .frame(width: diameter, height: diameter)
    }
}

// MARK: - StatusText

/// A `StatusDot` paired with a text label — used in list row trailing values.
struct StatusText: View {

    let kind: StatusDot.Kind
    let label: String

    var body: some View {
        HStack(spacing: 5) {
            StatusDot(kind: kind)
            Text(label)
                .font(.nickBodySmall)
                .foregroundStyle(kind.color)
        }
    }
}

// MARK: - Preview

#if DEBUG
#Preview {
    VStack(spacing: 20) {
        HStack(spacing: 12) {
            IconTile(systemImage: "checkmark.shield.fill", tint: .green)
            IconTile(systemImage: "checkmark.shield.fill", tint: .blue)
            IconTile(systemImage: "network", tint: .blue)
            IconTile(systemImage: "cpu", tint: .purple)
            IconTile(systemImage: "arrow.triangle.2.circlepath", tint: .orange)
            IconTile(systemImage: "exclamationmark.triangle.fill", tint: .red)
            IconTile(systemImage: "doc.text.magnifyingglass", tint: .gray)
        }
        HStack(spacing: 12) {
            IconTile(systemImage: "checkmark.shield.fill", tint: .green, size: 72)
        }
        HStack(spacing: 16) {
            StatusText(kind: .ok,      label: "All clear")
            StatusText(kind: .warn,    label: "1 issue")
            StatusText(kind: .bad,     label: "Broken")
            StatusText(kind: .neutral, label: "Disabled")
        }
    }
    .padding()
    .background(Color.backgroundPrimary)
}
#endif
