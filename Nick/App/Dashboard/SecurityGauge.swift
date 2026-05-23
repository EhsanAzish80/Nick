// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import SwiftUI

// MARK: - SecurityGauge

/// Circular arc gauge displaying the security health score (0–100).
///
/// The arc colour and label ("PROTECTED" / "WARNING" / "AT RISK") respond
/// to the score range. The outer glow is a static blurred circle — not
/// animated and not pulsing.
struct SecurityGauge: View {

    let score: Int

    // MARK: - Derived

    private var color: Color {
        switch score {
        case 80...100: return .statusGreen
        case 60..<80:  return .statusYellow
        case 40..<60:  return .statusOrange
        default:       return .statusRed
        }
    }

    private var statusLabel: String {
        switch score {
        case 80...100: return "PROTECTED"
        case 40..<80:  return "WARNING"
        default:       return "AT RISK"
        }
    }

    // MARK: - Body

    var body: some View {
        ZStack {
            // Outer glow — static blurred circle, not animated.
            Circle()
                .stroke(color.opacity(0.15), lineWidth: 20)
                .frame(width: 180, height: 180)
                .blur(radius: 15)

            // Track ring.
            Circle()
                .stroke(Color.backgroundTertiary, lineWidth: 6)
                .frame(width: 160, height: 160)

            // Progress arc — starts at 12 o'clock, sweeps clockwise.
            Circle()
                .trim(from: 0, to: CGFloat(score) / 100)
                .stroke(color, style: StrokeStyle(lineWidth: 6, lineCap: .round))
                .frame(width: 160, height: 160)
                .rotationEffect(.degrees(-90))
                .animation(.easeInOut(duration: 0.4), value: score)

            // Inner content.
            VStack(spacing: 4) {
                Text(statusLabel)
                    .font(.system(size: 9, weight: .bold))
                    .tracking(2)
                    .foregroundStyle(color)

                Text("\(score)")
                    .font(.system(size: 56, weight: .bold, design: .rounded))
                    .foregroundStyle(color)
                    .contentTransition(.numericText())
                    .animation(.easeInOut(duration: 0.4), value: score)

                Text("SECURITY SCORE")
                    .font(.system(size: 9, weight: .medium))
                    .tracking(1.5)
                    .foregroundStyle(Color.textTertiary)
            }
        }
        .frame(width: 200, height: 200)
    }
}

// MARK: - Previews

#Preview("Protected") { SecurityGauge(score: 95).padding().preferredColorScheme(.dark) }
#Preview("Warning")   { SecurityGauge(score: 68).padding().preferredColorScheme(.dark) }
#Preview("At Risk")   { SecurityGauge(score: 28).padding().preferredColorScheme(.dark) }
