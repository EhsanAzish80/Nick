// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import SwiftUI

// MARK: - SystemHealthGauge

/// Displays the overall security health score (0–100) with a large numeric value,
/// a single-word status label, and a thin horizontal progress bar.
///
/// Replaces the earlier circular `Gauge` widget. The horizontal design fits the
/// fixed 420pt panel width and avoids animation idioms inappropriate for a
/// security-context tool (no spinning, no rotation).
///
/// Score ranges: 80–100 green (SECURE), 60–79 yellow (WARNING),
/// 40–59 orange (ELEVATED), 0–39 red (CRITICAL).
struct SystemHealthGauge: View {

    let score: Int
    let isScanning: Bool

    var body: some View {
        VStack(spacing: NickSpacing.sm) {
            // Score number + status label. No inline spinner — the tab bar
            // progress bar below the tab bar owns all scan feedback.
            HStack(alignment: .lastTextBaseline, spacing: NickSpacing.md) {
                Text("\(score)")
                    .font(.nickGaugeValue)
                    .foregroundStyle(gaugeColor)
                    .contentTransition(.numericText())
                    .animation(.spring(response: 0.4, dampingFraction: 0.8), value: score)

                Text(statusLabel)
                    .font(.nickCaption)
                    .foregroundStyle(Color.textSecondary)
                    .kerning(2)
                    .animation(.easeInOut(duration: 0.2), value: score)
            }
            // Thin horizontal progress bar
            GeometryReader { geo in
                ZStack(alignment: .leading) {
                    Rectangle()
                        .fill(Color.borderSubtle)
                        .frame(height: NickLayout.scoreBarHeight)
                    Rectangle()
                        .fill(gaugeColor)
                        .frame(
                            width: geo.size.width * CGFloat(score) / 100.0,
                            height: NickLayout.scoreBarHeight
                        )
                        .animation(.spring(response: 0.4, dampingFraction: 0.8), value: score)
                }
                .clipShape(Capsule())
            }
            .frame(height: NickLayout.scoreBarHeight)
        }
        .padding(.horizontal, NickSpacing.xl)
        .padding(.vertical, NickSpacing.lg)
    }

    // MARK: - Private

    private var gaugeColor: Color {
        switch score {
        case 80...100: .statusGreen
        case 60..<80:  .statusYellow
        case 40..<60:  .statusOrange
        default:       .statusRed
        }
    }

    private var statusLabel: String {
        switch score {
        case 80...100: "SECURE"
        case 60..<80:  "WARNING"
        case 40..<60:  "ELEVATED"
        default:       "CRITICAL"
        }
    }
}

// MARK: - Preview

#Preview("Health States") {
    VStack(spacing: 0) {
        SystemHealthGauge(score: 100, isScanning: false)
        Divider()
        SystemHealthGauge(score: 72,  isScanning: false)
        Divider()
        SystemHealthGauge(score: 45,  isScanning: false)
        Divider()
        SystemHealthGauge(score: 20,  isScanning: false)
        Divider()
        SystemHealthGauge(score: 0,   isScanning: true)
    }
    .frame(width: NickLayout.windowWidth)
    .background(Color.backgroundPrimary)
}
