// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import SwiftUI

// MARK: - SystemHealthGauge

/// Circular gauge that communicates the overall security health score (0–100).
///
/// The ring colour transitions from green (≥ 80) through yellow (50–79)
/// to red (< 50), giving the user an at-a-glance risk level.
struct SystemHealthGauge: View {

    let score: Int
    let isScanning: Bool

    var body: some View {
        Gauge(value: Double(score), in: 0...100) {
            EmptyView()
        } currentValueLabel: {
            if isScanning {
                ProgressView().controlSize(.small)
            } else {
                Text("\(score)")
                    .font(.system(size: 18, weight: .bold, design: .rounded))
                    .foregroundStyle(gaugeColor)
            }
        }
        .gaugeStyle(.accessoryCircular)
        .tint(gaugeColor)
        .animation(.easeInOut(duration: 0.5), value: score)
    }

    private var gaugeColor: Color {
        switch score {
        case 80...100: .green
        case 50..<80:  .yellow
        default:       .red
        }
    }
}

// MARK: - Preview

#Preview {
    HStack(spacing: 24) {
        SystemHealthGauge(score: 100, isScanning: false)
        SystemHealthGauge(score: 65,  isScanning: false)
        SystemHealthGauge(score: 30,  isScanning: false)
        SystemHealthGauge(score: 50,  isScanning: true)
    }
    .padding()
}
