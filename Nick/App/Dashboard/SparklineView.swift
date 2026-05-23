// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import SwiftUI

// MARK: - SparklineView

/// Minimal line chart used inside monitor cards to show trend over recent scans.
///
/// Requires at least 2 data points to draw anything. When fewer than 2 values
/// are available (e.g. first launch), the view renders nothing — no placeholder
/// or fake data is shown.
struct SparklineView: View {

    let values: [Int]
    let color: Color

    var body: some View {
        GeometryReader { geo in
            if values.count >= 2 {
                let maxVal = max(values.max() ?? 1, 1)
                let minVal = values.min() ?? 0
                let range  = max(Double(maxVal - minVal), 1)

                Path { path in
                    for (index, value) in values.enumerated() {
                        let x = geo.size.width * CGFloat(index) / CGFloat(values.count - 1)
                        let y = geo.size.height * (1 - CGFloat(Double(value - minVal) / range))
                        if index == 0 {
                            path.move(to: CGPoint(x: x, y: y))
                        } else {
                            path.addLine(to: CGPoint(x: x, y: y))
                        }
                    }
                }
                .stroke(color.opacity(0.6), lineWidth: 1.5)
            }
            // Fewer than 2 values: render nothing (no fake data).
        }
    }
}
