// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import SwiftUI

// MARK: - ScanProgressView

/// Full-height overlay that replaces the tab content area while
/// `SecurityEngine.isScanning` is `true`.
struct ScanProgressView: View {

    // MARK: - Body

    var body: some View {
        VStack(alignment: .center, spacing: NickSpacing.md) {
            Spacer()
            ProgressView()
                .controlSize(.regular)
            Text("Scanning your system…")
                .font(.nickBodySmall)
                .foregroundStyle(Color.textSecondary)
            Text("It could usually take around a minute to complete.")
                .font(.nickBodySmall)
                .foregroundStyle(Color.textSecondary)
            Text("You can keep using your Mac while the scan is running.")
                .font(.nickBodySmall)
                .foregroundStyle(Color.textSecondary)
            Spacer()
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

}

// MARK: - Preview

#Preview {
    let engine = SecurityEngine()
    return ScanProgressView()
        .environment(engine)
        .frame(width: NickLayout.windowWidth, height: 400)
        .background(Color.backgroundPrimary)
        .preferredColorScheme(.dark)
}

