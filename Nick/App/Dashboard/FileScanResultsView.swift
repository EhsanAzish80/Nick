// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import SwiftUI

// MARK: - FileScanResultsView

/// Sheet shown after a manual YARA file or folder scan triggered from the
/// "Scan File…" button in the dashboard bottom bar (or via Finder Services).
///
/// Displays a ProgressView while the scan is running, a clean-bill-of-health
/// message when no matches are found, or a scrollable list of matched rules.
struct FileScanResultsView: View {

    let url: URL
    let results: [YARAMatch]
    let isScanning: Bool
    let error: String?

    @Environment(\.dismiss) private var dismiss

    var body: some View {
        VStack(spacing: 0) {
            header
            Rectangle()
                .fill(Color.borderSubtle)
                .frame(height: 0.5)
            body_content
        }
        .frame(width: NickLayout.windowWidth, height: 300)
        .background(Color.backgroundPrimary.ignoresSafeArea())
    }

    // MARK: - Header

    private var header: some View {
        HStack(spacing: NickSpacing.md) {
            VStack(alignment: .leading, spacing: NickSpacing.xs) {
                Text("YARA Scan Results")
                    .font(.nickBodyMedium)
                    .foregroundStyle(Color.textPrimary)
                Text(url.lastPathComponent)
                    .font(.nickCaption)
                    .foregroundStyle(Color.textSecondary)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }
            Spacer()
            Button(action: { dismiss() }) {
                Image(systemName: "xmark.circle.fill")
                    .font(.system(size: 16))
                    .foregroundStyle(Color.textTertiary)
            }
            .buttonStyle(.plain)
        }
        .padding(.horizontal, NickSpacing.lg)
        .frame(height: NickLayout.bottomBarHeight)
        .background(Color.backgroundSecondary)
    }

    // MARK: - Content

    @ViewBuilder
    private var body_content: some View {
        if isScanning {
            VStack(spacing: NickSpacing.lg) {
                ProgressView()
                    .controlSize(.regular)
                Text("Scanning…")
                    .font(.nickBody)
                    .foregroundStyle(Color.textSecondary)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        } else if let error {
            VStack(spacing: NickSpacing.md) {
                Image(systemName: "exclamationmark.triangle")
                    .font(.system(size: 28))
                    .foregroundStyle(Color.statusYellow)
                Text("Scan failed")
                    .font(.nickSubtitle)
                    .foregroundStyle(Color.textPrimary)
                Text(error)
                    .font(.nickCaption)
                    .foregroundStyle(Color.textSecondary)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal, NickSpacing.xl)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        } else if results.isEmpty {
            VStack(spacing: NickSpacing.md) {
                Image(systemName: "checkmark.shield.fill")
                    .font(.system(size: 32))
                    .foregroundStyle(Color.statusGreen)
                Text("No threats found")
                    .font(.nickSubtitle)
                    .foregroundStyle(Color.textPrimary)
                Text("No YARA rules matched in \(url.lastPathComponent).")
                    .font(.nickBodySmall)
                    .foregroundStyle(Color.textSecondary)
                    .multilineTextAlignment(.center)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        } else {
            ScrollView {
                LazyVStack(spacing: 0) {
                    ForEach(results, id: \.ruleName) { match in
                        MatchRow(match: match)
                        Rectangle()
                            .fill(Color.borderSubtle)
                            .frame(height: 0.5)
                    }
                }
            }
        }
    }
}

// MARK: - MatchRow

private struct MatchRow: View {

    let match: YARAMatch

    var body: some View {
        HStack(spacing: NickSpacing.md) {
            Image(systemName: "exclamationmark.triangle.fill")
                .foregroundStyle(Color.statusRed)
                .font(.system(size: 14))

            VStack(alignment: .leading, spacing: NickSpacing.xs) {
                Text(match.ruleName)
                    .font(.nickBodyMedium)
                    .foregroundStyle(Color.textPrimary)
                if !match.tags.isEmpty {
                    Text(match.tags.joined(separator: " · "))
                        .font(.nickCaption)
                        .foregroundStyle(Color.textSecondary)
                }
                Text((match.filePath as NSString).lastPathComponent)
                    .font(.nickMonoSmall)
                    .foregroundStyle(Color.textTertiary)
                    .lineLimit(1)
                    .truncationMode(.head)
            }

            Spacer()
        }
        .padding(.horizontal, NickSpacing.lg)
        .padding(.vertical, NickSpacing.md)
    }
}

// MARK: - Preview

#Preview {
    FileScanResultsView(
        url: URL(fileURLWithPath: "/Users/user/Downloads/sample.txt"),
        results: [],
        isScanning: false,
        error: nil
    )
    .environment(SecurityEngine())
}
