// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import SwiftUI

// MARK: - FileScanResultsView

/// Sheet shown after a manual YARA file or folder scan triggered from the
/// "Scan File…" button in the dashboard bottom bar (or via Finder Services).
///
/// Four states:
/// 1. **Scanning** — indeterminate progress while the YARA engine runs.
/// 2. **Clean** — shield icon + file metadata when no rules match.
/// 3. **Matches** — threat list + severity badges + file metadata.
/// 4. **Error** — failure description with an actionable hint for the
///    common "no rules bundled" case.
struct FileScanResultsView: View {

    let url:        URL
    let results:    [YARAMatch]
    let isScanning: Bool
    let error:      String?
    let summary:    FileScanSummary?
    let duration:   TimeInterval

    @Environment(\.dismiss) private var dismiss
    @State private var rulesCount: Int = 0

    var body: some View {
        VStack(spacing: 0) {
            header
            Rectangle()
                .fill(Color.borderSubtle)
                .frame(height: 0.5)
            ScrollView {
                VStack(spacing: 0) {
                    stateContent
                        .frame(minHeight: 200)
                    if !isScanning, let info = summary {
                            fileInfoBox(info)
                                .padding(.horizontal, NickSpacing.lg)
                                .padding(.bottom, NickSpacing.lg)
                    }
                }
            }
        }
        .frame(width: NickLayout.windowWidth)
        .background(Color.backgroundPrimary.ignoresSafeArea())
        .task {
            let dir = Bundle.main.resourceURL?
                .appendingPathComponent("Rules/community").path ?? ""
            rulesCount = await Task.detached {
                FileScanSummary.countRules(inDirectory: dir)
            }.value
        }
    }

    // MARK: - Header

    private var header: some View {
        HStack(alignment: .center, spacing: NickSpacing.md) {
            VStack(alignment: .leading, spacing: NickSpacing.xs) {
                Text("Nick Scan")
                    .font(.nickBodyMedium)
                    .foregroundStyle(Color.textPrimary)
                Text("Powered by YARA")
                    .font(.nickCaption)
                    .foregroundStyle(Color.textTertiary)
            }
            Spacer()
            Button(action: { dismiss() }) {
                Image(systemName: "xmark.circle.fill")
                    .font(.system(size: NickLayout.iconSize))
                    .foregroundStyle(Color.textTertiary)
            }
            .buttonStyle(.plain)
        }
        .padding(.horizontal, NickSpacing.lg)
        .frame(minHeight: NickLayout.rowHeight)
        .background(Color.backgroundSecondary)
    }

    // MARK: - State Router

    @ViewBuilder
    private var stateContent: some View {
        if isScanning {
            scanningState
        } else if let err = error {
            errorState(err)
        } else if results.isEmpty {
            cleanState
        } else {
            matchesState
        }
    }

    // MARK: Scanning

    private var scanningState: some View {
        VStack(spacing: NickSpacing.lg) {
            ProgressView()
                .controlSize(.regular)
            Text("Scanning \(url.lastPathComponent)…")
                .font(.nickBodySmall)
                .foregroundStyle(Color.textSecondary)
                .lineLimit(2)
                .multilineTextAlignment(.center)
                .padding(.horizontal, NickSpacing.xxl)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, NickSpacing.xxl)
    }

    // MARK: Clean

    private var cleanState: some View {
        VStack(spacing: NickSpacing.md) {
            Image(systemName: "checkmark.shield.fill")
                .font(.system(size: 32))
                .foregroundStyle(Color.statusGreen)
            Text("No threats detected")
                .font(.nickSubtitle)
                .foregroundStyle(Color.textPrimary)
            Text(url.lastPathComponent)
                .font(.nickBodySmall)
                .foregroundStyle(Color.textSecondary)
                .lineLimit(1)
                .truncationMode(.middle)
            statsLine
        }
        .frame(maxWidth: .infinity)
        .padding(.horizontal, NickSpacing.lg)
        .padding(.vertical, NickSpacing.xxl)
    }

    // MARK: Matches

    private var matchesState: some View {
        VStack(spacing: 0) {
            // Summary header
            VStack(spacing: NickSpacing.md) {
                Image(systemName: "exclamationmark.triangle.fill")
                    .font(.system(size: 32))
                    .foregroundStyle(Color.statusRed)
                Text("\(results.count) threat\(results.count == 1 ? "" : "s") detected")
                    .font(.nickSubtitle)
                    .foregroundStyle(Color.textPrimary)
                Text(url.lastPathComponent)
                    .font(.nickBodySmall)
                    .foregroundStyle(Color.textSecondary)
                    .lineLimit(1)
                    .truncationMode(.middle)
                statsLine
            }
            .frame(maxWidth: .infinity)
            .padding(.horizontal, NickSpacing.lg)
            .padding(.vertical, NickSpacing.xl)

            Rectangle()
                .fill(Color.borderSubtle)
                .frame(height: 0.5)

            // Match list
            VStack(spacing: 0) {
                ForEach(results, id: \.ruleName) { match in
                    MatchRow(match: match)
                    Rectangle()
                        .fill(Color.borderSubtle)
                        .frame(height: 0.5)
                        .padding(.leading, NickSpacing.lg)
                }
            }
            .padding(.bottom, NickSpacing.md)
        }
    }

    // MARK: Error

    private func errorState(_ message: String) -> some View {
        let isRulesError = message.localizedCaseInsensitiveContains("No YARA rules") ||
                           message.localizedCaseInsensitiveContains("noRulesCompiled")
        return VStack(spacing: NickSpacing.md) {
            Image(systemName: "xmark.circle")
                .font(.system(size: 32))
                .foregroundStyle(Color.statusRed)
            Text("Scan failed")
                .font(.nickSubtitle)
                .foregroundStyle(Color.textPrimary)
            Text(message)
                .font(.nickBodySmall)
                .foregroundStyle(Color.textSecondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal, NickSpacing.xxl)
            if isRulesError {
                Text("This usually means the YARA rules were not bundled correctly. Try reinstalling Nick.")
                    .font(.nickCaption)
                    .foregroundStyle(Color.textTertiary)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal, NickSpacing.xxl)
            }
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, NickSpacing.xxl)
    }

    // MARK: - Stats Line

    private var statsLine: some View {
        HStack(spacing: NickSpacing.sm) {
            if rulesCount > 0 {
                Text("\(rulesCount) rules")
                    .font(.nickCaption)
                    .foregroundStyle(Color.textTertiary)
                Text("·")
                    .font(.nickCaption)
                    .foregroundStyle(Color.textTertiary)
            }
            Text(durationText)
                .font(.nickCaption)
                .foregroundStyle(Color.textTertiary)
        }
    }

    private var durationText: String {
        if duration < 0.1 { return "< 0.1s" }
        if duration < 1 { return String(format: "%.1fs", duration) }
        return String(format: "%.0fs", duration)
    }

    // MARK: - File Info Box

    private func fileInfoBox(_ info: FileScanSummary) -> some View {
        VStack(alignment: .leading, spacing: NickSpacing.sm) {
            Text("FILE INFO")
                .font(.nickCaption)
                .foregroundStyle(Color.textTertiary)
            VStack(spacing: 0) {
                infoRow(label: "Size",    value: info.formattedSize)
                Divider()
                infoRow(label: "Type",    value: info.fileType)
                Divider()
                infoRow(label: "Entropy",
                        value: String(format: "%.2f  —  %@", info.entropy, info.entropyLabel))
                Divider()
                infoRow(label: "Signed",  value: info.signatureInfo)
            }
            .background(Color.backgroundTertiary)
            .clipShape(RoundedRectangle(cornerRadius: NickLayout.cardCornerRadius))
        }
    }

    private func infoRow(label: String, value: String) -> some View {
        HStack(alignment: .top) {
            Text(label)
                .font(.nickBodySmall)
                .foregroundStyle(Color.textSecondary)
            Spacer()
            Text(value)
                .font(.nickMono)
                .foregroundStyle(Color.textPrimary)
                .multilineTextAlignment(.trailing)
        }
        .padding(.horizontal, NickLayout.cardPadding)
        .padding(.vertical, NickSpacing.sm)
    }
}

// MARK: - MatchRow

private struct MatchRow: View {

    let match: YARAMatch

    var body: some View {
        HStack(alignment: .top, spacing: NickSpacing.sm) {
            Text("▸")
                .font(.nickBodySmall)
                .foregroundStyle(Color.statusRed)
                .padding(.top, 1)
            VStack(alignment: .leading, spacing: NickSpacing.xs) {
                HStack(spacing: NickSpacing.sm) {
                    Text(match.ruleName)
                        .font(.nickBodyMedium)
                        .foregroundStyle(Color.textPrimary)
                    Spacer()
                    if let sev = match.metadata["severity"] {
                        YARASeverityBadge(severity: sev)
                    }
                }
                if let desc = match.metadata["description"] {
                    Text(desc)
                        .font(.nickBodySmall)
                        .foregroundStyle(Color.textSecondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
        }
        .padding(.horizontal, NickSpacing.lg)
        .padding(.vertical, NickSpacing.md)
    }
}

// MARK: - YARASeverityBadge

private struct YARASeverityBadge: View {

    let severity: String

    var body: some View {
        Text(severity)
            .font(.nickCaption)
            .foregroundStyle(badgeColor)
            .padding(.horizontal, NickSpacing.lg / 2)
            .padding(.vertical, NickSpacing.xs)
            .background(badgeColor.opacity(0.12))
            .clipShape(RoundedRectangle(cornerRadius: NickLayout.badgeCornerRadius))
    }

    private var badgeColor: Color {
        switch severity.uppercased() {
        case "HIGH":   return .statusRed
        case "MEDIUM": return .statusYellow
        case "LOW":    return .statusGreen
        default:       return .textTertiary
        }
    }
}

// MARK: - Preview

#Preview("Scanning") {
    FileScanResultsView(
        url: URL(fileURLWithPath: "/Users/user/Downloads/malware.app"),
        results: [],
        isScanning: true,
        error: nil,
        summary: nil,
        duration: 0
    )
}

#Preview("Clean") {
    FileScanResultsView(
        url: URL(fileURLWithPath: "/bin/ls"),
        results: [],
        isScanning: false,
        error: nil,
        summary: FileScanSummary(
            fileSize: 49_152,
            fileType: "Unix Executable",
            entropy: 5.8,
            isSigned: true,
            signatureInfo: "Yes (Software Signing)"
        ),
        duration: 0.34
    )
}

#Preview("Error — No Rules") {
    FileScanResultsView(
        url: URL(fileURLWithPath: "/tmp/sample.bin"),
        results: [],
        isScanning: false,
        error: "No YARA rules were compiled — rules directory is empty or contains no valid .yar files.",
        summary: nil,
        duration: 0.01
    )
}

