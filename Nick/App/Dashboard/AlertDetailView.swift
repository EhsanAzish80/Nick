// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import SwiftUI

// MARK: - AlertDetailView

/// Full-detail sheet for a single `ThreatAlert`.
///
/// Shows severity badge, confidence score, timestamp, description, contributing
/// signals in a nested card, and "Copy JSON" / "Dismiss" action buttons.
/// Uses Nick design tokens throughout — no hardcoded fonts, colors, or spacing.
struct AlertDetailView: View {

    let alert: ThreatAlert
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header
            Rectangle()
                .fill(Color.borderSubtle)
                .frame(height: 0.5)
            ScrollView {
                VStack(alignment: .leading, spacing: NickSpacing.xl) {
                    descriptionSection
                    if !alert.contributingSignals.isEmpty {
                        signalsSection
                    }
                    if let explanation = alert.explanation {
                        explanationSection(explanation)
                    }
                    actionSection
                }
                .padding(NickSpacing.xl)
            }
            Rectangle()
                .fill(Color.borderSubtle)
                .frame(height: 0.5)
            footer
        }
        .frame(width: NickLayout.windowWidth, height: 540)
        .background(Color.backgroundPrimary)
    }

    // MARK: - Header

    private var header: some View {
        HStack(alignment: .top, spacing: NickSpacing.md) {
            VStack(alignment: .leading, spacing: NickSpacing.sm) {
                Text(alert.title)
                    .font(.nickTitle)
                    .foregroundStyle(Color.textPrimary)
                    .lineLimit(2)
                    .fixedSize(horizontal: false, vertical: true)

                HStack(spacing: NickSpacing.md) {
                    SeverityBadge(severity: alert.severity)
                    Text(String(format: "Confidence: %.0f%%", alert.score * 100))
                        .font(.nickMono)
                        .foregroundStyle(Color.textSecondary)
                    Spacer()
                    Text(alert.timestamp.formatted(date: .abbreviated, time: .shortened))
                        .font(.nickMonoSmall)
                        .foregroundStyle(Color.textTertiary)
                }
            }

            Button { dismiss() } label: {
                Image(systemName: "xmark.circle.fill")
                    .font(.system(size: NickLayout.iconSizeLarge))
                    .foregroundStyle(Color.textTertiary)
            }
            .buttonStyle(.plain)
        }
        .padding(NickSpacing.xl)
        .background(Color.backgroundSecondary)
    }

    // MARK: - Description

    private var descriptionSection: some View {
        VStack(alignment: .leading, spacing: NickSpacing.sm) {
            Text("Description")
                .font(.nickSubtitle)
                .foregroundStyle(Color.textSecondary)
            Text(alert.description)
                .font(.nickBody)
                .foregroundStyle(Color.textPrimary)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    // MARK: - Signals

    private var signalsSection: some View {
        VStack(alignment: .leading, spacing: NickSpacing.sm) {
            Text("Contributing Signals")
                .font(.nickSubtitle)
                .foregroundStyle(Color.textSecondary)

            VStack(alignment: .leading, spacing: 0) {
                ForEach(alert.contributingSignals) { signal in
                    HStack(alignment: .top, spacing: NickSpacing.md) {
                        Image(systemName: signal.source.systemImage)
                            .font(.system(size: NickLayout.iconSize))
                            .foregroundStyle(Color.textTertiary)
                            .frame(width: NickLayout.iconSizeLarge)
                        VStack(alignment: .leading, spacing: NickSpacing.xs) {
                            Text(signal.title)
                                .font(.nickBodyMedium)
                                .foregroundStyle(Color.textPrimary)
                            Text(signal.description)
                                .font(.nickBodySmall)
                                .foregroundStyle(Color.textSecondary)
                                .lineLimit(2)
                        }
                    }
                    .padding(.vertical, NickSpacing.md)
                    .padding(.horizontal, NickSpacing.lg)
                    if signal.id != alert.contributingSignals.last?.id {
                        Divider().padding(.leading, NickLayout.separatorInset)
                    }
                }
            }
            .background(Color.backgroundTertiary, in: RoundedRectangle(cornerRadius: NickLayout.cardCornerRadius))
        }
    }

    // MARK: - AI Explanation

    private func explanationSection(_ text: String) -> some View {
        VStack(alignment: .leading, spacing: NickSpacing.sm) {
            Text("AI Analysis")
                .font(.nickSubtitle)
                .foregroundStyle(Color.textSecondary)
            Text(text)
                .font(.nickBody)
                .foregroundStyle(Color.textPrimary)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    // MARK: - Recommended Action

    private var actionSection: some View {
        HStack(alignment: .top, spacing: NickSpacing.md) {
            Image(systemName: "lightbulb")
                .font(.system(size: NickLayout.iconSize))
                .foregroundStyle(Color.statusYellow)
                .frame(width: NickLayout.iconSizeLarge)
            VStack(alignment: .leading, spacing: NickSpacing.xs) {
                Text("Recommended Action")
                    .font(.nickSubtitle)
                    .foregroundStyle(Color.textSecondary)
                Text(alert.recommendedAction)
                    .font(.nickBody)
                    .foregroundStyle(Color.textPrimary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .padding(NickSpacing.lg)
        .background(Color.statusYellowBg, in: RoundedRectangle(cornerRadius: NickLayout.cardCornerRadius))
    }

    // MARK: - Footer

    private var footer: some View {
        HStack {
            Button("Copy JSON") { copyJSON() }
                .buttonStyle(.nickSecondary)
            Spacer()
            Button("Dismiss") { dismiss() }
                .buttonStyle(.nickPrimary)
        }
        .padding(.horizontal, NickSpacing.xl)
        .padding(.vertical, NickSpacing.md)
        .background(Color.backgroundSecondary)
    }

    // MARK: - Private Helpers

    private func copyJSON() {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        guard let data = try? encoder.encode(alert),
              let string = String(data: data, encoding: .utf8)
        else { return }
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(string, forType: .string)
    }
}

// MARK: - SignalRow (internal helper)

private struct SignalRow: View {
    let signal: ThreatSignal

    var body: some View {
        HStack(alignment: .top, spacing: NickSpacing.md) {
            Image(systemName: signal.source.systemImage)
                .font(.system(size: NickLayout.iconSize))
                .foregroundStyle(Color.textTertiary)
                .frame(width: NickLayout.iconSizeLarge)
            VStack(alignment: .leading, spacing: NickSpacing.xs) {
                Text(signal.title)
                    .font(.nickBodyMedium)
                    .foregroundStyle(Color.textPrimary)
                Text(signal.description)
                    .font(.nickBodySmall)
                    .foregroundStyle(Color.textSecondary)
                    .lineLimit(2)
            }
        }
    }
}

// MARK: - Preview

#Preview {
    AlertDetailView(alert: ThreatAlert(
        score: 0.91,
        title: "Reverse shell detected",
        description: "A shell process has established an outbound TCP connection.",
        severity: .critical,
        contributingSignals: [],
        recommendedAction: "Terminate the process and investigate its parent chain."
    ))
}

