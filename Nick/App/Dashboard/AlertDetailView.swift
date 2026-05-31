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

    // Phase 4: simple/technical mode
    @AppStorage("simpleAlertMode") private var simpleAlertMode: Bool = true
    @State private var showTechnicalDetails: Bool = false

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            if simpleAlertMode {
                simpleHeader
            } else {
                header
            }
            Rectangle()
                .fill(Color.borderSubtle)
                .frame(height: 0.5)
            ScrollView {
                if simpleAlertMode {
                    simpleContent
                } else {
                    VStack(alignment: .leading, spacing: NickSpacing.xl) {
                        descriptionSection
                        if !alert.contributingSignals.isEmpty {
                            signalsSection
                        }
                        actionSection
                    }
                    .padding(NickSpacing.xl)
                }
            }
            Rectangle()
                .fill(Color.borderSubtle)
                .frame(height: 0.5)
            footer
        }
        .frame(width: NickLayout.windowWidth, height: 540)
        .background(Color.backgroundPrimary)
    }

    // MARK: - Simple Mode Header

    private var simpleHeader: some View {
        let userAlert = UserFacingAlertBuilder.shared.build(from: alert)
        return HStack(alignment: .top, spacing: NickSpacing.md) {
            // Severity icon
            ZStack {
                RoundedRectangle(cornerRadius: 10, style: .continuous)
                    .fill(simpleIconColor(userAlert.severity))
                    .frame(width: 40, height: 40)
                Image(systemName: simpleIconName(userAlert.severity))
                    .font(.system(size: 18, weight: .semibold))
                    .foregroundStyle(.white)
            }

            VStack(alignment: .leading, spacing: NickSpacing.xs) {
                Text(userAlert.headline)
                    .font(.nickTitle)
                    .foregroundStyle(Color.textPrimary)
                    .lineLimit(2)
                    .fixedSize(horizontal: false, vertical: true)
                Text(alert.timestamp.formatted(date: .abbreviated, time: .shortened))
                    .font(.nickMonoSmall)
                    .foregroundStyle(Color.textTertiary)
            }

            Spacer()

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

    // MARK: - Simple Mode Content

    private var simpleContent: some View {
        let userAlert = UserFacingAlertBuilder.shared.build(from: alert)
        return VStack(alignment: .leading, spacing: NickSpacing.xl) {

            // Plain-English explanation
            Text(userAlert.explanation)
                .font(.nickBody)
                .foregroundStyle(Color.textPrimary)
                .fixedSize(horizontal: false, vertical: true)

            // Recommended action (plain English from the alert, not the tech detail)
            HStack(alignment: .top, spacing: NickSpacing.md) {
                Image(systemName: "lightbulb")
                    .font(.system(size: NickLayout.iconSize))
                    .foregroundStyle(Color.statusYellow)
                    .frame(width: NickLayout.iconSizeLarge)
                Text(alert.recommendedAction)
                    .font(.nickBody)
                    .foregroundStyle(Color.textPrimary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .padding(NickSpacing.lg)
            .background(Color.statusYellowBg, in: RoundedRectangle(cornerRadius: NickLayout.cardCornerRadius))

            // Technical detail disclosure — paths/PIDs hidden until expanded
            DisclosureGroup(
                isExpanded: $showTechnicalDetails,
                content: {
                    VStack(alignment: .leading, spacing: NickSpacing.md) {
                        // Score + severity
                        HStack(spacing: NickSpacing.md) {
                            SeverityBadge(severity: alert.severity)
                            Text(String(format: "Confidence: %.0f%%", alert.score * 100))
                                .font(.nickMono)
                                .foregroundStyle(Color.textSecondary)
                        }
                        .padding(.top, NickSpacing.xs)

                        // Technical description
                        Text(alert.explanation ?? alert.description)
                            .font(.nickBodySmall)
                            .foregroundStyle(Color.textSecondary)
                            .fixedSize(horizontal: false, vertical: true)

                        // Contributing signals with paths + PIDs
                        if !alert.contributingSignals.isEmpty {
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
                                            let displayPath = signal.metadata["script_path"]
                                                ?? signal.metadata["path"]
                                                ?? signal.processInfo?.path
                                            if let path = displayPath, !path.isEmpty {
                                                Text(path)
                                                    .font(.nickMono)
                                                    .foregroundStyle(Color.textTertiary)
                                                    .lineLimit(1)
                                                    .truncationMode(.middle)
                                            }
                                            if let pid = signal.processInfo?.pid {
                                                Text("PID \(pid)")
                                                    .font(.nickMonoSmall)
                                                    .foregroundStyle(Color.textTertiary)
                                            }
                                        }
                                    }
                                    .padding(.vertical, NickSpacing.md)
                                    .padding(.horizontal, NickSpacing.lg)
                                    if signal.id != alert.contributingSignals.last?.id {
                                        Divider().padding(.leading, NickLayout.separatorInset)
                                    }
                                }
                            }
                            .background(
                                Color.backgroundTertiary,
                                in: RoundedRectangle(cornerRadius: NickLayout.cardCornerRadius)
                            )
                        }
                    }
                },
                label: {
                    Label(showTechnicalDetails ? "Hide Technical Details" : "Show Technical Details",
                          systemImage: "chevron.right.circle")
                        .font(.nickBodyMedium)
                        .foregroundStyle(Color.textSecondary)
                }
            )
        }
        .padding(NickSpacing.xl)
    }

    // MARK: - Simple Mode Icon Helpers

    private func simpleIconName(_ severity: UserFacingAlert.AlertSeverity) -> String {
        switch severity {
        case .critical: return "exclamationmark.triangle.fill"
        case .warning:  return "exclamationmark.circle.fill"
        case .safe:     return "checkmark.shield.fill"
        }
    }

    private func simpleIconColor(_ severity: UserFacingAlert.AlertSeverity) -> Color {
        switch severity {
        case .critical: return Color.statusRed
        case .warning:  return Color.statusOrange
        case .safe:     return Color.statusGreen
        }
    }

    // MARK: - Technical Mode Header
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
            // Prefer the Foundation Models explanation — it's tailored to the specific
            // threat. Fall back to the generic rule description if not yet generated.
            Text(alert.explanation ?? alert.description)
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
                            // Show the concrete file path so the user knows exactly
                            // which file to investigate.
                            let displayPath = signal.metadata["script_path"]
                                ?? signal.metadata["path"]
                                ?? signal.processInfo?.path
                            if let path = displayPath, !path.isEmpty {
                                Text(path)
                                    .font(.nickMono)
                                    .foregroundStyle(Color.textTertiary)
                                    .lineLimit(1)
                                    .truncationMode(.middle)
                            }
                            if let pid = signal.processInfo?.pid {
                                Text("PID \(pid)")
                                    .font(.nickMonoSmall)
                                    .foregroundStyle(Color.textTertiary)
                            }
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
        HStack(spacing: NickSpacing.md) {
            // Kill Process — only shown when the process is still alive.
            if let pid = alert.contributingSignals.first?.processInfo?.pid,
               ProcessScanner.isRunning(pid: pid) {
                Button {
                    kill(pid, SIGTERM)
                } label: {
                    Label("Kill Process", systemImage: "xmark.circle")
                        .font(.nickButton)
                }
                .buttonStyle(.nickDestructive)
            }

            // Show in Finder — resolves script_path first, then process path.
            let finderPath = alert.contributingSignals.first?.metadata["script_path"]
                ?? alert.contributingSignals.first?.processInfo?.path
            if let path = finderPath, !path.isEmpty {
                Button {
                    NSWorkspace.shared.selectFile(path, inFileViewerRootedAtPath: "")
                } label: {
                    Label("Show in Finder", systemImage: "folder")
                        .font(.nickButton)
                }
                .buttonStyle(.nickSecondary)
            }

            Spacer()

            Button("Copy JSON") { copyJSON() }
                .buttonStyle(.nickSecondary)
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
        content: AlertContent(
            title: "Reverse shell detected",
            description: "A shell process has established an outbound TCP connection.",
            severity: .critical,
            recommendedAction: "Terminate the process and investigate its parent chain."
        ),
        contributingSignals: []
    ))
}

