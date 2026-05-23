// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import SwiftUI

// MARK: - DeepScanView

/// Full-system YARA scan window opened when the user taps "Deep Scan".
///
/// Three sequential states driven by `DeepScanner`:
/// 1. **Confirmation** — description, time estimate, power toggle, Start/Cancel.
/// 2. **Progress** — percentage, file counter, progress bar, current path, timing.
/// 3. **Results** — clean summary or threat list matching the Nick Scan format.
struct DeepScanWindowView: View {

    @Environment(SecurityEngine.self) private var engine
    @Environment(\.dismiss) private var dismiss

    @State private var scanner      = DeepScanner()
    @State private var hasStarted   = false
    @State private var onlyOnPower  = false

    // MARK: - Phase

    private enum Phase { case confirmation, scanning, paused, results }

    private var phase: Phase {
        guard hasStarted else { return .confirmation }
        if scanner.isPaused   { return .paused   }
        if scanner.isScanning { return .scanning  }
        return .results
    }

    // MARK: - Body

    var body: some View {
        VStack(spacing: 0) {
            header
            Rectangle()
                .fill(Color.borderSubtle)
                .frame(height: 0.5)
            ScrollView {
                stateContent
                    .frame(maxWidth: .infinity, minHeight: 320, alignment: .top)
            }
        }
        .frame(minWidth: 480, idealWidth: 480)
        .background(Color.backgroundPrimary.ignoresSafeArea())
        .onDisappear { scanner.cancel() }
    }

    // MARK: - Header

    private var header: some View {
        HStack(alignment: .center, spacing: NickSpacing.md) {
            VStack(alignment: .leading, spacing: NickSpacing.xs) {
                Text("Deep Scan")
                    .font(.nickBodyMedium)
                    .foregroundStyle(Color.textPrimary)
                Text("Powered by YARA")
                    .font(.nickCaption)
                    .foregroundStyle(Color.textTertiary)
            }
            Spacer()
            Button(action: { scanner.cancel(); dismiss() }) {
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
        switch phase {
        case .confirmation: confirmationState
        case .scanning:     progressState
        case .paused:       pausedState
        case .results:      resultsState
        }
    }

    // MARK: - Confirmation

    private var confirmationState: some View {
        VStack(alignment: .leading, spacing: NickSpacing.lg) {
            VStack(alignment: .leading, spacing: NickSpacing.sm) {
                Text("Scans all executables and scripts on your Mac using YARA rules and heuristic analysis. Media and document files are skipped.")
                    .font(.nickBodySmall)
                    .foregroundStyle(Color.textSecondary)
                    .fixedSize(horizontal: false, vertical: true)

                HStack(alignment: .top, spacing: NickSpacing.sm) {
                    Image(systemName: "exclamationmark.triangle")
                        .font(.system(size: 11, weight: .medium))
                        .foregroundStyle(Color.statusYellow)
                        .padding(.top, 1)
                    Text("This may take 10–30 minutes depending on the number of files on your system.")
                        .font(.nickBodySmall)
                        .foregroundStyle(Color.textSecondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                .padding(.top, NickSpacing.xs)
            }

            Toggle(isOn: $onlyOnPower) {
                Text("Only scan when on power")
                    .font(.nickBodySmall)
                    .foregroundStyle(Color.textPrimary)
            }
            .toggleStyle(.checkbox)

            // Full Disk Access note
            HStack(alignment: .top, spacing: NickSpacing.sm) {
                Image(systemName: "info.circle")
                    .font(.system(size: 11, weight: .medium))
                    .foregroundStyle(Color.statusBlue)
                    .padding(.top, 1)
                VStack(alignment: .leading, spacing: NickSpacing.xs) {
                    Text("For a thorough scan, grant Nick Full Disk Access in System Settings → Privacy & Security → Full Disk Access.")
                        .font(.nickBodySmall)
                        .foregroundStyle(Color.textSecondary)
                        .fixedSize(horizontal: false, vertical: true)
                    Button("Open Privacy Settings →") {
                        if let url = URL(string: "x-apple.systempreferences:com.apple.settings.PrivacySecurity.extension?Privacy_AllFiles") {
                            NSWorkspace.shared.open(url)
                        }
                    }
                    .font(.nickCaption)
                    .foregroundStyle(Color.statusBlue)
                    .buttonStyle(.plain)
                }
            }

            HStack(spacing: NickSpacing.md) {
                Button("Cancel") { dismiss() }
                    .buttonStyle(.nickSecondary)
                Spacer()
                Button("Start Deep Scan") {
                    hasStarted = true
                    Task { @MainActor in
                        scanner.start(onlyOnPower: onlyOnPower) { [engine] path in
                            try await engine.scanFile(at: URL(fileURLWithPath: path))
                        }
                    }
                }
                .buttonStyle(.nickPrimary)
            }
        }
        .padding(NickSpacing.lg)
    }

    // MARK: - Progress

    private var progressState: some View {
        VStack(spacing: NickSpacing.lg) {
            // Percentage
            Text("\(Int(scanner.progress * 100))%")
                .font(.nickGaugeValue)
                .foregroundStyle(Color.statusBlue)
                .monospacedDigit()

            // File count
            Text("\(scanner.scannedFiles.formatted()) / \(scanner.totalFiles.formatted()) files scanned")
                .font(.nickMono)
                .foregroundStyle(Color.textSecondary)

            // Progress bar
            progressBar

            // Current file
            VStack(alignment: .leading, spacing: NickSpacing.xs) {
                Text("Currently scanning:")
                    .font(.nickCaption)
                    .foregroundStyle(Color.textTertiary)
                Text(scanner.currentFile)
                    .font(.nickMonoSmall)
                    .foregroundStyle(Color.textTertiary)
                    .lineLimit(1)
                    .truncationMode(.middle)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }

            // Timing
            HStack(spacing: NickSpacing.sm) {
                Image(systemName: "timer")
                    .font(.system(size: 10, weight: .regular))
                    .foregroundStyle(Color.textTertiary)
                Text("Elapsed: \(formatTime(scanner.elapsedTime))")
                    .font(.nickMonoSmall)
                    .foregroundStyle(Color.textTertiary)
                if scanner.estimatedRemaining > 0 {
                    Text("·")
                        .font(.nickMonoSmall)
                        .foregroundStyle(Color.textTertiary)
                    Text("Est. remaining: \(formatTime(scanner.estimatedRemaining))")
                        .font(.nickMonoSmall)
                        .foregroundStyle(Color.textTertiary)
                }
            }

            // Threats found
            HStack(spacing: NickSpacing.sm) {
                Image(systemName: scanner.threatsFound > 0 ? "exclamationmark.triangle.fill" : "checkmark.shield")
                    .font(.system(size: 11, weight: .medium))
                    .foregroundStyle(scanner.threatsFound > 0 ? Color.statusRed : Color.textTertiary)
                Text("Threats found: \(scanner.threatsFound)")
                    .font(.nickBodySmall)
                    .foregroundStyle(scanner.threatsFound > 0 ? Color.statusRed : Color.textSecondary)
            }

            Button("Cancel Deep Scan") { scanner.cancel() }
                .buttonStyle(.nickSecondary)
                .padding(.top, NickSpacing.xs)
        }
        .padding(NickSpacing.lg)
        .multilineTextAlignment(.center)
        .frame(maxWidth: .infinity)
    }

    private var progressBar: some View {
        GeometryReader { proxy in
            ZStack(alignment: .leading) {
                Capsule()
                    .fill(Color.backgroundTertiary)
                    .frame(height: 4)
                Capsule()
                    .fill(Color.statusBlue)
                    .frame(width: max(4, proxy.size.width * scanner.progress), height: 4)
                    .animation(.linear(duration: 0.3), value: scanner.progress)
            }
        }
        .frame(height: 4)
    }

    // MARK: - Paused

    private var pausedState: some View {
        VStack(spacing: NickSpacing.md) {
            Image(systemName: "pause.circle.fill")
                .font(.system(size: 32))
                .foregroundStyle(Color.statusYellow)
            Text("Deep Scan paused")
                .font(.nickSubtitle)
                .foregroundStyle(Color.textPrimary)
            Text("Connect to power to continue")
                .font(.nickBodySmall)
                .foregroundStyle(Color.textSecondary)
            Button("Cancel Deep Scan") { scanner.cancel() }
                .buttonStyle(.nickSecondary)
                .padding(.top, NickSpacing.xs)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, NickSpacing.xxl)
    }

    // MARK: - Results

    @ViewBuilder
    private var resultsState: some View {
        if scanner.threatsFound == 0 {
            cleanResults
        } else {
            threatResults
        }
    }

    private var cleanResults: some View {
        VStack(spacing: NickSpacing.md) {
            Image(systemName: "checkmark.shield.fill")
                .font(.system(size: 32))
                .foregroundStyle(Color.statusGreen)
            Text("No threats detected")
                .font(.nickSubtitle)
                .foregroundStyle(Color.textPrimary)
            Text("\(scanner.totalFiles.formatted()) executables in monitored directories · \(formatTime(scanner.elapsedTime))")
                .font(.nickBodySmall)
                .foregroundStyle(Color.textSecondary)
            Button("Close") { dismiss() }
                .buttonStyle(.nickSecondary)
                .padding(.top, NickSpacing.xs)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, NickSpacing.xxl)
    }

    private var threatResults: some View {
        VStack(spacing: 0) {
            // Summary header
            VStack(spacing: NickSpacing.md) {
                Image(systemName: "exclamationmark.triangle.fill")
                    .font(.system(size: 32))
                    .foregroundStyle(Color.statusRed)
                Text("\(scanner.threatsFound) threat\(scanner.threatsFound == 1 ? "" : "s") detected")
                    .font(.nickSubtitle)
                    .foregroundStyle(Color.textPrimary)
                Text("\(scanner.totalFiles.formatted()) executables in monitored directories · \(formatTime(scanner.elapsedTime))")
                    .font(.nickBodySmall)
                    .foregroundStyle(Color.textSecondary)
            }
            .frame(maxWidth: .infinity)
            .padding(.horizontal, NickSpacing.lg)
            .padding(.vertical, NickSpacing.xl)

            Rectangle()
                .fill(Color.borderSubtle)
                .frame(height: 0.5)

            VStack(spacing: 0) {
                ForEach(deduplicatedResults.indices, id: \.self) { i in
                    DeepScanMatchRow(match: deduplicatedResults[i].match, count: deduplicatedResults[i].count)
                    Rectangle()
                        .fill(Color.borderSubtle)
                        .frame(height: 0.5)
                        .padding(.leading, NickSpacing.lg)
                }
            }

            Button("Close") { dismiss() }
                .buttonStyle(.nickSecondary)
                .padding(NickSpacing.lg)
        }
    }

    // MARK: - Helpers

    /// Collapses duplicate (filePath, ruleName) pairs into a single entry with a count,
    /// preserving the original first-occurrence order.
    private var deduplicatedResults: [(match: YARAMatch, count: Int)] {
        var counts:  [String: Int]      = [:]
        var first:   [String: YARAMatch] = [:]
        var ordered: [String]           = []
        for match in scanner.results {
            let key = "\(match.filePath)|\(match.ruleName)"
            if counts[key] == nil {
                ordered.append(key)
                first[key] = match
            }
            counts[key, default: 0] += 1
        }
        return ordered.compactMap { key in
            guard let match = first[key], let count = counts[key] else { return nil }
            return (match: match, count: count)
        }
    }

    private func formatTime(_ interval: TimeInterval) -> String {
        guard interval > 0 else { return "--:--" }
        let total   = Int(interval)
        let minutes = total / 60
        let seconds = total % 60
        return String(format: "%d:%02d", minutes, seconds)
    }
}

// MARK: - DeepScanMatchRow

private struct DeepScanMatchRow: View {

    let match: YARAMatch
    let count: Int

    var body: some View {
        HStack(alignment: .top, spacing: NickSpacing.sm) {
            Text("▸")
                .font(.nickBodySmall)
                .foregroundStyle(Color.statusRed)
                .padding(.top, 1)
            VStack(alignment: .leading, spacing: NickSpacing.xs) {
                HStack(spacing: NickSpacing.sm) {
                    Text(count > 1 ? "\(match.ruleName) (×\(count))" : match.ruleName)
                        .font(.nickBodyMedium)
                        .foregroundStyle(Color.textPrimary)
                    Spacer()
                    if let sev = match.metadata["severity"] {
                        DeepScanSeverityBadge(severity: sev)
                    }
                }
                if let desc = match.metadata["description"] {
                    Text(desc)
                        .font(.nickBodySmall)
                        .foregroundStyle(Color.textSecondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Text(match.filePath)
                    .font(.nickMonoSmall)
                    .foregroundStyle(Color.textTertiary)
                    .lineLimit(1)
                    .truncationMode(.middle)
                Button("Show in Finder") {
                    NSWorkspace.shared.selectFile(match.filePath, inFileViewerRootedAtPath: "")
                }
                .font(.nickCaption)
                .foregroundStyle(Color.statusBlue)
                .buttonStyle(.plain)
            }
        }
        .padding(.horizontal, NickSpacing.lg)
        .padding(.vertical, NickSpacing.md)
    }
}

// MARK: - DeepScanSeverityBadge

private struct DeepScanSeverityBadge: View {

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
