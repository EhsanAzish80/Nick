// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import AppKit
import SwiftUI

// MARK: - SimpleScanView

/// Simple ▸ Scan: three big choices and results in plain words.
/// Quick Check runs the background system check, Full Check runs Deep Scan,
/// and Check a File or Drive runs the same YARA scan as Advanced ▸ Scan.
struct SimpleScanView: View {

    private enum Job: Equatable { case quick, full, file }

    @Environment(SecurityEngine.self) private var engine

    @State private var lastJob: Job?
    @State private var quickFinished = false
    @State private var fileTarget: URL?
    @State private var fileResult: SimpleScanResult?
    @State private var fileError: String?
    @State private var trashed: Set<String> = []
    @State private var trashError = false

    private var scanner: DeepScanner { engine.deepScanner }

    private var ignoredPaths: Set<String> {
        engine.deepScanIgnoredPaths
    }

    private var quickResult: SimpleScanResult {
        let issues = AttentionIssue.issues(
            endpointProtectionActive: true,
            auditIssues: engine.auditResults.filter { $0.status != .pass }.count,
            persistenceIssues: engine.persistenceItems.filter { $0.signingStatus?.isSuspicious == true }.count,
            processIssues: engine.processes.filter { $0.signingStatus == .unsigned || $0.signingStatus == .invalid }.count,
            networkIssues: engine.connections.filter { $0.isShellProcess && $0.isOutbound }.count
        )
        return .quickCheck(needsAttention: issues.count + engine.activeActionableAlerts.count)
    }

    private var fullResult: SimpleScanResult {
        .fullCheck(
            filesChecked: scanner.totalFiles,
            results: scanner.results,
            verdicts: scanner.resultVerdicts,
            ignoredPaths: ignoredPaths
        )
    }

    // MARK: Body

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 22) {
                ViewThatFits(in: .horizontal) {
                    HStack(alignment: .top, spacing: 14) { choices }
                    VStack(spacing: 14) { choices }
                }
                statusPanel
            }
            .padding(24)
            .frame(maxWidth: 1000, alignment: .leading)
            .frame(maxWidth: .infinity)
        }
        .background(Color.nickWindow)
        .navigationTitle("Scan")
        .onAppear(perform: consumePendingFileRequest)
        .onChange(of: engine.pendingFinderScanURL) { _, _ in consumePendingFileRequest() }
        .onChange(of: engine.isScanning) { wasScanning, isScanning in
            if lastJob == .quick, wasScanning, !isScanning { quickFinished = true }
        }
        .alert("Nick couldn’t move it to the Trash", isPresented: $trashError) {
            Button("OK", role: .cancel) {}
        } message: {
            Text("It may be in use. Quit the app and try again, or drag it to the Trash in Finder.")
        }
    }

    // MARK: Choices

    @ViewBuilder
    private var choices: some View {
        ScanChoiceCard(
            icon: "bolt.shield",
            title: "Quick Check",
            detail: "Your Mac’s settings, startup items, running apps and connections. About a minute.",
            buttonTitle: engine.isScanning && lastJob == .quick ? "Checking…" : "Run Quick Check",
            isBusy: engine.isScanning,
            action: runQuickCheck
        )
        ScanChoiceCard(
            icon: "magnifyingglass",
            title: "Full Check",
            detail: "Every app, download and startup file. Can take a while; you can keep working.",
            buttonTitle: scanner.isScanning ? "Stop" : "Run Full Check",
            isBusy: false,
            action: toggleFullCheck
        )
        ScanChoiceCard(
            icon: "externaldrive.badge.checkmark",
            title: "Check a File or Drive",
            detail: "Pick an app, download, folder or USB drive and Nick checks it now.",
            buttonTitle: "Choose…",
            isBusy: lastJob == .file && fileTarget != nil && fileResult == nil && fileError == nil,
            action: chooseFile
        )
    }

    // MARK: Status

    @ViewBuilder
    private var statusPanel: some View {
        switch lastJob {
        case .file?:
            if let fileResult {
                resultCard(fileResult, again: chooseFile)
            } else if let fileError {
                messageCard(icon: "exclamationmark.triangle", tone: .warning,
                            title: "Nick couldn’t check that", detail: fileError)
            } else if let fileTarget {
                progressCard(title: "Checking “\(fileTarget.lastPathComponent)”…", detail: nil, onStop: nil)
            }
        case .quick?:
            if engine.isScanning {
                progressCard(title: "Checking your Mac…", detail: "This usually takes about a minute.", onStop: nil)
            } else if quickFinished {
                resultCard(quickResult, again: runQuickCheck)
            }
        case .full?, nil:
            if scanner.isScanning || scanner.isPaused {
                progressCard(
                    title: scanner.isPaused ? "Paused until your Mac is plugged in" : "Running a Full Check…",
                    detail: fullProgressText,
                    onStop: { scanner.cancel() }
                )
            } else if scanner.hasCompletedScan {
                resultCard(fullResult, again: toggleFullCheck)
            }
        }
    }

    private var fullProgressText: String {
        if scanner.isIndexing {
            return "Checked \(scanner.scannedFiles.formatted()) of \(scanner.discoveredFiles.formatted()) files found so far"
        }
        let percent = Int((scanner.progress * 100).rounded())
        return "\(percent)% · checked \(scanner.scannedFiles.formatted()) of \(scanner.totalFiles.formatted()) files"
    }

    private func progressCard(title: String, detail: String?, onStop: (() -> Void)?) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Text(title).font(.system(size: 15, weight: .semibold))
                Spacer()
                if let onStop {
                    Button("Stop", action: onStop)
                        .disabled(scanner.isCancelling)
                }
            }
            if lastJob == .full || lastJob == nil, !scanner.isIndexing, scanner.totalFiles > 0 {
                ProgressView(value: scanner.progress)
            } else {
                ProgressView().progressViewStyle(.linear)
            }
            if let detail {
                Text(detail)
                    .font(.system(size: 12))
                    .monospacedDigit()
                    .foregroundStyle(Color.nickSecondaryText)
            }
        }
        .padding(20)
        .nickSurface()
    }

    private func resultCard(_ result: SimpleScanResult, again: @escaping () -> Void) -> some View {
        let remaining = zip(result.flaggedNames, result.flaggedPaths)
            .map { FlaggedFile(name: $0.0, path: $0.1) }
            .filter { !trashed.contains($0.path) }
        let tone: ResultTone = result.verdict == .clear ? .good : (result.verdict == .harmful ? .danger : .warning)
        return VStack(alignment: .leading, spacing: 14) {
            messageContent(
                icon: result.verdict == .clear ? "checkmark.shield" : "exclamationmark.shield",
                tone: tone, title: result.headline, detail: result.detail
            )
            if !remaining.isEmpty {
                VStack(spacing: 0) {
                    ForEach(Array(remaining.prefix(8))) { file in
                        HStack(spacing: 10) {
                            Image(systemName: "doc")
                                .foregroundStyle(Color.nickSecondaryText)
                                .accessibilityHidden(true)
                            Text(file.name)
                                .font(.system(size: 13, weight: .medium))
                                .lineLimit(1)
                                .truncationMode(.middle)
                            Spacer()
                            Button("Show in Finder") {
                                NSWorkspace.shared.selectFile(file.path, inFileViewerRootedAtPath: "")
                            }
                            .buttonStyle(.link)
                            Button("Move to Trash") { moveToTrash(file.path) }
                        }
                        .padding(.vertical, 8)
                        Divider().opacity(0.5)
                    }
                    if remaining.count > 8 {
                        Text("…and \(remaining.count - 8) more. Advanced ▸ Scan lists them all.")
                            .font(.system(size: 12))
                            .foregroundStyle(Color.nickSecondaryText)
                            .padding(.top, 8)
                    }
                }
            }
            HStack {
                Spacer()
                Button("Check Again", action: again)
            }
        }
        .padding(20)
        .nickSurface()
    }

    private enum ResultTone { case good, warning, danger }

    private struct FlaggedFile: Identifiable {
        let name: String
        let path: String
        var id: String { path }
    }

    private func messageCard(icon: String, tone: ResultTone, title: String, detail: String) -> some View {
        messageContent(icon: icon, tone: tone, title: title, detail: detail)
            .padding(20)
            .frame(maxWidth: .infinity, alignment: .leading)
            .nickSurface()
    }

    private func messageContent(icon: String, tone: ResultTone, title: String, detail: String) -> some View {
        let colors: (Color, Color) = switch tone {
        case .good:    (.nickAccent, .nickAccentTint)
        case .warning: (.nickWarningText, .nickWarningBackground)
        case .danger:  (.nickDangerText, .nickDangerBackground)
        }
        return HStack(alignment: .top, spacing: 14) {
            Image(systemName: icon)
                .font(.system(size: 20, weight: .medium))
                .foregroundStyle(colors.0)
                .frame(width: 44, height: 44)
                .background(
                    RoundedRectangle(cornerRadius: NickLayout.iconTileCornerRadius, style: .continuous)
                        .fill(colors.1)
                )
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 4) {
                Text(title).font(.system(size: 17, weight: .semibold))
                Text(detail)
                    .font(.system(size: 13))
                    .foregroundStyle(Color.nickSecondaryText)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .accessibilityElement(children: .combine)
            Spacer(minLength: 0)
        }
    }

    // MARK: Actions

    private func runQuickCheck() {
        lastJob = .quick
        quickFinished = false
        engine.runFullScan()
    }

    private func toggleFullCheck() {
        lastJob = .full
        if scanner.isScanning {
            scanner.cancel()
            return
        }
        scanner.resetResults()
        trashed = []
        let ignored = ignoredPaths
        scanner.start(onlyOnPower: false, ignoredPaths: ignored) { [engine] path in
            try await engine.scanFile(at: URL(fileURLWithPath: path))
        }
    }

    private func chooseFile() {
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = true
        panel.allowsMultipleSelection = false
        panel.message = "Choose an app, file, folder or drive to check"
        panel.prompt = "Check"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        checkFile(url)
    }

    private func consumePendingFileRequest() {
        guard let url = engine.pendingFinderScanURL else { return }
        engine.pendingFinderScanURL = nil
        checkFile(url)
    }

    private func checkFile(_ url: URL) {
        lastJob = .file
        fileTarget = url
        fileResult = nil
        fileError = nil
        trashed = []
        Task { @MainActor in
            do {
                let matches = try await engine.scanFile(at: url)
                let result = await Task.detached(priority: .utility) {
                    SimpleScanResult.fileCheck(target: url, matches: matches)
                }.value
                if fileTarget == url { fileResult = result }
            } catch {
                if fileTarget == url {
                    fileError = "Nick may not have permission to read it. Give Nick Full Disk Access in System Settings and try again."
                }
            }
        }
    }

    private func moveToTrash(_ path: String) {
        do {
            try FileManager.default.trashItem(at: URL(fileURLWithPath: path), resultingItemURL: nil)
            trashed.insert(path)
        } catch {
            trashError = true
        }
    }
}

// MARK: - ScanChoiceCard

private struct ScanChoiceCard: View {
    let icon: String
    let title: String
    let detail: String
    let buttonTitle: String
    let isBusy: Bool
    let action: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Image(systemName: icon)
                .font(.system(size: 20, weight: .medium))
                .foregroundStyle(Color.nickAccent)
                .frame(width: 44, height: 44)
                .background(
                    RoundedRectangle(cornerRadius: NickLayout.iconTileCornerRadius, style: .continuous)
                        .fill(Color.nickAccentTint)
                )
                .accessibilityHidden(true)
            Text(title).font(.system(size: 17, weight: .semibold))
            Text(detail)
                .font(.system(size: 13))
                .foregroundStyle(Color.nickSecondaryText)
                .fixedSize(horizontal: false, vertical: true)
            Spacer(minLength: 4)
            Button(buttonTitle, action: action)
                .buttonStyle(.borderedProminent)
                .buttonBorderShape(.capsule)
                .controlSize(.large)
                .disabled(isBusy)
        }
        .padding(20)
        .frame(maxWidth: .infinity, minHeight: 210, alignment: .topLeading)
        .nickSurface()
    }
}
