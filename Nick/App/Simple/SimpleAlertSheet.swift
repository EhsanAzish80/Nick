// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import AppKit
import SwiftUI

// MARK: - SimpleAlertSheet

/// Simple-mode alert sheet: what happened, what Nick did, what to do.
/// Technical data (rule, confidence, signer, paths, PIDs) stays behind a
/// collapsed disclosure.
struct SimpleAlertSheet: View {

    let alert: ThreatAlert

    @Environment(\.dismiss) private var dismiss
    @Environment(SecurityEngine.self) private var engine
    @Environment(ExtensionXPCClient.self) private var xpcClient

    @State private var showsTechnicalDetails = false
    @State private var confirmsTrust = false
    @State private var confirmsTrash = false
    @State private var actionError: String?

    private var user: UserFacingAlert { UserFacingAlertBuilder.shared.build(from: alert) }

    private var filePath: String? { alert.detectedFilePath }

    private var quarantineRecord: QuarantineRecord? {
        guard let path = filePath else { return nil }
        return xpcClient.quarantineRecords.first { $0.originalPath == path }
    }

    private var fileStillPresent: Bool {
        guard let path = filePath else { return false }
        return FileManager.default.fileExists(atPath: path)
    }

    private var copy: SimpleAlertCopy {
        SimpleAlertCopy.make(
            alert: alert,
            user: user,
            isQuarantined: quarantineRecord != nil,
            fileStillPresent: fileStillPresent
        )
    }

    private var hasStableSignedIdentity: Bool {
        alert.contributingSignals.contains { signal in
            guard let process = signal.processInfo,
                  case .signed(let teamID) = process.signingStatus else { return false }
            return !teamID.isEmpty && !process.path.isEmpty
        }
    }

    private var toneColors: (Color, Color) {
        switch copy.tone {
        case .danger:  (.nickDangerText, .nickDangerBackground)
        case .warning: (.nickWarningText, .nickWarningBackground)
        case .safe:    (.nickAccent, .nickAccentTint)
        }
    }

    // MARK: Body

    var body: some View {
        let current = self.copy
        VStack(alignment: .leading, spacing: 0) {
            header(current)
                .padding(.horizontal, 28)
                .padding(.top, 26)
                .padding(.bottom, 20)

            ScrollView {
                VStack(alignment: .leading, spacing: 10) {
                    row("WHAT HAPPENED", current.whatHappened)
                    row("WHAT NICK DID", current.whatNickDid)
                    row("WHAT YOU SHOULD DO", current.whatToDo)
                    technicalDetails(current)
                        .padding(.top, 6)
                }
                .padding(.horizontal, 28)
                .padding(.bottom, 16)
            }

            Divider()
            footer
                .padding(.horizontal, 28)
                .padding(.vertical, 16)
        }
        .frame(width: 720, height: 640)
        .background(Color.nickCard)
        .confirmationDialog(
            "Trust this app?",
            isPresented: $confirmsTrust,
            titleVisibility: .visible
        ) {
            Button(hasStableSignedIdentity ? "Trust for 7 Days" : "Trust for 24 Hours") { trust() }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("Nick will stop warning about this exact behaviour. It will still warn you about anything new or harmful.")
        }
        .confirmationDialog(
            "Move this app to the Trash?",
            isPresented: $confirmsTrash,
            titleVisibility: .visible
        ) {
            Button("Move to Trash", role: .destructive) { moveToTrash() }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("You can get it back from the Trash if you change your mind.")
        }
        .alert(
            "Nick couldn’t do that",
            isPresented: Binding(get: { actionError != nil }, set: { if !$0 { actionError = nil } })
        ) {
            Button("OK", role: .cancel) { actionError = nil }
        } message: {
            Text(actionError ?? "")
        }
    }

    // MARK: Sections

    private func header(_ copy: SimpleAlertCopy) -> some View {
        HStack(alignment: .top, spacing: 16) {
            Image(systemName: copy.tone == .safe ? "checkmark.shield" : "exclamationmark.shield")
                .font(.system(size: 26, weight: .medium))
                .foregroundStyle(toneColors.0)
                .frame(width: 56, height: 56)
                .background(
                    RoundedRectangle(cornerRadius: NickLayout.insetCornerRadius, style: .continuous)
                        .fill(toneColors.1)
                )
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 4) {
                Text(copy.title)
                    .font(.system(size: 22, weight: .semibold))
                    .fixedSize(horizontal: false, vertical: true)
                Text(copy.subline)
                    .font(.system(size: 13))
                    .foregroundStyle(Color.nickSecondaryText)
            }
            .accessibilityElement(children: .combine)
            Spacer(minLength: 12)
            StatusChip(text: copy.status.rawValue, textColor: toneColors.0, fillColor: toneColors.1)
        }
    }

    private func row(_ label: String, _ text: String) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(label)
                .font(.system(size: 11, weight: .semibold))
                .tracking(0.6)
                .foregroundStyle(Color.nickSecondaryText)
            Text(text)
                .font(.system(size: 14))
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(
            RoundedRectangle(cornerRadius: NickLayout.insetCornerRadius, style: .continuous)
                .fill(Color.nickInset)
        )
        .accessibilityElement(children: .combine)
    }

    private func technicalDetails(_ copy: SimpleAlertCopy) -> some View {
        DisclosureGroup(isExpanded: $showsTechnicalDetails) {
            AlertTechnicalDetails(alert: alert)
                .padding(.top, 8)
        } label: {
            VStack(alignment: .leading, spacing: 2) {
                Text("Technical details")
                    .font(.system(size: 13, weight: .medium))
                if !showsTechnicalDetails {
                    Text(copy.technicalSummary)
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundStyle(Color.nickSecondaryText)
                        .lineLimit(1)
                        .truncationMode(.middle)
                }
            }
        }
    }

    private var footer: some View {
        HStack(spacing: 12) {
            if copy.status != .info {
                Button("I trust this app…") { confirmsTrust = true }
                    .buttonStyle(.link)
                    .tint(Color.nickAccent)
            }
            Spacer()
            if quarantineRecord != nil {
                Button("Keep in Quarantine") {
                    engine.hideAlert(alert.id)
                    dismiss()
                }
                .keyboardShortcut(.defaultAction)
            } else if copy.tone == .danger, fileStillPresent {
                Button("Close") { dismiss() }
                Button("Move to Trash") { confirmsTrash = true }
                    .keyboardShortcut(.defaultAction)
                    .tint(Color.nickDangerText)
                    .buttonStyle(.borderedProminent)
            } else {
                Button("Done") { dismiss() }
                    .keyboardShortcut(.defaultAction)
            }
        }
        .controlSize(.large)
    }

    // MARK: Actions

    private func trust() {
        if hasStableSignedIdentity {
            engine.alwaysAllowBehavior(from: alert.id)
        } else {
            engine.allowAlertOnce(alert.id)
        }
        dismiss()
    }

    /// Moves the file to the Trash — never a permanent delete.
    private func moveToTrash() {
        guard let path = filePath else { return }
        do {
            try FileManager.default.trashItem(at: URL(fileURLWithPath: path), resultingItemURL: nil)
            engine.resolveAlert(alert.id)
            dismiss()
        } catch {
            actionError = "It may be in use or protected. Quit the app and try again, or drag it to the Trash in Finder."
        }
    }
}

// MARK: - AlertTechnicalDetails

/// The technical view of an alert: rule, confidence, signals with paths and
/// PIDs, and Copy JSON. Shown only inside a "Technical details" disclosure.
struct AlertTechnicalDetails: View {
    let alert: ThreatAlert

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 10) {
                SeverityBadge(severity: alert.severity)
                Text("Confidence \(Int((alert.score * 100).rounded()))%")
                    .font(.system(size: 12, design: .monospaced))
                    .foregroundStyle(Color.nickSecondaryText)
                Spacer()
                Button("Copy JSON", action: copyJSON)
                    .buttonStyle(.link)
            }
            Text(alert.title)
                .font(.system(size: 13, weight: .medium))
            Text(alert.explanation ?? alert.description)
                .font(.system(size: 12))
                .foregroundStyle(Color.nickSecondaryText)
                .fixedSize(horizontal: false, vertical: true)
            ForEach(alert.contributingSignals) { signal in
                VStack(alignment: .leading, spacing: 3) {
                    Text(signal.title)
                        .font(.system(size: 12, weight: .medium))
                    if let path = signal.metadata["script_path"] ?? signal.metadata["path"] ?? signal.processInfo?.path,
                       !path.isEmpty {
                        Text(path)
                            .font(.system(size: 11, design: .monospaced))
                            .foregroundStyle(Color.nickSecondaryText)
                            .lineLimit(1)
                            .truncationMode(.middle)
                            .textSelection(.enabled)
                    }
                    if let process = signal.processInfo {
                        Text("PID \(process.pid) · \(process.name)")
                            .font(.system(size: 11, design: .monospaced))
                            .foregroundStyle(Color.nickSecondaryText)
                    }
                    if let rule = signal.metadata["rule"] ?? signal.metadata["yaraRules"], !rule.isEmpty {
                        Text("Rule \(rule)")
                            .font(.system(size: 11, design: .monospaced))
                            .foregroundStyle(Color.nickSecondaryText)
                    }
                }
                .padding(10)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(
                    RoundedRectangle(cornerRadius: 10, style: .continuous)
                        .fill(Color.nickInset)
                )
            }
        }
    }

    private func copyJSON() {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        guard let data = try? encoder.encode(alert),
              let string = String(data: data, encoding: .utf8) else { return }
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(string, forType: .string)
    }
}
