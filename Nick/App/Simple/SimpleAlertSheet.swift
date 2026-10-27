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
    @Environment(NetworkProtectionManager.self) private var networkProtection

    @State private var showsTechnicalDetails = false
    @State private var confirmsTrust = false
    @State private var confirmsTrash = false
    @State private var actionError: String?

    private var user: UserFacingAlert { UserFacingAlertBuilder.shared.build(from: alert) }

    private var filePath: String? { alert.remediableFilePath }

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
            fileStillPresent: fileStillPresent,
            incident: incident
        )
    }
    private var behaviorPresentation: BehaviorIncidentPresentation {
        BehaviorIncidentPresentation(alert: alert, incident: incident)
    }

    private var trustEligibleProcess: NickProcessInfo? { TrustedProcessList.eligibleProcess(in: alert) }
    private var networkDomain: String? { TrustedProcessList.networkDomain(in: alert) }
    private var contributesToLearning: Bool { engine.contributesToVerdictLearning(alert) }

    private var incident: SecurityIncident? {
        engine.incidentStore.incidents.first { $0.alert.id == alert.id }
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
                    if let dismissedAt = incident?.previouslyDismissedAt {
                        row(
                            "HISTORY",
                            "Previously dismissed \(dismissedAt.formatted(date: .abbreviated, time: .shortened)). This new occurrence reopened the incident."
                        )
                    }
                    if let state = incident?.reopenedAfterState,
                       let reopenedAt = incident?.reopenedAfterAt {
                        row(
                            "HISTORY",
                            "Reopened after \(state.displayName) on \(reopenedAt.formatted(date: .abbreviated, time: .shortened))."
                        )
                    }
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
            contributesToLearning ? "Confirm this expected activity?" : "Trust this app?",
            isPresented: $confirmsTrust,
            titleVisibility: .visible
        ) {
            Button(contributesToLearning ? "Confirm Expected Activity" : "Trust for 7 Days") { trust() }
            Button("Cancel", role: .cancel) {
                // SwiftUI dismisses a confirmation dialog for its cancel role.
            }
        } message: {
            if contributesToLearning {
                Text("Nick will record this review decision. A second distinct occurrence must also be confirmed before matching review-only findings are lowered to Info. They are never hidden.")
            } else {
                Text("Nick will stop warning about this exact behaviour for 7 days. It will still warn you about anything new or harmful.")
            }
        }
        .confirmationDialog(
            "Move this app to the Trash?",
            isPresented: $confirmsTrash,
            titleVisibility: .visible
        ) {
            Button("Move to Trash", role: .destructive) { moveToTrash() }
            Button("Cancel", role: .cancel) {
                // SwiftUI dismisses a confirmation dialog for its cancel role.
            }
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
                if behaviorPresentation.isBehavior || behaviorPresentation.responsibleAppName != "Unknown app" {
                    ResponsibleAppLine(presentation: behaviorPresentation)
                        .padding(.top, 4)
                }
            }
            .accessibilityElement(children: .combine)
            Spacer(minLength: 12)
            StatusChip(text: copy.badgeText, textColor: toneColors.0, fillColor: toneColors.1)
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
            if let networkDomain {
                Button("Allow this domain") {
                    Task { _ = await networkProtection.allowDomain(networkDomain) }
                    dismiss()
                }
                .buttonStyle(.link)
                .tint(Color.nickAccent)
            } else if copy.status != .observed, trustEligibleProcess != nil {
                Button("I trust this app…") { confirmsTrust = true }
                    .buttonStyle(.link)
                    .tint(Color.nickAccent)
            }
            Spacer()
            if behaviorPresentation.status == .needsReview {
                Button("Mark as reviewed") {
                    engine.markAlertReviewed(alert.id)
                    dismiss()
                }
                .buttonStyle(.borderedProminent)
                .tint(Color.nickAccent)
            }
            if quarantineRecord != nil {
                Button("Keep in Quarantine") {
                    engine.hideAlert(alert.id)
                    dismiss()
                }
                .keyboardShortcut(.defaultAction)
            } else if copy.tone == .danger, fileStillPresent, user.actions.contains(.quarantine) {
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
        guard trustEligibleProcess != nil else { return }
        engine.alwaysAllowBehavior(from: alert.id)
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

    private var behavior: BehaviorIncidentPresentation {
        BehaviorIncidentPresentation(alert: alert)
    }

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
            if behavior.isBehavior || behavior.responsibleAppName != "Unknown app" {
                technicalValue(
                    "Responsible app",
                    [behavior.responsibleAppName, behavior.bundleID, behavior.teamID, behavior.signing]
                        .compactMap { $0 }.joined(separator: " · ")
                )
                technicalValue("Chain", behavior.chain)
                technicalValue("Shell / actor", "\(behavior.actor) · \(behavior.actorSigning)")
                if let matchedCommand = behavior.matchedCommand {
                    technicalValue("Matched command", matchedCommand)
                }
            }
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
                        Text("PID \(String(process.pid)) · \(process.name)")
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

    private func technicalValue(_ label: String, _ value: String) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(label).font(.system(size: 11, weight: .semibold))
            Text(value)
                .font(.system(size: 11, design: .monospaced))
                .foregroundStyle(Color.nickSecondaryText)
                .textSelection(.enabled)
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

struct ResponsibleAppLine: View {
    let presentation: BehaviorIncidentPresentation

    var body: some View {
        HStack(spacing: 6) {
            if let path = presentation.appPath {
                Image(nsImage: NSWorkspace.shared.icon(forFile: path))
                    .resizable()
                    .frame(width: 18, height: 18)
                    .accessibilityHidden(true)
            } else {
                Image(systemName: "app.dashed")
                    .frame(width: 18, height: 18)
                    .accessibilityHidden(true)
            }
            Text(presentation.responsibleLine)
                .font(.system(size: 12, weight: .medium))
                .foregroundStyle(Color.nickSecondaryText)
                .fixedSize(horizontal: false, vertical: true)
        }
    }
}
