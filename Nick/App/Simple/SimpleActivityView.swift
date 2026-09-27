// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import AppKit
import SwiftUI

// MARK: - SimpleActivityView

/// Simple ▸ Activity: alerts, Quarantine and blocked launches on one
/// timeline, grouped by day, with All · Needs action · Blocked · Quarantined.
struct SimpleActivityView: View {

    @Environment(SecurityEngine.self) private var engine
    @Environment(ExtensionXPCClient.self) private var xpcClient

    @State private var filter: SimpleActivityFilter = .all
    @State private var presentedAlert: ThreatAlert?
    @State private var presentedQuarantine: QuarantineRecord?

    private var items: [SimpleActivityItem] {
        let actionable = Set(engine.activeActionableAlerts.map(\.id))
        return SimpleActivityFeed.items(
            alerts: SimpleActivityFeed.alertInputs(from: engine.alerts, actionable: actionable),
            quarantine: xpcClient.quarantineRecords,
            blocked: SimpleActivityFeed.blockedInputs(from: xpcClient.events)
        )
    }

    private var subtitle: String {
        let count = engine.activeActionableAlerts.count
        switch count {
        case 0:  return "Nothing needs your attention"
        case 1:  return "1 thing needs your attention"
        default: return "\(count) things need your attention"
        }
    }

    var body: some View {
        let all = items
        let days = SimpleActivityFeed.days(all.filter(filter.includes))

        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                NotificationPermissionRow()

                filterBar(all)

                if days.isEmpty {
                    emptyState
                } else {
                    ForEach(days) { day in
                        daySection(day)
                    }
                }
            }
            .padding(.horizontal, 24)
            .padding(.top, 8)
            .padding(.bottom, 28)
            .frame(maxWidth: 900, alignment: .leading)
            .frame(maxWidth: .infinity)
        }
        .background(Color.nickWindow)
        .navigationTitle("Activity")
        .navigationSubtitle(subtitle)
        .sheet(item: $presentedAlert) { alert in
            AlertDetailView(alert: alert)
                .environment(engine)
                .environment(xpcClient)
        }
        .sheet(item: $presentedQuarantine) { record in
            QuarantineActionSheet(record: record) {
                presentedQuarantine = nil
            }
            .environment(xpcClient)
        }
    }

    // MARK: Pieces

    private func filterBar(_ all: [SimpleActivityItem]) -> some View {
        HStack(spacing: 8) {
            ForEach(SimpleActivityFilter.allCases) { option in
                let count = SimpleActivityFeed.count(all, option)
                Button {
                    filter = option
                } label: {
                    HStack(spacing: 6) {
                        Text(option.rawValue)
                        if option != .all && count > 0 {
                            Text("\(count)")
                                .monospacedDigit()
                                .foregroundStyle(filter == option ? Color.white.opacity(0.85) : Color.nickSecondaryText)
                        }
                    }
                    .font(.system(size: 12, weight: .semibold))
                    .foregroundStyle(filter == option ? Color.white : Color.textPrimary)
                    .padding(.horizontal, 12)
                    .frame(height: 28)
                    .background(
                        Capsule().fill(filter == option ? Color.nickAccent : Color.nickCard)
                    )
                    .overlay(
                        Capsule().strokeBorder(Color.primary.opacity(filter == option ? 0 : 0.1), lineWidth: 1)
                    )
                    .contentShape(Capsule())
                }
                .buttonStyle(.plain)
                .accessibilityLabel("\(option.rawValue), \(count) item\(count == 1 ? "" : "s")")
                .accessibilityAddTraits(filter == option ? .isSelected : [])
            }
            Spacer()
        }
    }

    private func daySection(_ day: SimpleActivityFeed.Day) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(day.title)
                .font(.system(size: 13, weight: .semibold))
                .foregroundStyle(Color.nickSecondaryText)
                .padding(.horizontal, 4)
                .accessibilityAddTraits(.isHeader)

            VStack(spacing: 0) {
                ForEach(Array(day.items.enumerated()), id: \.element.id) { index, item in
                    if index > 0 { Divider().opacity(0.5).padding(.leading, 58) }
                    row(item)
                }
            }
            .padding(.vertical, 4)
            .nickSurface()
        }
    }

    @ViewBuilder
    private func row(_ item: SimpleActivityItem) -> some View {
        if item.opensDetail {
            Button { open(item) } label: {
                SimpleActivityRow(item: item, showsChevron: true)
            }
            .buttonStyle(.plain)
            .accessibilityHint("Shows what happened and what you can do")
        } else {
            SimpleActivityRow(item: item, showsChevron: false)
        }
    }

    private var emptyState: some View {
        VStack(spacing: 10) {
            Image(systemName: "checkmark.shield")
                .font(.system(size: 30, weight: .light))
                .foregroundStyle(Color.nickAccent)
                .accessibilityHidden(true)
            Text(emptyTitle)
                .font(.system(size: 15, weight: .semibold))
            Text("Nick keeps watching in the background and will list anything it does here.")
                .font(.system(size: 13))
                .foregroundStyle(Color.nickSecondaryText)
                .multilineTextAlignment(.center)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 48)
        .nickSurface()
        .accessibilityElement(children: .combine)
    }

    private var emptyTitle: String {
        switch filter {
        case .all:         "No activity yet"
        case .needsAction: "Nothing needs your attention"
        case .blocked:     "Nothing has been blocked"
        case .quarantined: "Quarantine is empty"
        }
    }

    private func open(_ item: SimpleActivityItem) {
        switch item.source {
        case .alert(let id):
            presentedAlert = engine.alerts.first { $0.id == id }
        case .quarantine(let id):
            presentedQuarantine = xpcClient.quarantineRecords.first { $0.id == id }
        case .blocked:
            break
        }
    }
}

// MARK: - SimpleActivityRow

struct SimpleActivityRow: View {
    let item: SimpleActivityItem
    let showsChevron: Bool

    private var colors: (Color, Color) {
        switch item.status {
        case .needsAction, .threat, .quarantined, .blocked:
            (.nickDangerText, .nickDangerBackground)
        case .warning:
            (.nickWarningText, .nickWarningBackground)
        }
    }

    var body: some View {
        HStack(alignment: .center, spacing: 14) {
            Image(systemName: item.icon)
                .font(.system(size: 13, weight: .semibold))
                .foregroundStyle(colors.0)
                .frame(width: 30, height: 30)
                .background(Circle().fill(colors.1))
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 2) {
                Text(item.title)
                    .font(.system(size: 13, weight: .medium))
                    .foregroundStyle(Color.textPrimary)
                    .fixedSize(horizontal: false, vertical: true)
                    .multilineTextAlignment(.leading)
                Text("\(item.detail) · \(item.date.formatted(date: .omitted, time: .shortened))")
                    .font(.system(size: 11))
                    .foregroundStyle(Color.nickSecondaryText)
            }
            Spacer(minLength: 8)
            StatusChip(text: item.status.rawValue, textColor: colors.0, fillColor: colors.1)
            if showsChevron {
                Image(systemName: "chevron.right")
                    .font(.system(size: 11, weight: .semibold))
                    .foregroundStyle(Color.nickSecondaryText)
                    .accessibilityHidden(true)
            }
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
        .contentShape(Rectangle())
        .accessibilityElement(children: .combine)
    }
}

// MARK: - QuarantineActionSheet

/// A quarantined file in plain words, with Keep / Restore / Delete.
/// The original location and threat name sit behind Technical details.
struct QuarantineActionSheet: View {
    let record: QuarantineRecord
    let done: () -> Void

    @Environment(ExtensionXPCClient.self) private var xpcClient

    @State private var confirmsDelete = false
    @State private var confirmsRestore = false
    @State private var failure: String?
    @State private var working = false

    private var name: String { (record.originalPath as NSString).lastPathComponent }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack(alignment: .top, spacing: 14) {
                Image(systemName: "archivebox")
                    .font(.system(size: 24, weight: .medium))
                    .foregroundStyle(Color.nickDangerText)
                    .frame(width: 56, height: 56)
                    .background(
                        RoundedRectangle(cornerRadius: 14, style: .continuous)
                            .fill(Color.nickDangerBackground)
                    )
                    .accessibilityHidden(true)
                VStack(alignment: .leading, spacing: 4) {
                    Text("“\(name)” is in Quarantine")
                        .font(.system(size: 22, weight: .semibold))
                        .fixedSize(horizontal: false, vertical: true)
                    Text(HomeFormatting.dayAndTime(record.quarantinedAt))
                        .font(.system(size: 13))
                        .foregroundStyle(Color.nickSecondaryText)
                }
                Spacer()
                StatusChip(text: "Quarantined", textColor: .nickDangerText, fillColor: .nickDangerBackground)
            }

            infoRow("WHAT HAPPENED", "Nick found that “\(name)” looked harmful.")
            infoRow("WHAT NICK DID", "Moved it to Quarantine, where it can’t run or change anything.")
            infoRow("WHAT YOU CAN DO", "Keep it there, or delete it for good. Only restore it if you’re sure it’s safe.")

            DisclosureGroup("Technical details") {
                VStack(alignment: .leading, spacing: 6) {
                    detail("Detection", record.threatName)
                    detail("Original location", record.originalPath)
                    detail("SHA-256", record.hash)
                }
                .padding(.top, 6)
                .textSelection(.enabled)
            }
            .font(.system(size: 13))

            HStack(spacing: 10) {
                Button("Restore…") { confirmsRestore = true }
                    .disabled(working)
                Spacer()
                Button("Delete…", role: .destructive) { confirmsDelete = true }
                    .disabled(working)
                Button("Keep in Quarantine", action: done)
                    .keyboardShortcut(.defaultAction)
            }
            .controlSize(.large)
        }
        .padding(28)
        .frame(width: 580)
        .confirmationDialog("Delete “\(name)”?", isPresented: $confirmsDelete, titleVisibility: .visible) {
            Button("Delete", role: .destructive) { delete() }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("This removes it for good. It can’t be undone.")
        }
        .confirmationDialog("Restore “\(name)”?", isPresented: $confirmsRestore, titleVisibility: .visible) {
            Button("Restore") { restore() }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("It goes back where it was and will be able to run again. Only do this if you’re sure it’s safe.")
        }
        .alert(failure ?? "", isPresented: Binding(
            get: { failure != nil },
            set: { if !$0 { failure = nil } }
        )) {
            Button("OK", role: .cancel) {}
        } message: {
            Text("It’s still safely in Quarantine. Try again in a moment.")
        }
    }

    private func delete() {
        working = true
        xpcClient.requestDeleteQuarantinedFile(id: record.id) { success in
            working = false
            if success { done() } else { failure = "Nick couldn’t delete it" }
        }
    }

    private func restore() {
        working = true
        xpcClient.requestRestoreQuarantinedFile(id: record.id) { success in
            working = false
            if success { done() } else { failure = "Nick couldn’t restore it" }
        }
    }

    private func infoRow(_ label: String, _ text: String) -> some View {
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

    private func detail(_ label: String, _ value: String) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            Text(label)
                .foregroundStyle(Color.nickSecondaryText)
                .frame(width: 130, alignment: .leading)
            Text(value)
                .font(.system(size: 12, design: .monospaced))
                .fixedSize(horizontal: false, vertical: true)
        }
        .font(.system(size: 12))
    }
}
