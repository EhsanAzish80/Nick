// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import AppKit
import SwiftUI

// MARK: - SimpleHomeView

/// Simple ▸ Home: one status hero, four protection cards, the Mac security
/// settings bar, and a plain-language "What Nick did lately" feed.
/// No PIDs, rule names, Team IDs, confidence scores, or paths.
struct SimpleHomeView: View {

    @Binding var selection: SimpleSection?

    @Environment(SecurityEngine.self) private var engine
    @Environment(ExtensionXPCClient.self) private var xpcClient
    @Environment(NetworkProtectionManager.self) private var networkProtection
    @Environment(\.openURL) private var openURL
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @Environment(\.controlActiveState) private var controlActiveState

    @State private var endpointHealth: [String: Any]?
    @State private var windowVisible = false
    @State private var entranceVisible = HomeEntrance.hasRun
    @State private var checkStartedAt: Date?
    @State private var userStartedCheck = false
    @State private var completionBounce = 0
    @State private var healthLoaded = false
    @State private var presentedAlert: ThreatAlert?
    @State private var presentedQuarantine: QuarantineRecord?
    @State private var showsWhy = false
    @State private var confirmsDelete = false
    @State private var deleteFailed = false

    /// Incidents the user has already opened from the hero, newest last.
    @AppStorage("simpleHomeSeenIncidents") private var seenIncidentsRaw = ""

    // MARK: Derived state

    private var endpointActive: Bool {
        // Before the first heartbeat read, don't flash "Protection is paused".
        !healthLoaded || EndpointHealth.isProtectionActive(endpointHealth)
    }

    private var ransomwareShieldActive: Bool {
        EndpointHealth.isRansomwareShieldActive(endpointHealth)
    }

    private var issues: [AttentionIssue] {
        AttentionIssue.issues(
            endpointProtectionActive: endpointActive,
            auditIssues: engine.auditResults.filter { $0.status != .pass }.count,
            persistenceIssues: engine.persistenceItems.filter { $0.signingStatus?.isSuspicious == true }.count,
            processIssues: engine.processes.filter { $0.signingStatus == .unsigned || $0.signingStatus == .invalid }.count,
            networkIssues: engine.connections.filter { $0.isShellProcess && $0.isOutbound }.count,
            unreviewedFindings: engine.activeActionableAlerts.filter {
                UserFacingAlertBuilder.shared.build(from: $0).severity != .critical
            }.count
        )
    }

    private var seenIncidents: Set<String> {
        Set(seenIncidentsRaw.split(separator: "\n").map(String.init))
    }

    private var incident: HomeIncident? {
        HomeIncident.latest(
            alerts: engine.activeActionableAlerts,
            quarantine: xpcClient.quarantineRecords,
            seen: seenIncidents
        )
    }

    private var hero: HomeHero {
        let weekAgo = Date().addingTimeInterval(-7 * 24 * 60 * 60)
        return HomeHero.make(
            incident: incident,
            issues: issues,
            websitesProtected: networkProtection.isEnabled,
            lastCheck: engine.lastScanDate,
            hadRecentWarnings: engine.alerts.contains { $0.lastSeen >= weekAgo }
        )
    }

    private var cards: [ProtectionCard] {
        ProtectionCard.cards(
            endpointActive: endpointActive,
            networkState: networkProtection.state,
            ransomwareShieldActive: ransomwareShieldActive
        )
    }

    private var macSettings: MacSettingsSummary {
        MacSettingsSummary.make(from: engine.auditResults)
    }

    private var activity: [HomeActivityLine] {
        HomeActivityLine.recent(
            alerts: engine.alerts,
            quarantine: xpcClient.quarantineRecords,
            activity: engine.activityLog.events,
            checkedFileDates: xpcClient.events
                .filter { $0.eventType == .authExec || $0.eventType == .notifyWrite }
                .map(\.timestamp)
        )
    }

    /// Only checks the user started get the progress arc; automatic checks
    /// just change the meta line.
    private var scanProgress: Double? {
        guard engine.isScanning, userStartedCheck, let checkStartedAt else { return nil }
        return QuickCheckProgress.fraction(events: engine.activityLog.events, since: checkStartedAt)
    }

    /// Only the calm, protected state breathes, and only while someone can see it.
    private var heroBreathes: Bool {
        hero.state == .protected
            && !engine.isScanning
            && windowVisible
            && controlActiveState == .key
            && !reduceMotion
    }

    private var feedAnimation: Animation? {
        HomeMotion.animation(HomeMotion.stateChange, reduceMotion: reduceMotion)
    }

    private var subtitle: String {
        let current = self.hero
        switch current.state {
        case .protected: return "Protected · \(current.meta.lowercasedFirst)"
        case .attention:
            return issues.count == 1 ? "1 thing needs your attention" : "\(issues.count) things need your attention"
        case .blocked:
            return incident?.wasQuarantined == true ? "Threat stopped · your files are safe" : "Something needs a look"
        }
    }

    // MARK: Body

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 22) {
                GuardHeroView(
                    hero: hero,
                    scanProgress: scanProgress,
                    breathes: heroBreathes,
                    completionBounce: completionBounce,
                    isBackgroundChecking: engine.isScanning && !userStartedCheck,
                    primaryDisabled: hero.state == .protected && engine.isScanning,
                    primary: performPrimary,
                    secondary: performSecondary
                )
                .popover(isPresented: $showsWhy, arrowEdge: .bottom) {
                    whyPopover
                }
                .homeFadeUp(visible: entranceVisible, index: 0, reduceMotion: reduceMotion)

                ViewThatFits(in: .horizontal) {
                    HStack(alignment: .top, spacing: 20) {
                        protectionColumn
                            .frame(minWidth: 460)
                        activityFeed
                            .frame(width: 330)
                    }
                    VStack(alignment: .leading, spacing: 20) {
                        protectionColumn
                        activityFeed
                    }
                }
            }
            .padding(.horizontal, 24)
            .padding(.top, 8)
            .padding(.bottom, 28)
            .frame(maxWidth: 1200, alignment: .leading)
            .frame(maxWidth: .infinity)
        }
        .background(Color.nickWindow)
        .navigationTitle("Home")
        .navigationSubtitle(subtitle)
        .background(WindowVisibilityReader { windowVisible = $0 })
        .task { await refreshHealth() }
        .onAppear(perform: runEntranceOnce)
        .onAppear {
            if engine.isScanning, checkStartedAt == nil { checkStartedAt = Date() }
        }
        .onChange(of: engine.isScanning) { _, scanning in
            if scanning {
                checkStartedAt = Date()
            } else {
                checkStartedAt = nil
                if userStartedCheck {
                    userStartedCheck = false
                    if hero.state == .protected && !reduceMotion { completionBounce += 1 }
                }
            }
        }
        .sheet(item: $presentedAlert) { alert in
            AlertDetailView(alert: alert)
                .environment(engine)
                .environment(xpcClient)
        }
        .sheet(item: $presentedQuarantine) { record in
            QuarantineIncidentSheet(record: record) {
                presentedQuarantine = nil
            }
            .environment(xpcClient)
        }
        .confirmationDialog(
            "Delete this app?",
            isPresented: $confirmsDelete,
            titleVisibility: .visible
        ) {
            Button("Delete It", role: .destructive) { deleteQuarantinedIncident() }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("It’s already in Quarantine and can’t run. Deleting it removes it for good.")
        }
        .alert("Nick couldn’t delete it", isPresented: $deleteFailed) {
            Button("OK", role: .cancel) {}
        } message: {
            Text("It’s still safely in Quarantine. You can try again from Activity.")
        }
    }

    // MARK: Sections

    private var protectionColumn: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(alignment: .firstTextBaseline) {
                Text("Protection")
                    .font(.system(size: 13, weight: .semibold))
                    .foregroundStyle(Color.nickSecondaryText)
                Spacer()
                Button("Manage") { selection = .protection }
                    .buttonStyle(.link)
                    .font(.system(size: 12, weight: .semibold))
                    .tint(Color.nickAccent)
            }
            .padding(.horizontal, 4)

            LazyVGrid(
                columns: [GridItem(.flexible(), spacing: 14), GridItem(.flexible(), spacing: 14)],
                spacing: 14
            ) {
                ForEach(Array(cards.enumerated()), id: \.element.id) { index, card in
                    Button { selection = .protection } label: {
                        ProtectionCardView(card: card)
                    }
                    .buttonStyle(.plain)
                    .accessibilityHint("Opens Protection")
                    .homeFadeUp(visible: entranceVisible, index: index + 1, reduceMotion: reduceMotion)
                }
            }

            MacSettingsBar(summary: macSettings) { fix in
                if let url = fix.url.flatMap(URL.init(string:)) {
                    openURL(url)
                } else {
                    selection = .protection
                }
            }
            .homeFadeUp(visible: entranceVisible, index: cards.count + 1, reduceMotion: reduceMotion)
        }
    }

    private var activityFeed: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(alignment: .firstTextBaseline) {
                Text("What Nick did lately")
                    .font(.system(size: 13, weight: .semibold))
                    .foregroundStyle(Color.nickSecondaryText)
                Spacer()
                Button("All activity") { selection = .activity }
                    .buttonStyle(.link)
                    .font(.system(size: 12, weight: .semibold))
                    .tint(Color.nickAccent)
            }
            .padding(.bottom, 8)

            if activity.isEmpty {
                Text("Nothing to report yet. Nick is watching in the background.")
                    .font(.system(size: 13))
                    .foregroundStyle(Color.nickSecondaryText)
                    .padding(.vertical, 12)
            } else {
                VStack(alignment: .leading, spacing: 0) {
                    ForEach(activity) { line in
                        VStack(alignment: .leading, spacing: 0) {
                            Divider().opacity(0.5)
                            ActivityLineView(line: line)
                        }
                        .transition(.move(edge: .top).combined(with: .opacity))
                    }
                }
                .animation(feedAnimation, value: activity.map(\.id))
                .clipped()
            }
        }
        .padding(.horizontal, 18)
        .padding(.top, 18)
        .padding(.bottom, 8)
        .nickSurface()
        .homeFadeUp(visible: entranceVisible, index: cards.count + 2, reduceMotion: reduceMotion)
    }

    private var whyPopover: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Why this matters")
                .font(.headline)
            Text(issues.first?.whyItMatters ?? "")
                .font(.system(size: 13))
                .foregroundStyle(Color.nickSecondaryText)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(16)
        .frame(width: 320)
    }

    // MARK: Actions

    private func performPrimary() {
        switch hero.state {
        case .protected:
            // Run the Quick Check in place so the hero ring can show progress.
            guard !engine.isScanning else { return }
            userStartedCheck = true
            engine.runFullScan()
        case .attention:
            guard let fix = issues.first?.simpleFix else { return }
            switch fix {
            case .openURL(let string):
                if let url = URL(string: string) { openURL(url) }
            case .showActivity:
                selection = .activity
            case .showProtection:
                selection = .protection
            }
        case .blocked:
            guard let incident else { return }
            markSeen(incident)
            switch incident.source {
            case .alert(let id):
                presentedAlert = engine.alerts.first { $0.id == id }
            case .quarantine(let id):
                presentedQuarantine = xpcClient.quarantineRecords.first { $0.id == id }
            }
        }
    }

    private func performSecondary() {
        switch hero.state {
        case .protected:
            chooseFileToScan()
        case .attention:
            showsWhy = true
        case .blocked:
            if incident?.wasQuarantined == true {
                confirmsDelete = true
            } else {
                selection = .activity
            }
        }
    }

    private func chooseFileToScan() {
        let panel = NSOpenPanel()
        panel.prompt = "Scan"
        panel.canChooseDirectories = true
        panel.allowsMultipleSelection = false
        panel.begin { result in
            guard result == .OK, let url = panel.url else { return }
            engine.pendingFinderScanURL = url
            selection = .scan
        }
    }

    private func deleteQuarantinedIncident() {
        guard let incident, case .quarantine(let id) = incident.source else { return }
        xpcClient.requestDeleteQuarantinedFile(id: id) { success in
            if success {
                markSeen(incident)
            } else {
                deleteFailed = true
            }
        }
    }

    private func runEntranceOnce() {
        guard !HomeEntrance.hasRun else { return }
        HomeEntrance.hasRun = true
        if reduceMotion {
            entranceVisible = true
        } else {
            // Let the hidden first frame render so the fade-up is visible.
            Task { @MainActor in
                await Task.yield()
                entranceVisible = true
            }
        }
    }

    private func markSeen(_ incident: HomeIncident) {
        var ids = seenIncidentsRaw.split(separator: "\n").map(String.init)
        guard !ids.contains(incident.id) else { return }
        ids.append(incident.id)
        seenIncidentsRaw = ids.suffix(100).joined(separator: "\n")
    }

    private func refreshHealth() async {
        while !Task.isCancelled {
            endpointHealth = await EndpointHealth.load()
            healthLoaded = true
            try? await Task.sleep(for: .seconds(5))
        }
    }
}

// MARK: - GuardHeroView

/// The dark status card. VoiceOver reads it as one element ("title. body"),
/// with the two buttons reachable separately.
struct GuardHeroView: View {
    let hero: HomeHero
    /// Non-nil while a check runs: the inner ring becomes a progress arc.
    var scanProgress: Double? = nil
    /// Protected-only breathing of the outer ring. The caller gates it on
    /// window visibility, key state and Reduce Motion.
    var breathes: Bool = false
    /// Incremented when a check the user started finishes.
    var completionBounce: Int = 0
    /// An automatic check is running: meta says "Checking…", no arc.
    var isBackgroundChecking: Bool = false
    var primaryDisabled: Bool = false
    let primary: () -> Void
    let secondary: () -> Void

    @Environment(\.colorScheme) private var colorScheme
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    private var stateAnimation: Animation? {
        HomeMotion.animation(HomeMotion.stateChange, reduceMotion: reduceMotion)
    }

    private var ring: Color {
        switch hero.state {
        case .protected: .nickRingProtected
        case .attention: .nickRingAttention
        case .blocked:   .nickRingBlocked
        }
    }

    private var glyph: String {
        switch hero.state {
        case .protected: "checkmark.shield"
        case .attention: "exclamationmark.shield"
        case .blocked:   "xmark.shield"
        }
    }

    private var meta: String {
        if let scanProgress {
            return "Checking your Mac… \(Int((scanProgress * 100).rounded()))%"
        }
        return isBackgroundChecking ? "Checking…" : hero.meta
    }

    var body: some View {
        HStack(spacing: 40) {
            ZStack {
                outerRing
                innerRing
                    .padding(14)
                Image(systemName: glyph)
                    .font(.system(size: 54, weight: .light))
                    .foregroundStyle(ring)
                    .contentTransition(.symbolEffect(.replace))
                    .symbolEffect(.bounce, options: .nonRepeating, value: reduceMotion ? 0 : completionBounce)
            }
            .frame(width: 148, height: 148)
            .animation(stateAnimation, value: hero.state)
            .animation(stateAnimation, value: scanProgress == nil)
            .accessibilityHidden(true)

            VStack(alignment: .leading, spacing: 10) {
                VStack(alignment: .leading, spacing: 10) {
                    Text(hero.eyebrow)
                        .font(.system(size: 11, weight: .semibold))
                        .tracking(0.7)
                        .foregroundStyle(Color.nickHeroEyebrow)
                        .contentTransition(.opacity)
                    Text(hero.title)
                        .font(.system(size: 36, weight: .semibold))
                        .foregroundStyle(.white)
                        .fixedSize(horizontal: false, vertical: true)
                        .contentTransition(.opacity)
                    Text(hero.body)
                        .font(.system(size: 15))
                        .lineSpacing(3)
                        .foregroundStyle(Color.nickHeroBody)
                        .frame(maxWidth: 560, alignment: .leading)
                        .fixedSize(horizontal: false, vertical: true)
                        .contentTransition(.opacity)
                }
                .animation(stateAnimation, value: hero)
                .accessibilityElement(children: .ignore)
                .accessibilityLabel("\(hero.title). \(hero.body)")
                .accessibilityAddTraits(.isHeader)

                HStack(spacing: 12) {
                    Button(hero.primaryTitle, action: primary)
                        .buttonStyle(HeroPrimaryButtonStyle(fill: ring))
                        .disabled(primaryDisabled)
                        .opacity(primaryDisabled ? 0.6 : 1)
                    Button(hero.secondaryTitle, action: secondary)
                        .buttonStyle(HeroSecondaryButtonStyle())
                    Text(meta)
                        .font(.system(size: 12))
                        .foregroundStyle(Color.nickHeroMeta)
                        .padding(.leading, 6)
                        .lineLimit(1)
                        .contentTransition(.numericText())
                        .animation(stateAnimation, value: meta)
                }
                .animation(stateAnimation, value: hero.state)
                .padding(.top, 10)
            }
            Spacer(minLength: 0)
        }
        .padding(.vertical, 36)
        .padding(.horizontal, 40)
        .background(
            RoundedRectangle(cornerRadius: NickLayout.heroCornerRadius, style: .continuous)
                .fill(Color.nickGuardHero)
                .shadow(color: Color.black.opacity(0.18), radius: 15, x: 0, y: 10)
        )
        .overlay {
            if colorScheme == .dark {
                RoundedRectangle(cornerRadius: NickLayout.heroCornerRadius, style: .continuous)
                    .strokeBorder(Color.white.opacity(0.08), lineWidth: 0.5)
            }
        }
        .environment(\.colorScheme, .dark)
    }

    /// Breathes only while `breathes` is true. The timeline is paused
    /// otherwise, so a hidden, background or amber/red hero costs no frames.
    private var outerRing: some View {
        TimelineView(.animation(minimumInterval: 1.0 / 20.0, paused: !breathes)) { context in
            let phase = breathes ? HomeMotion.breathPhase(at: context.date) : 0
            Circle()
                .strokeBorder(ring.opacity(0.25 + 0.15 * phase), lineWidth: 1)
                .scaleEffect(1 + 0.04 * phase)
        }
    }

    @ViewBuilder
    private var innerRing: some View {
        if let scanProgress {
            Circle()
                .fill(ring.opacity(0.08))
                .overlay(Circle().strokeBorder(ring.opacity(0.25), lineWidth: 2))
                .overlay(
                    Circle()
                        .inset(by: 1)
                        .trim(from: 0, to: scanProgress)
                        .stroke(ring, style: StrokeStyle(lineWidth: 2, lineCap: .round))
                        .rotationEffect(.degrees(-90))
                        .animation(HomeMotion.animation(.smooth(duration: 0.6), reduceMotion: reduceMotion),
                                   value: scanProgress)
                )
                .transition(.opacity)
        } else {
            Circle()
                .fill(ring.opacity(0.08))
                .overlay(Circle().strokeBorder(ring, lineWidth: 2))
                .transition(.opacity)
        }
    }
}

private struct HeroPrimaryButtonStyle: ButtonStyle {
    let fill: Color

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.system(size: 15, weight: .semibold))
            .foregroundStyle(Color.nickHeroOnRing)
            .padding(.horizontal, 22)
            .frame(height: 42)
            .background(Capsule().fill(fill.opacity(configuration.isPressed ? 0.8 : 1)))
            .contentShape(Capsule())
    }
}

private struct HeroSecondaryButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.system(size: 14, weight: .medium))
            .foregroundStyle(.white)
            .padding(.horizontal, 20)
            .frame(height: 42)
            .background(Capsule().fill(Color.white.opacity(configuration.isPressed ? 0.12 : 0.06)))
            .overlay(Capsule().strokeBorder(Color.white.opacity(0.16), lineWidth: 1))
            .contentShape(Capsule())
    }
}

// MARK: - ProtectionCardView

struct ProtectionCardView: View {
    let card: ProtectionCard

    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var hovering = false
    @State private var statusBounce = 0
    @State private var appearedAt = Date()

    private var tileForeground: Color {
        switch card.status {
        case .on:     .nickAccent
        case .paused: .nickWarningText
        case .off:    .nickSecondaryText
        }
    }

    private var tileFill: Color {
        switch card.status {
        case .on:     .nickAccentTint
        case .paused: .nickWarningBackground
        case .off:    .nickNeutralTile
        }
    }

    var body: some View {
        HStack(alignment: .top, spacing: 14) {
            Image(systemName: card.icon)
                .font(.system(size: 17, weight: .medium))
                .foregroundStyle(tileForeground)
                .symbolEffect(.bounce, options: .nonRepeating, value: reduceMotion ? 0 : statusBounce)
                .frame(width: 38, height: 38)
                .background(
                    RoundedRectangle(cornerRadius: NickLayout.iconTileCornerRadius, style: .continuous)
                        .fill(tileFill)
                )
            VStack(alignment: .leading, spacing: 4) {
                HStack(spacing: 8) {
                    Text(card.title)
                        .font(.system(size: 14, weight: .semibold))
                        .foregroundStyle(Color.textPrimary)
                    Spacer(minLength: 4)
                    StatusChip(text: card.status.rawValue, textColor: tileForeground, fillColor: tileFill)
                }
                .animation(HomeMotion.animation(HomeMotion.stateChange, reduceMotion: reduceMotion),
                           value: card.status)
                Text(card.detail)
                    .font(.system(size: 12))
                    .foregroundStyle(Color.nickSecondaryText)
                    .fixedSize(horizontal: false, vertical: true)
                    .multilineTextAlignment(.leading)
            }
        }
        .padding(18)
        .frame(maxWidth: .infinity, alignment: .leading)
        .nickSurface()
        .shadow(color: .black.opacity(hovering ? 0.10 : 0.04), radius: hovering ? 6 : 2, y: hovering ? 3 : 1)
        .scaleEffect(hovering && !reduceMotion ? 1.01 : 1)
        .animation(HomeMotion.animation(HomeMotion.hover, reduceMotion: reduceMotion), value: hovering)
        .contentShape(Rectangle())
        .onHover { hovering = $0 }
        .onAppear { appearedAt = Date() }
        .onChange(of: card.status) {
            // One bounce per real change. Skip the settle right after Home
            // appears (the first heartbeat read can flip On to Paused).
            guard !reduceMotion, Date().timeIntervalSince(appearedAt) > 1.5 else { return }
            statusBounce += 1
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(card.title), \(card.status.rawValue). \(card.detail)")
    }
}

/// Status conveyed by a word as well as a colour.
struct StatusChip: View {
    let text: String
    let textColor: Color
    let fillColor: Color

    var body: some View {
        HStack(spacing: 5) {
            Circle().fill(textColor).frame(width: 6, height: 6)
            Text(text)
                .contentTransition(.opacity)
        }
        .font(.system(size: 11, weight: .semibold))
        .foregroundStyle(textColor)
        .padding(.horizontal, 8)
        .padding(.vertical, 2)
        .background(Capsule().fill(fillColor))
    }
}

// MARK: - MacSettingsBar

struct MacSettingsBar: View {
    let summary: MacSettingsSummary
    let fix: (MacSettingsSummary.Fix) -> Void

    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        HStack(spacing: 14) {
            Image(systemName: "desktopcomputer")
                .font(.system(size: 17, weight: .medium))
                .foregroundStyle(Color.textSecondary)
                .frame(width: 38, height: 38)
                .background(
                    RoundedRectangle(cornerRadius: NickLayout.iconTileCornerRadius, style: .continuous)
                        .fill(Color.nickNeutralTile)
                )
            VStack(alignment: .leading, spacing: 6) {
                HStack(alignment: .firstTextBaseline, spacing: 8) {
                    Text("Mac security settings")
                        .font(.system(size: 14, weight: .semibold))
                    Text(summary.headline)
                        .font(.system(size: 12))
                        .foregroundStyle(Color.nickSecondaryText)
                        .contentTransition(.numericText())
                        .animation(HomeMotion.animation(HomeMotion.stateChange, reduceMotion: reduceMotion),
                                   value: summary.headline)
                }
                if summary.total > 0 {
                    HStack(spacing: 4) {
                        ForEach(Array(summary.segments.enumerated()), id: \.offset) { _, isOn in
                            Capsule()
                                .fill(isOn ? Color.nickAccent : Color.nickNeutralTile)
                                .frame(height: 5)
                        }
                    }
                    .accessibilityHidden(true)
                }
            }
            .accessibilityElement(children: .combine)
            Spacer(minLength: 8)
            if let action = summary.fix {
                Button(action.title) { fix(action) }
                    .buttonStyle(.bordered)
                    .buttonBorderShape(.capsule)
                    .controlSize(.regular)
            }
        }
        .padding(.horizontal, 18)
        .padding(.vertical, 16)
        .nickSurface()
    }
}

// MARK: - ActivityLineView

struct ActivityLineView: View {
    let line: HomeActivityLine

    private var colors: (Color, Color) {
        switch line.tone {
        case .good:    (.nickAccent, .nickAccentTint)
        case .warning: (.nickWarningText, .nickWarningBackground)
        case .danger:  (.nickDangerText, .nickDangerBackground)
        case .neutral: (.textSecondary, .nickNeutralTile)
        }
    }

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: line.icon)
                .font(.system(size: 12, weight: .semibold))
                .foregroundStyle(colors.0)
                .frame(width: 28, height: 28)
                .background(Circle().fill(colors.1))
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 2) {
                Text(line.text)
                    .font(.system(size: 13, weight: .medium))
                    .fixedSize(horizontal: false, vertical: true)
                Text(line.isSummary ? HomeFormatting.day(line.date) : HomeFormatting.dayAndTime(line.date))
                    .font(.system(size: 11))
                    .foregroundStyle(Color.nickSecondaryText)
            }
            Spacer(minLength: 0)
        }
        .padding(.vertical, 11)
        .accessibilityElement(children: .combine)
    }
}

// MARK: - QuarantineIncidentSheet

/// Plain summary of a file Nick moved to Quarantine, opened from the hero.
struct QuarantineIncidentSheet: View {
    let record: QuarantineRecord
    let done: () -> Void

    private var name: String { (record.originalPath as NSString).lastPathComponent }

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            HStack(alignment: .top, spacing: 14) {
                Image(systemName: "archivebox")
                    .font(.system(size: 24, weight: .medium))
                    .foregroundStyle(Color.nickDangerText)
                    .frame(width: 56, height: 56)
                    .background(
                        RoundedRectangle(cornerRadius: 14, style: .continuous)
                            .fill(Color.nickDangerBackground)
                    )
                VStack(alignment: .leading, spacing: 4) {
                    Text("Nick stopped a harmful app")
                        .font(.system(size: 22, weight: .semibold))
                    Text("\(HomeFormatting.dayAndTime(record.quarantinedAt)) · Your files and passwords are safe")
                        .font(.system(size: 13))
                        .foregroundStyle(Color.nickSecondaryText)
                }
                Spacer()
                StatusChip(text: "Blocked", textColor: .nickDangerText, fillColor: .nickDangerBackground)
            }

            row("WHAT HAPPENED", "“\(name)” looked harmful.")
            row("WHAT NICK DID", "Moved it to Quarantine, where it can’t run or change anything.")
            row("WHAT YOU SHOULD DO", "Nothing right now. If you don’t recognise it, you can delete it from Activity.")

            HStack {
                Spacer()
                Button("Done", action: done)
                    .keyboardShortcut(.defaultAction)
            }
        }
        .padding(28)
        .frame(width: 560)
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
}

private extension String {
    var lowercasedFirst: String {
        guard let first else { return self }
        return first.lowercased() + dropFirst()
    }
}
