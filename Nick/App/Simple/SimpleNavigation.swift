// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import SwiftUI

// MARK: - SimpleSection

/// The Simple interface's destinations: four items plus Settings.
enum SimpleSection: String, CaseIterable, Identifiable, Hashable, Sendable {
    case home
    case scan
    case activity
    case protection
    case settings

    var id: String { rawValue }

    var title: String {
        switch self {
        case .home:       "Home"
        case .scan:       "Scan"
        case .activity:   "Activity"
        case .protection: "Protection"
        case .settings:   "Settings"
        }
    }

    var icon: String {
        switch self {
        case .home:       "shield"
        case .scan:       "magnifyingglass"
        case .activity:   "bell"
        case .protection: "slider.horizontal.3"
        case .settings:   "gearshape"
        }
    }

    /// The four main destinations (Settings sits at the bottom).
    static let primary: [SimpleSection] = [.home, .scan, .activity, .protection]
}

// MARK: - Mode switch routing

/// Keeps the user on the equivalent page when the interface mode changes.
enum InterfaceModeRouting {

    static func simpleSection(for section: SidebarSection?) -> SimpleSection {
        switch section ?? .overview {
        case .overview:              .home
        case .smartScan, .scan:      .scan
        case .alerts, .quarantine:   .activity
        case .settings:              .settings
        default:                     .home
        }
    }

    static func advancedSection(for section: SimpleSection?) -> SidebarSection {
        switch section ?? .home {
        case .home:       .overview
        case .scan:       .smartScan
        case .activity:   .alerts
        case .protection: .settings
        case .settings:   .settings
        }
    }
}

// MARK: - SimpleSidebar

/// Four items plus Settings, no section headers.
struct SimpleSidebar: View {
    @Binding var selection: SimpleSection?
    let activityBadge: Int

    var body: some View {
        List(selection: $selection) {
            ForEach(SimpleSection.primary) { section in
                row(section, badge: section == .activity ? activityBadge : 0)
                    .tag(section)
            }
        }
        // Settings sits at the bottom of the sidebar, apart from the four
        // main destinations.
        .safeAreaInset(edge: .bottom) {
            Button { selection = .settings } label: {
                row(.settings, badge: 0)
                    .padding(.horizontal, 10)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(
                        RoundedRectangle(cornerRadius: 8, style: .continuous)
                            .fill(selection == .settings ? Color.primary.opacity(0.08) : .clear)
                    )
                    .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .padding(.horizontal, 10)
            .padding(.bottom, 10)
            .accessibilityAddTraits(selection == .settings ? .isSelected : [])
        }
        .navigationSplitViewColumnWidth(min: 200, ideal: 220)
        .navigationTitle("Nick")
    }

    private func row(_ section: SimpleSection, badge: Int) -> some View {
        Label {
            HStack {
                Text(section.title)
                    .font(.system(size: 14, weight: selection == section ? .semibold : .regular))
                Spacer()
                if badge > 0 {
                    Text("\(badge)")
                        .font(.system(size: 11, weight: .bold))
                        .monospacedDigit()
                        .foregroundStyle(.white)
                        .padding(.horizontal, 6)
                        .padding(.vertical, 1)
                        .background(Capsule().fill(Color.nickDangerText))
                        .accessibilityLabel("\(badge) need attention")
                }
            }
        } icon: {
            Image(systemName: section.icon)
                .font(.system(size: 15))
                .foregroundStyle(selection == section ? Color.nickAccent : Color.nickSecondaryText)
        }
        .frame(minHeight: 30)
    }
}
