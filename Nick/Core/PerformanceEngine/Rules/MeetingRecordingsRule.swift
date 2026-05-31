// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation

/// Finds Zoom, Teams, and WebEx meeting recordings on Desktop and in Documents.
struct MeetingRecordingsRule: ScanRule {
    let category = JunkCategory.meetingRecordings
    let displayName = "Meeting Recordings"

    func scan() async -> [JunkItem] {
        var items: [JunkItem] = []

        // Well-known default recording folders
        let namedFolders: [(URL, String)] = [
            (ScanRuleHelpers.homeURL("Documents", "Zoom"),     "Zoom Recordings"),
            (ScanRuleHelpers.homeURL("Documents", "Microsoft Teams - Recording"), "Teams Recordings"),
            (ScanRuleHelpers.homeURL("Documents", "Webex Recordings"), "Webex Recordings"),
            (ScanRuleHelpers.homeURL("Desktop", "Zoom"),       "Zoom Recordings (Desktop)"),
        ]

        for (url, label) in namedFolders {
            guard ScanRuleHelpers.exists(url) else { continue }
            let size = ScanRuleHelpers.size(of: url)
            guard size > 0 else { continue }
            items.append(JunkItem(url: url, size: size, category: category,
                                  riskLevel: .review, name: label,
                                  reason: "Meeting recording folder — review and delete recordings you no longer need."))
        }

        return items
    }
}
