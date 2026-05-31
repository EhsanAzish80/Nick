// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation

/// Scans `~/Library/Messages/Attachments` for large message attachments.
struct MessagesAttachmentsRule: ScanRule {
    let category = JunkCategory.messagesAttachments
    let displayName = "Messages Attachments"

    func scan() async -> [JunkItem] {
        let root = ScanRuleHelpers.homeURL("Library", "Messages", "Attachments")
        guard ScanRuleHelpers.exists(root) else { return [] }
        let size = ScanRuleHelpers.size(of: root)
        guard size > 0 else { return [] }
        return [JunkItem(url: root, size: size, category: category,
                         riskLevel: .review, name: "Messages Attachments",
                         reason: "Attachments received via iMessage/SMS — clearing removes them from Messages.app.")]
    }
}
