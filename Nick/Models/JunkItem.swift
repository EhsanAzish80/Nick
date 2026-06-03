// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation

// MARK: - RiskLevel

/// How cautious the cleanup UI should be before removing a `JunkItem`.
public enum RiskLevel: String, Codable, Sendable, CaseIterable {

    /// Safe to remove automatically — the system will recreate it if needed.
    case safe     = "safe"

    /// Remove only after user confirmation — data may be valuable.
    case review   = "review"

    /// Advanced users only — removal may break things if done incorrectly.
    case advanced = "advanced"

    var displayName: String {
        switch self {
        case .safe:     return "Safe to Clean"
        case .review:   return "Review First"
        case .advanced: return "Advanced"
        }
    }
}

// MARK: - JunkItem

/// A single file or directory identified as reclaimable disk space.
public struct JunkItem: Identifiable, Codable, Sendable, Hashable {

    public let id: UUID
    /// Absolute URL of the file or directory.
    public let url: URL
    /// Disk size in bytes. Computed by `SizeCalculator`.
    public let size: Int64
    /// Category for grouping in the UI.
    public let category: JunkCategory
    /// How confidently this item can be removed.
    public let riskLevel: RiskLevel
    /// Short human-readable label (typically the file/folder name).
    public let name: String
    /// Why this item is considered junk (shown in detail view).
    public let reason: String
    /// Whether this item was selected for cleanup.
    public var isSelected: Bool

    public init(
        url: URL,
        size: Int64,
        category: JunkCategory,
        riskLevel: RiskLevel,
        name: String,
        reason: String,
        isSelected: Bool = true
    ) {
        self.id = UUID()
        self.url = url
        self.size = size
        self.category = category
        self.riskLevel = riskLevel
        self.name = name
        self.reason = reason
        self.isSelected = isSelected
    }

    // Convenience: absolute path string
    public var path: String { url.path }
}
