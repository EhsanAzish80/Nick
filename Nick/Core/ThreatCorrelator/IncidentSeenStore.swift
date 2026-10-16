// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation

/// Per-user presentation state for Activity badges. This deliberately stays
/// outside the root-owned evidence store: seeing an incident is not a security
/// verdict and must not change its review status.
final class IncidentSeenStore: @unchecked Sendable {
    private static let storageKey = "nickSeenIncidentOccurrencesV1"

    private let defaults: UserDefaults
    private let lock = NSLock()
    private var seenOccurrences: [String: Int]

    init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
        self.seenOccurrences = defaults.dictionary(forKey: Self.storageKey)?
            .compactMapValues { ($0 as? NSNumber)?.intValue } ?? [:]
    }

    func isUnseen(id: UUID, occurrenceCount: Int) -> Bool {
        lock.withLock {
            seenOccurrences[id.uuidString, default: 0] < max(1, occurrenceCount)
        }
    }

    func markSeen(id: UUID, occurrenceCount: Int) {
        lock.withLock {
            let key = id.uuidString
            seenOccurrences[key] = max(seenOccurrences[key, default: 0], max(1, occurrenceCount))
            defaults.set(seenOccurrences, forKey: Self.storageKey)
        }
    }

    func unseenCount(in incidents: [SecurityIncident]) -> Int {
        incidents.filter {
            $0.isVisible
                && $0.displayStatus.contributesToProtectionStatus
                && isUnseen(id: $0.alert.id, occurrenceCount: $0.alert.occurrenceCount)
        }.count
    }
}
