import Foundation

enum RuntimeSnapshotComparator {
    static func compare(baseline: RuntimeSnapshot, followUp: RuntimeSnapshot) -> [RuntimeFinding] {
        var findings: [RuntimeFinding] = []
        findings += qualityFindings(baseline: baseline, followUp: followUp)
        // A reboot replaces most short-lived processes by design. Comparing the
        // two point-in-time inventories across boot sessions produces hundreds
        // of technically true but useless "no longer observed" findings.
        if sameBootSession(baseline, followUp),
           canCompareComplete(provider: "Processes", baseline: baseline, followUp: followUp) {
            findings += differences(
            before: baseline.processes, after: followUp.processes,
            key: \.stableKey, category: .process,
            addedTitle: { "Process appeared: \($0.name)" },
            removedTitle: { "Process no longer observed: \($0.name)" },
            addedExplanation: { "Nick observed \($0.path.isEmpty ? $0.name : $0.path) running in the follow-up capture." },
            removedExplanation: { _ in "Nick observed this process in the baseline but not in the follow-up process snapshot." },
            attention: { $0.signingState.contains("Unsigned") || $0.signingState.contains("Invalid") ? .important : .informational },
            limitation: "A point-in-time process snapshot cannot prove when or why a process started or stopped."
            )
        }
        if canCompareComplete(provider: "Connections", baseline: baseline, followUp: followUp) {
            findings += differences(
            before: baseline.listeners, after: followUp.listeners,
            key: \.stableKey, category: .listener,
            addedTitle: { "New listening port: \($0.ownerName) on \($0.localPort)" },
            removedTitle: { "Listener no longer observed: \($0.ownerName) on \($0.localPort)" },
            addedExplanation: { "\($0.ownerName) was accepting \($0.transport) connections on \($0.localAddress):\($0.localPort) in the follow-up." },
            removedExplanation: { _ in "This listener was present in the baseline but not in the follow-up snapshot." },
            attention: { RuntimeIdentity.addressScope($0.localAddress) == "wildcard" ? .review : .informational },
            limitation: "Listener state is a point-in-time observation."
            )
            findings += connectionDifferences(baseline: baseline, followUp: followUp)
        }
        findings += persistenceDifferences(baseline: baseline, followUp: followUp)
        findings += extensionDifferences(baseline: baseline, followUp: followUp)
        return findings.sorted {
            if $0.attention != $1.attention { return $0.attention > $1.attention }
            if $0.category != $1.category { return $0.category.rawValue < $1.category.rawValue }
            return $0.title < $1.title
        }
    }

    private static func qualityFindings(baseline: RuntimeSnapshot, followUp: RuntimeSnapshot) -> [RuntimeFinding] {
        var result: [RuntimeFinding] = []
        if baseline.bootSessionIdentifier != followUp.bootSessionIdentifier {
            result.append(finding(
                category: .sensor, change: .quality, evidence: .observed, attention: .review,
                key: "boot-session", title: "Captures were made in different boot sessions",
                explanation: "PID and short-lived runtime state naturally change after a restart.",
                limitation: "Nick uses stable owner identities where possible and does not treat PID changes as findings.", refs: []
            ))
        }
        if baseline.configuration.requestedObservationSeconds != followUp.configuration.requestedObservationSeconds {
            result.append(finding(
                category: .sensor, change: .quality, evidence: .observed, attention: .review,
                key: "observation-window", title: "Connection observation windows differ",
                explanation: "The captures observed connections for different durations.",
                limitation: "A longer window is more likely to observe short-lived connections.", refs: []
            ))
        }
        if baseline.sensorHealth != followUp.sensorHealth {
            result.append(finding(
                category: .sensor, change: .quality, evidence: .observed, attention: .important,
                key: "sensor-health", title: "Sensor availability changed between captures",
                explanation: "Endpoint Security or Network Filter health was not equivalent in both captures.",
                limitation: "Categories that depend on an unavailable sensor may be incomplete.", refs: []
            ))
        }
        for provider in Set((baseline.providerHealth + followUp.providerHealth).filter { $0.state != .available }.map(\.provider)) {
            result.append(finding(
                category: .sensor, change: .quality, evidence: .cannotConfirm, attention: .review,
                key: "provider-\(provider)", title: "\(provider) evidence is incomplete",
                explanation: "At least one capture reported partial or unavailable \(provider) data.",
                limitation: "Nick cannot confirm all changes in this category.", refs: []
            ))
        }
        return result
    }

    private static func connectionDifferences(baseline: RuntimeSnapshot, followUp: RuntimeSnapshot) -> [RuntimeFinding] {
        differences(
            before: baseline.connections, after: followUp.connections,
            key: \.stableKey, category: .connection,
            addedTitle: { "New destination observed for \($0.ownerName)" },
            removedTitle: { "Destination not observed again for \($0.ownerName)" },
            addedExplanation: { "Nick observed \($0.ownerName) connect to \($0.remoteAddress):\($0.remotePort) during the follow-up window." },
            removedExplanation: { _ in "This destination appeared during the baseline window but not during the follow-up window." },
            attention: { _ in .review },
            limitation: "Not observed does not mean the connection is disabled or cannot occur."
        )
    }

    private static func persistenceDifferences(baseline: RuntimeSnapshot, followUp: RuntimeSnapshot) -> [RuntimeFinding] {
        guard canCompareAtAll(provider: "Persistence", baseline: baseline, followUp: followUp) else { return [] }
        let complete = canCompareComplete(provider: "Persistence", baseline: baseline, followUp: followUp)
        var result = complete ? differences(
                before: baseline.persistence, after: followUp.persistence,
                key: \.stableKey, category: .persistence,
                addedTitle: { "Persistence item added: \($0.name)" },
                removedTitle: { "Persistence item removed: \($0.name)" },
                addedExplanation: { "Nick observed a new \($0.type) at \($0.path)." },
                removedExplanation: { "Nick no longer observed the \($0.type) at \($0.path)." },
                attention: { $0.isEnabled ? .review : .informational }, limitation: nil
            ) : []
        let before = indexedByStableKey(baseline.persistence, key: \.stableKey)
        for item in followUp.persistence {
            guard let old = before[item.stableKey], old.isEnabled != item.isEnabled || old.executablePath != item.executablePath else { continue }
            result.append(finding(
                category: .persistence, change: .changed, evidence: .observed, attention: .review,
                key: item.stableKey, title: "Persistence item changed: \(item.name)",
                explanation: "Enabled state or executable path changed between captures.",
                limitation: complete ? nil : "At least one persistence inventory was partial; this finding uses matching records observed in both captures.",
                refs: [old.id, item.id]
            ))
        }
        return result
    }

    private static func extensionDifferences(baseline: RuntimeSnapshot, followUp: RuntimeSnapshot) -> [RuntimeFinding] {
        guard canCompareAtAll(provider: "Extensions", baseline: baseline, followUp: followUp) else { return [] }
        let complete = canCompareComplete(provider: "Extensions", baseline: baseline, followUp: followUp)
        var result = complete ? differences(
            before: baseline.extensions, after: followUp.extensions,
            key: \.stableKey, category: .systemExtension,
            addedTitle: { "Extension appeared: \($0.bundleIdentifier)" },
            removedTitle: { "Extension no longer listed: \($0.bundleIdentifier)" },
            addedExplanation: { "macOS listed this \($0.category.rawValue) extension in the follow-up capture." },
            removedExplanation: { _ in "macOS listed this extension in the baseline but not in the follow-up." },
            attention: { $0.isActivated && $0.isEnabled ? .review : .informational },
            limitation: "Nick cannot infer MDM intent, ownership, or whether an absent extension is orphaned."
        ) : []
        let before = indexedExtensionsByStableKey(baseline.extensions)
        for item in followUp.extensions {
            guard let old = before[item.stableKey],
                  old.isActivated != item.isActivated || old.isEnabled != item.isEnabled || old.version != item.version else { continue }
            result.append(finding(
                category: .systemExtension, change: .changed, evidence: .observed,
                attention: (old.isEnabled && !item.isEnabled) ? .important : .review,
                key: item.stableKey, title: "Extension state changed: \(item.bundleIdentifier)",
                explanation: "Version, activation, or enabled state changed between captures.",
                limitation: complete
                    ? "This is observed extension state, not proof of the change's cause."
                    : "At least one extension inventory was partial; this finding uses matching records observed in both captures.",
                refs: [old.id, item.id]
            ))
        }
        return result
    }

    private static func canCompareComplete(
        provider: String, baseline: RuntimeSnapshot, followUp: RuntimeSnapshot
    ) -> Bool {
        providerState(provider, in: baseline) == .available
            && providerState(provider, in: followUp) == .available
    }

    private static func sameBootSession(_ baseline: RuntimeSnapshot, _ followUp: RuntimeSnapshot) -> Bool {
        baseline.bootSessionIdentifier == followUp.bootSessionIdentifier
    }

    /// `systemextensionsctl` can briefly report the retiring and active copy of
    /// the same extension during an update. Prefer the active record so input
    /// ordering cannot manufacture a disabled-state transition.
    private static func indexedExtensionsByStableKey(
        _ values: [RuntimeExtensionRecord]
    ) -> [String: RuntimeExtensionRecord] {
        Dictionary(values.map { ($0.stableKey, $0) }, uniquingKeysWith: { current, candidate in
            let currentRank = (current.isActivated ? 2 : 0) + (current.isEnabled ? 1 : 0)
            let candidateRank = (candidate.isActivated ? 2 : 0) + (candidate.isEnabled ? 1 : 0)
            if currentRank != candidateRank { return currentRank > candidateRank ? current : candidate }
            return current.id <= candidate.id ? current : candidate
        })
    }

    private static func canCompareAtAll(
        provider: String, baseline: RuntimeSnapshot, followUp: RuntimeSnapshot
    ) -> Bool {
        providerState(provider, in: baseline) != .unavailable
            && providerState(provider, in: followUp) != .unavailable
    }

    /// Provider health was added with Runtime Compare. Missing entries are
    /// treated as available for compatibility with early local comparison files;
    /// an explicit partial or unavailable state always limits derived findings.
    private static func providerState(_ provider: String, in snapshot: RuntimeSnapshot) -> RuntimeProviderState {
        snapshot.providerHealth.first { $0.provider == provider }?.state ?? .available
    }

    private static func differences<T>(
        before: [T], after: [T], key: KeyPath<T, String>, category: RuntimeFindingCategory,
        addedTitle: (T) -> String, removedTitle: (T) -> String,
        addedExplanation: (T) -> String, removedExplanation: (T) -> String,
        attention: (T) -> RuntimeAttention, limitation: String?
    ) -> [RuntimeFinding] where T: Identifiable, T.ID == String {
        let old = indexedByStableKey(before, key: key)
        let new = indexedByStableKey(after, key: key)
        var result: [RuntimeFinding] = []
        for (identity, item) in new where old[identity] == nil {
            result.append(finding(category: category, change: .added, evidence: .observed,
                                  attention: attention(item), key: "added-\(identity)",
                                  title: addedTitle(item), explanation: addedExplanation(item),
                                  limitation: limitation, refs: [item.id]))
        }
        for (identity, item) in old where new[identity] == nil {
            result.append(finding(category: category, change: .removed,
                                  evidence: category == .connection ? .inference : .observed,
                                  attention: .informational, key: "removed-\(identity)",
                                  title: removedTitle(item), explanation: removedExplanation(item),
                                  limitation: limitation, refs: [item.id]))
        }
        return result
    }

    /// Real system inventories can briefly contain duplicate logical identities
    /// (for example, overlapping extension records during an update). A runtime
    /// comparison must coalesce those records instead of using
    /// `Dictionary(uniqueKeysWithValues:)`, which traps the entire app.
    private static func indexedByStableKey<T>(
        _ values: [T], key: KeyPath<T, String>
    ) -> [String: T] where T: Identifiable, T.ID == String {
        Dictionary(values.map { ($0[keyPath: key], $0) }, uniquingKeysWith: { current, candidate in
            current.id <= candidate.id ? current : candidate
        })
    }

    private static func finding(
        category: RuntimeFindingCategory, change: RuntimeChangeKind,
        evidence: RuntimeEvidenceLevel, attention: RuntimeAttention, key: String,
        title: String, explanation: String, limitation: String?, refs: [String]
    ) -> RuntimeFinding {
        RuntimeFinding(id: "\(category.rawValue)|\(key)", category: category, change: change,
                       evidence: evidence, attention: attention, title: title,
                       explanation: explanation, limitation: limitation, sourceReferences: refs)
    }
}
