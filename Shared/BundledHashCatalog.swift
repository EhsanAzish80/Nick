import Foundation

struct BundledHashCatalog: Codable, Sendable {
    struct Entry: Codable, Sendable, Equatable {
        let hash: String
        let name: String
        let family: String
        let severity: String
    }

    let version: Int
    let entries: [Entry]

    var validatedEntries: [Entry] {
        let allowedSeverities: Set<String> = ["low", "medium", "high", "critical"]
        return entries.compactMap { entry in
            let normalized = Entry(
                hash: entry.hash.lowercased(),
                name: entry.name.trimmingCharacters(in: .whitespacesAndNewlines),
                family: entry.family.trimmingCharacters(in: .whitespacesAndNewlines),
                severity: entry.severity.lowercased()
            )
            guard normalized.hash.count == 64,
                  normalized.hash.allSatisfy(\.isHexDigit),
                  !normalized.name.isEmpty,
                  !normalized.family.isEmpty,
                  allowedSeverities.contains(normalized.severity)
            else { return nil }
            return normalized
        }
    }
}
