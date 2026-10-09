import Foundation

struct BundledHashCatalog: Codable, Sendable {
    static let maximumEntryCount = 5_000

    struct Entry: Codable, Sendable, Equatable {
        let hash: String
        let name: String
        let family: String
        let severity: String
    }

    let version: Int
    let retrievedAt: String
    let entries: [Entry]

    enum ValidationError: Error, Equatable {
        case invalidVersion
        case invalidRetrievalDate
        case tooManyEntries(actual: Int, maximum: Int)
        case malformedEntry(index: Int)
        case duplicateHash(String)
    }

    func validatedEntries() throws -> [Entry] {
        guard version > 0 else { throw ValidationError.invalidVersion }
        guard ISO8601DateFormatter().date(from: retrievedAt) != nil else {
            throw ValidationError.invalidRetrievalDate
        }
        guard entries.count <= Self.maximumEntryCount else {
            throw ValidationError.tooManyEntries(
                actual: entries.count,
                maximum: Self.maximumEntryCount
            )
        }

        let allowedSeverities: Set<String> = ["low", "medium", "high", "critical"]
        var seenHashes = Set<String>()
        return try entries.enumerated().map { index, entry in
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
            else { throw ValidationError.malformedEntry(index: index) }
            guard seenHashes.insert(normalized.hash).inserted else {
                throw ValidationError.duplicateHash(normalized.hash)
            }
            return normalized
        }
    }

    func entry(matchingSHA256 hash: String) throws -> Entry? {
        let normalizedHash = hash.lowercased()
        return try validatedEntries().first { $0.hash == normalizedHash }
    }
}
