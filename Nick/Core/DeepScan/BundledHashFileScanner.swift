import CryptoKit
import Foundation

/// Matches manually scanned files against Nick's validated, bundled SHA-256 catalog.
struct BundledHashFileScanner: Sendable {
    enum ScannerError: LocalizedError, Equatable {
        case catalogMissing
        case catalogUnreadable
        case fileUnreadable(String)

        var errorDescription: String? {
            switch self {
            case .catalogMissing:
                return "Nick's exact-hash threat catalog is missing from this build."
            case .catalogUnreadable:
                return "Nick's exact-hash threat catalog could not be validated."
            case .fileUnreadable(let path):
                return "Cannot read file for exact-hash scan: \(path)."
            }
        }
    }

    private let entriesByHash: [String: BundledHashCatalog.Entry]

    init(entries: [BundledHashCatalog.Entry]) {
        entriesByHash = Dictionary(uniqueKeysWithValues: entries.map { ($0.hash, $0) })
    }

    init(bundle: Bundle) throws {
        guard let url = bundle.url(forResource: "known-threat-hashes", withExtension: "json") else {
            throw ScannerError.catalogMissing
        }
        do {
            let catalog = try JSONDecoder().decode(
                BundledHashCatalog.self,
                from: Data(contentsOf: url)
            )
            self.init(entries: try catalog.validatedEntries())
        } catch {
            throw ScannerError.catalogUnreadable
        }
    }

    func scanFile(at url: URL) throws -> YARAMatch? {
        let hash = try sha256(of: url)
        guard let entry = entriesByHash[hash] else { return nil }
        return YARAMatch(
            ruleName: entry.name,
            tags: ["signature", entry.family],
            filePath: url.path,
            metadata: [
                "class": "signature",
                "description": "Exact SHA-256 match for \(entry.name)",
                "family": entry.family,
                "severity": entry.severity,
                "sha256": hash,
            ]
        )
    }

    func scanDirectory(at root: URL) throws -> [YARAMatch] {
        let keys: [URLResourceKey] = [.isDirectoryKey, .isRegularFileKey, .isSymbolicLinkKey]
        guard let enumerator = FileManager.default.enumerator(
            at: root,
            includingPropertiesForKeys: keys,
            options: [.skipsHiddenFiles, .skipsPackageDescendants]
        ) else {
            throw ScannerError.fileUnreadable(root.path)
        }

        var matches: [YARAMatch] = []
        for case let url as URL in enumerator {
            let values = try? url.resourceValues(forKeys: Set(keys))
            if values?.isDirectory == true || values?.isSymbolicLink == true { continue }
            guard values?.isRegularFile == true else { continue }
            if let match = try scanFile(at: url) {
                matches.append(match)
            }
        }
        return matches
    }

    private func sha256(of url: URL) throws -> String {
        guard let handle = try? FileHandle(forReadingFrom: url) else {
            throw ScannerError.fileUnreadable(url.path)
        }
        defer { try? handle.close() }

        var hasher = SHA256()
        do {
            while true {
                let data = try handle.read(upToCount: 1_048_576) ?? Data()
                if data.isEmpty { break }
                hasher.update(data: data)
            }
        } catch {
            throw ScannerError.fileUnreadable(url.path)
        }
        return hasher.finalize().map { String(format: "%02x", $0) }.joined()
    }
}
