import XCTest
@testable import Nick

final class BundledHashCatalogTests: XCTestCase {
    func test_catalogValidationNormalizesAndRejectsUnsafeEntries() throws {
        let validHash = String(repeating: "A", count: 64)
        let catalog = BundledHashCatalog(version: 2, entries: [
            .init(hash: validHash, name: " EICAR test ", family: " Test ", severity: "HIGH"),
            .init(hash: "not-a-hash", name: "Bad", family: "Test", severity: "critical"),
            .init(hash: String(repeating: "b", count: 64), name: "", family: "Test", severity: "low"),
            .init(hash: String(repeating: "c", count: 64), name: "Bad severity", family: "Test", severity: "urgent")
        ])

        XCTAssertEqual(catalog.validatedEntries, [
            .init(hash: validHash.lowercased(), name: "EICAR test", family: "Test", severity: "high")
        ])
    }

    func test_bundledCatalogContainsKnownEICARHash() throws {
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
        let data = try Data(contentsOf: root.appendingPathComponent("NickExtension/known-threat-hashes.json"))
        let catalog = try JSONDecoder().decode(BundledHashCatalog.self, from: data)

        XCTAssertGreaterThan(catalog.version, 0)
        XCTAssertTrue(catalog.validatedEntries.contains {
            $0.hash == "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
        })
    }
}
