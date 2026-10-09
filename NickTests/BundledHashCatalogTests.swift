import XCTest
@testable import Nick

final class BundledHashCatalogTests: XCTestCase {
    func test_catalogValidationNormalizesValidEntry() throws {
        let validHash = String(repeating: "A", count: 64)
        let catalog = BundledHashCatalog(version: 2, retrievedAt: "2026-10-09T00:00:00Z", entries: [
            .init(hash: validHash, name: " EICAR test ", family: " Test ", severity: "HIGH"),
        ])

        XCTAssertEqual(try catalog.validatedEntries(), [
            .init(hash: validHash.lowercased(), name: "EICAR test", family: "Test", severity: "high")
        ])
    }

    func test_catalogRejectsMalformedEntryInsteadOfPartiallyLoading() {
        let catalog = BundledHashCatalog(
            version: 2,
            retrievedAt: "2026-10-09T00:00:00Z",
            entries: [.init(hash: "not-a-hash", name: "Bad", family: "Test", severity: "critical")]
        )

        XCTAssertThrowsError(try catalog.validatedEntries()) { error in
            XCTAssertEqual(error as? BundledHashCatalog.ValidationError, .malformedEntry(index: 0))
        }
    }

    func test_catalogRejectsEntriesBeyondTheSizeCap() {
        let entry = BundledHashCatalog.Entry(
            hash: String(repeating: "a", count: 64),
            name: "Fixture",
            family: "Test",
            severity: "low"
        )
        let catalog = BundledHashCatalog(
            version: 2,
            retrievedAt: "2026-10-09T00:00:00Z",
            entries: Array(repeating: entry, count: BundledHashCatalog.maximumEntryCount + 1)
        )

        XCTAssertThrowsError(try catalog.validatedEntries()) { error in
            XCTAssertEqual(
                error as? BundledHashCatalog.ValidationError,
                .tooManyEntries(actual: 5_001, maximum: 5_000)
            )
        }
    }

    func test_bundledCatalogContainsKnownEICARHash() throws {
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
        let data = try Data(contentsOf: root.appendingPathComponent("NickExtension/known-threat-hashes.json"))
        let catalog = try JSONDecoder().decode(BundledHashCatalog.self, from: data)

        XCTAssertGreaterThan(catalog.version, 0)
        let entries = try catalog.validatedEntries()
        XCTAssertEqual(entries.count, 25)
        XCTAssertEqual(catalog.retrievedAt, "2026-10-09T00:00:00Z")
        XCTAssertTrue(entries.contains {
            $0.hash == "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
                && $0.family == "Test"
                && $0.severity == "low"
        })

        let knownHash = "BBBFE62CF15006014E356885FBC7447E3FD37C3743E0522B1F8320AD5C3791C9"
        let match = try catalog.entry(matchingSHA256: knownHash)
        XCTAssertEqual(match?.family, "DazzleSpy")
        XCTAssertEqual(match?.severity, "high")
    }

    func test_provenanceManifestMatchesCatalogAndDocumentsCap() throws {
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
        let manifestData = try Data(contentsOf: root.appendingPathComponent(
            "NickExtension/known-threat-hashes.provenance.json"
        ))
        let catalogData = try Data(contentsOf: root.appendingPathComponent(
            "NickExtension/known-threat-hashes.json"
        ))
        let manifest = try XCTUnwrap(
            JSONSerialization.jsonObject(with: manifestData) as? [String: Any]
        )
        let catalog = try JSONDecoder().decode(BundledHashCatalog.self, from: catalogData)

        XCTAssertEqual(manifest["catalogVersion"] as? Int, catalog.version)
        XCTAssertEqual(manifest["retrievedAt"] as? String, catalog.retrievedAt)
        XCTAssertEqual(manifest["entryCount"] as? Int, try catalog.validatedEntries().count)
        XCTAssertEqual(manifest["maximumEntries"] as? Int, BundledHashCatalog.maximumEntryCount)

        let sources = try XCTUnwrap(manifest["sources"] as? [[String: Any]])
        let eset = try XCTUnwrap(sources.first { $0["name"] as? String == "ESET malware-ioc" })
        XCTAssertEqual(eset["licence"] as? String, "BSD-2-Clause")
        XCTAssertEqual(
            eset["commit"] as? String,
            "17baf44964a77368e9149f4f593eb098beddf1c5"
        )
    }

    func test_esetBSDNoticeShipsInsideHostAppResources() throws {
        let noticeURL = try XCTUnwrap(Bundle.main.url(
            forResource: "eset",
            withExtension: "txt",
            subdirectory: "Rules/families/LICENSES"
        ))
        let notice = try String(contentsOf: noticeURL, encoding: .utf8)
        XCTAssertTrue(notice.contains("Redistribution and use in source and binary forms"))
        XCTAssertTrue(notice.contains("Copyright (c) 2014-2018 ESET"))
    }
}
