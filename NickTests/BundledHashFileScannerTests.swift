import CryptoKit
import XCTest
@testable import Nick

final class BundledHashFileScannerTests: XCTestCase {
    func test_bundledCatalogDetectsStandardEICARByExactHash() throws {
        let eicar = Data(#"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"#.utf8)
        let fixture = try temporaryFile(contents: eicar)
        defer { try? FileManager.default.removeItem(at: fixture) }

        let scanner = try BundledHashFileScanner(bundle: .main)
        let match = try XCTUnwrap(scanner.scanFile(at: fixture))

        XCTAssertEqual(
            match.metadata["sha256"],
            "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
        )
        XCTAssertEqual(match.metadata["class"], "signature")
        XCTAssertEqual(match.metadata["family"], "Test")
    }

    func test_exactHashMatchReturnsSignatureMetadata() throws {
        let fixture = try temporaryFile(contents: Data("known threat".utf8))
        defer { try? FileManager.default.removeItem(at: fixture) }
        let hash = SHA256.hash(data: Data("known threat".utf8)).hexString
        let scanner = BundledHashFileScanner(entries: [
            .init(hash: hash, name: "Known fixture", family: "Test", severity: "critical")
        ])

        let match = try XCTUnwrap(scanner.scanFile(at: fixture))

        XCTAssertEqual(match.ruleName, "Known fixture")
        XCTAssertEqual(match.filePath, fixture.path)
        XCTAssertEqual(match.metadata["class"], "signature")
        XCTAssertEqual(match.metadata["severity"], "critical")
        XCTAssertEqual(match.metadata["sha256"], hash)
    }

    func test_cleanFileDoesNotMatchCatalog() throws {
        let fixture = try temporaryFile(contents: Data("clean".utf8))
        defer { try? FileManager.default.removeItem(at: fixture) }
        let scanner = BundledHashFileScanner(entries: [
            .init(
                hash: String(repeating: "a", count: 64),
                name: "Other",
                family: "Test",
                severity: "low"
            )
        ])

        XCTAssertNil(try scanner.scanFile(at: fixture))
    }

    func test_missingCatalogFailsInsteadOfReportingClean() {
        let emptyBundle = Bundle(path: NSTemporaryDirectory()) ?? .main
        XCTAssertThrowsError(try BundledHashFileScanner(bundle: emptyBundle)) { error in
            XCTAssertEqual(error as? BundledHashFileScanner.ScannerError, .catalogMissing)
        }
    }

    func test_unreadableFileFailsInsteadOfReportingClean() {
        let scanner = BundledHashFileScanner(entries: [])
        let missing = URL(fileURLWithPath: "/private/tmp/nick-missing-hash-scan-fixture")
        XCTAssertThrowsError(try scanner.scanFile(at: missing)) { error in
            XCTAssertEqual(
                error as? BundledHashFileScanner.ScannerError,
                .fileUnreadable(missing.path)
            )
        }
    }

    private func temporaryFile(contents: Data) throws -> URL {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("nick-hash-scanner-\(UUID().uuidString)")
        try contents.write(to: url, options: .atomic)
        return url
    }
}

private extension SHA256.Digest {
    var hexString: String { map { String(format: "%02x", $0) }.joined() }
}
