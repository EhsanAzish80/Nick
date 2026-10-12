// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import CryptoKit
import Foundation
import XCTest
@testable import Nick

final class QuarantineManagerFailureTests: XCTestCase {
    func test_readOnlyVolumePreflightLeavesVaultEmptyAndOriginalIntact() throws {
        let fixture = try Fixture()
        defer { fixture.cleanup() }
        var moveCalled = false
        let manager = QuarantineManager(
            supportDir: fixture.support.path,
            volumeInfo: { _ in QuarantineVolumeInfo(isReadOnly: true, name: "NickReadOnly") },
            moveItem: { _, _ in moveCalled = true }
        )

        let failure = try XCTUnwrap(manager.quarantineFailure(for: fixture.file, hash: fixture.hash))

        XCTAssertEqual(failure.reason, .readOnlyVolume)
        XCTAssertEqual(failure.errorDomain, NSPOSIXErrorDomain)
        XCTAssertEqual(failure.errorCode, Int(EROFS))
        XCTAssertEqual(failure.volumeName, "NickReadOnly")
        XCTAssertFalse(moveCalled)
        XCTAssertTrue(FileManager.default.fileExists(atPath: fixture.file.path))
        XCTAssertTrue(try fixture.vaultContents().isEmpty)
    }

    func test_copyThenRemoveFailureDeletesVaultCopyAndPreservesOriginal() throws {
        let fixture = try Fixture()
        defer { fixture.cleanup() }
        let manager = QuarantineManager(
            supportDir: fixture.support.path,
            volumeInfo: { _ in QuarantineVolumeInfo(isReadOnly: false, name: "Writable") },
            moveItem: { source, destination in
                try FileManager.default.copyItem(atPath: source, toPath: destination)
                throw CocoaError(.fileWriteVolumeReadOnly)
            }
        )

        let failure = try XCTUnwrap(manager.quarantineFailure(for: fixture.file, hash: fixture.hash))

        XCTAssertEqual(failure.reason, .readOnlyVolume)
        XCTAssertTrue(FileManager.default.fileExists(atPath: fixture.file.path))
        XCTAssertTrue(try fixture.vaultContents().isEmpty)
    }

    func test_cocoaReadOnlyVolumeErrorMapsToReadOnlyVolume() throws {
        let fixture = try Fixture()
        defer { fixture.cleanup() }
        let manager = fixture.manager(throwing: CocoaError(.fileWriteVolumeReadOnly))

        XCTAssertEqual(
            try XCTUnwrap(manager.quarantineFailure(for: fixture.file, hash: fixture.hash)).reason,
            .readOnlyVolume
        )
    }

    func test_underlyingPOSIXEROFSMapsToReadOnlyVolume() throws {
        let fixture = try Fixture()
        defer { fixture.cleanup() }
        let underlying = NSError(domain: NSPOSIXErrorDomain, code: Int(EROFS))
        let error = NSError(
            domain: NSCocoaErrorDomain,
            code: CocoaError.fileWriteUnknown.rawValue,
            userInfo: [NSUnderlyingErrorKey: underlying]
        )
        let manager = fixture.manager(throwing: error)

        let failure = try XCTUnwrap(manager.quarantineFailure(for: fixture.file, hash: fixture.hash))
        XCTAssertEqual(failure.reason, .readOnlyVolume)
        XCTAssertEqual(failure.errorDomain, NSPOSIXErrorDomain)
        XCTAssertEqual(failure.errorCode, Int(EROFS))
    }

    func test_hashMismatchReturnsFileChanged() throws {
        let fixture = try Fixture()
        defer { fixture.cleanup() }
        let manager = fixture.manager(throwing: CocoaError(.fileWriteUnknown))

        let failure = try XCTUnwrap(manager.quarantineFailure(
            for: fixture.file,
            hash: String(repeating: "0", count: 64)
        ))

        XCTAssertEqual(failure.reason, .fileChanged)
        XCTAssertEqual(failure.statusLine, "Quarantine failed — the file changed after Nick reviewed it")
        XCTAssertTrue(FileManager.default.fileExists(atPath: fixture.file.path))
        XCTAssertTrue(try fixture.vaultContents().isEmpty)
    }
}

private extension QuarantineManager {
    func quarantineFailure(for file: URL, hash: String) -> QuarantineFailure? {
        switch quarantine(
            filePath: file.path,
            hash: hash,
            threatName: "EICAR Anti-Malware Test File",
            severity: "high",
            processPath: "",
            pid: 0
        ) {
        case .success:
            XCTFail("Expected quarantine to fail")
            return nil
        case .failure(let failure):
            return failure
        }
    }
}

private final class Fixture {
    let root: URL
    let support: URL
    let file: URL
    let hash: String

    init() throws {
        root = FileManager.default.temporaryDirectory
            .appendingPathComponent("NickQuarantineManagerTests-\(UUID().uuidString)")
        support = root.appendingPathComponent("support")
        file = root.appendingPathComponent("eicar.com")
        try FileManager.default.createDirectory(at: support, withIntermediateDirectories: true)
        let data = Data("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*".utf8)
        try data.write(to: file)
        hash = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    func manager(throwing error: Error) -> QuarantineManager {
        QuarantineManager(
            supportDir: support.path,
            volumeInfo: { _ in QuarantineVolumeInfo(isReadOnly: false, name: "Writable") },
            moveItem: { _, _ in throw error }
        )
    }

    func vaultContents() throws -> [String] {
        try FileManager.default.contentsOfDirectory(atPath: support.appendingPathComponent("Quarantine").path)
    }

    func cleanup() {
        try? FileManager.default.removeItem(at: root)
    }
}
