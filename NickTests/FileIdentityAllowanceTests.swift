// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import XCTest
@testable import Nick

final class FileIdentityAllowanceTests: XCTestCase {

    func test_allowanceMatchesUnchangedFile() throws {
        let file = try temporaryFile(contents: Data("reviewed".utf8))
        defer { try? FileManager.default.removeItem(at: file.deletingLastPathComponent()) }

        let reviewed = try XCTUnwrap(FileIdentity(path: file.path))
        let allowance = OneTimeFileAllowance(identity: reviewed)

        XCTAssertTrue(allowance.permits(try XCTUnwrap(FileIdentity(path: file.path))))
    }

    func test_allowanceRejectsFileModifiedAtSamePath() throws {
        let file = try temporaryFile(contents: Data("reviewed".utf8))
        defer { try? FileManager.default.removeItem(at: file.deletingLastPathComponent()) }

        let allowance = OneTimeFileAllowance(
            identity: try XCTUnwrap(FileIdentity(path: file.path))
        )
        try Data("replacement content".utf8).write(to: file)

        XCTAssertFalse(allowance.permits(try XCTUnwrap(FileIdentity(path: file.path))))
    }

    func test_reviewRequiresTheIdentityCapturedByTheScan() throws {
        let file = try temporaryFile(contents: Data("reviewed".utf8))
        defer { try? FileManager.default.removeItem(at: file.deletingLastPathComponent()) }

        let reviewed = try XCTUnwrap(FileIdentity(path: file.path))
        try Data("swapped after scan".utf8).write(to: file)
        let current = try XCTUnwrap(FileIdentity(path: file.path))

        XCTAssertFalse(ReviewedFileAllowancePolicy.permits(reviewed: reviewed, current: current))
        XCTAssertFalse(ReviewedFileAllowancePolicy.permits(reviewed: nil, current: current))
    }

    func test_identityFollowsFinalSymlinkLikeEndpointSecurity() throws {
        let target = try temporaryFile(contents: Data("reviewed".utf8))
        let directory = target.deletingLastPathComponent()
        defer { try? FileManager.default.removeItem(at: directory) }
        let link = directory.appendingPathComponent("link")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: target)

        XCTAssertEqual(FileIdentity(path: link.path), FileIdentity(path: target.path))
    }

    func test_endpointSecurityCanonicalPathKeepsPrivateTmpPrefix() throws {
        let directory = URL(fileURLWithPath: "/private/tmp", isDirectory: true)
            .appendingPathComponent("NickAllowanceTests-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: directory) }
        let file = directory.appendingPathComponent("sample")
        try Data("reviewed".utf8).write(to: file)

        let canonical = try XCTUnwrap(EndpointSecurityPath.canonical(file.path))
        XCTAssertTrue(canonical.hasPrefix("/private/tmp/"), canonical)
        XCTAssertEqual(FileIdentity(path: canonical), FileIdentity(path: file.path))
    }

    func test_endpointSecurityCanonicalPathResolvesSymlinkedDotfileTarget() throws {
        let target = try temporaryFile(contents: Data("export SAFE=1".utf8))
        let directory = target.deletingLastPathComponent()
        defer { try? FileManager.default.removeItem(at: directory) }
        let dotfile = directory.appendingPathComponent(".zshrc")
        try FileManager.default.createSymbolicLink(at: dotfile, withDestinationURL: target)

        XCTAssertEqual(
            EndpointSecurityPath.canonical(dotfile.path),
            EndpointSecurityPath.canonical(target.path)
        )
    }

    private func temporaryFile(contents: Data) throws -> URL {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("NickAllowanceTests-(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let file = directory.appendingPathComponent("sample")
        try contents.write(to: file)
        return file
    }
}
