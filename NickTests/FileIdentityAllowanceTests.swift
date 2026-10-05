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

    private func temporaryFile(contents: Data) throws -> URL {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("NickAllowanceTests-(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let file = directory.appendingPathComponent("sample")
        try contents.write(to: file)
        return file
    }
}
