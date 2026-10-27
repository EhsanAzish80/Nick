import Foundation
import XCTest
@testable import Nick

final class StorageOperationApprovalTests: XCTestCase {
    private final class TestClock: @unchecked Sendable {
        private let lock = NSLock()
        private var value: Date

        init(_ value: Date) { self.value = value }

        func now() -> Date { lock.withLock { value } }
        func set(_ value: Date) { lock.withLock { self.value = value } }
    }

    private let pid: Int32 = 410
    private let pidVersion: Int32 = 73

    func testInScopeMetadataReadIsApprovedOnlyForExactProcessInstance() throws {
        let registry = StorageOperationRegistry(now: { Date(timeIntervalSince1970: 100) })
        let request = request(kind: .sizeScan, scopes: ["/tmp/NickStorage/cache"])
        XCTAssertTrue(registry.register(
            request, authenticatedPID: pid, authenticatedPIDVersion: pidVersion
        ))
        XCTAssertTrue(registry.permits(
            pid: pid, pidVersion: pidVersion,
            event: .metadataRead(path: "/tmp/NickStorage/cache/item")
        ))
        XCTAssertFalse(registry.permits(
            pid: pid + 1, pidVersion: pidVersion,
            event: .metadataRead(path: "/tmp/NickStorage/cache/item")
        ))
        XCTAssertFalse(registry.permits(
            pid: pid, pidVersion: pidVersion,
            event: .metadataRead(path: "/tmp/NickStorage/outside")
        ))
    }

    func testExpiredOperationAndReusedIDAreRejected() {
        let clock = TestClock(Date(timeIntervalSince1970: 100))
        let registry = StorageOperationRegistry(now: { clock.now() })
        let request = request(kind: .sizeScan, scopes: ["/tmp/NickStorage/cache"])
        XCTAssertTrue(registry.register(
            request, authenticatedPID: pid, authenticatedPIDVersion: pidVersion
        ))
        clock.set(Date(timeIntervalSince1970: 701))
        XCTAssertFalse(registry.permits(
            pid: pid, pidVersion: pidVersion,
            event: .metadataRead(path: "/tmp/NickStorage/cache/item")
        ))
        XCTAssertFalse(registry.register(
            request, authenticatedPID: pid, authenticatedPIDVersion: pidVersion
        ))
    }

    func testTrashApprovalDoesNotCoverOutOfScopeOrNonTrashRename() {
        let registry = StorageOperationRegistry(now: { Date(timeIntervalSince1970: 100) })
        XCTAssertTrue(registry.register(
            request(kind: .trashCleanup, scopes: ["/tmp/NickStorage/cache"]),
            authenticatedPID: pid, authenticatedPIDVersion: pidVersion
        ))
        XCTAssertTrue(registry.permits(
            pid: pid, pidVersion: pidVersion,
            event: .trashRename(
                source: "/tmp/NickStorage/cache/item",
                destination: "/Users/test/.Trash/item"
            )
        ))
        XCTAssertFalse(registry.permits(
            pid: pid, pidVersion: pidVersion,
            event: .trashRename(
                source: "/tmp/NickStorage/other",
                destination: "/Users/test/.Trash/other"
            )
        ))
        XCTAssertFalse(registry.permits(
            pid: pid, pidVersion: pidVersion,
            event: .trashRename(
                source: "/tmp/NickStorage/cache/item",
                destination: "/tmp/stolen"
            )
        ))
    }

    func testCredentialAndProtectedScopesCanNeverBeRegistered() {
        for path in [
            "/Users/test/Library/Application Support/Google/Chrome/Default/Login Data",
            "/Users/test/Library/Keychains/login.keychain-db",
            "/Users/test/Library/LaunchAgents",
            "/Applications/Nick.app"
        ] {
            let registry = StorageOperationRegistry(now: { Date(timeIntervalSince1970: 100) })
            XCTAssertFalse(registry.register(
                request(kind: .sizeScan, scopes: [path]),
                authenticatedPID: pid, authenticatedPIDVersion: pidVersion
            ), path)
        }
    }

    func testSymlinkIntoCredentialStoreIsNeverApproved() throws {
        let root = FileManager.default.temporaryDirectory
            .appending(path: "nick-storage-\(UUID().uuidString)")
        let cache = root.appending(path: "cache")
        let credentials = root.appending(path: "Login Data")
        try FileManager.default.createDirectory(at: cache, withIntermediateDirectories: true)
        try Data("secret".utf8).write(to: credentials)
        let link = cache.appending(path: "linked")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: credentials)
        defer { try? FileManager.default.removeItem(at: root) }

        let registry = StorageOperationRegistry(now: { Date(timeIntervalSince1970: 100) })
        XCTAssertTrue(registry.register(
            request(kind: .sizeScan, scopes: [cache.path]),
            authenticatedPID: pid, authenticatedPIDVersion: pidVersion
        ))
        XCTAssertFalse(registry.permits(
            pid: pid, pidVersion: pidVersion,
            event: .metadataRead(path: link.path)
        ))
    }

    @MainActor
    func testBrowserStorageScopeContainsCacheSubfoldersOnly() {
        let paths = PerformanceMonitor.browserCacheScopePaths.map { $0.lowercased() }
        XCTAssertFalse(paths.isEmpty)
        XCTAssertTrue(paths.allSatisfy { path in
            path.contains("cache") && !path.hasSuffix("/profiles")
                && !path.contains("login data") && !path.contains("cookies")
                && !path.contains("logins.json") && !path.contains("key4.db")
        })
    }

    private func request(kind: StorageOperationKind, scopes: [String]) -> StorageOperationRequest {
        StorageOperationRequest(
            operationID: UUID(), kind: kind,
            actorPID: pid, actorPIDVersion: pidVersion,
            scopedPaths: scopes, expiresAt: Date(timeIntervalSince1970: 200)
        )
    }
}
