// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import XCTest
@testable import Nick

final class WebhookURLPolicyTests: XCTestCase {

    func test_acceptsRemoteHTTPS() {
        XCTAssertTrue(WebhookURLPolicy.permits(
            URL(string: "https://alerts.example.com/nick")!,
            allowInsecureLocalhost: false
        ))
    }

    func test_rejectsRemoteHTTPEvenWithLocalOptIn() {
        XCTAssertFalse(WebhookURLPolicy.permits(
            URL(string: "http://alerts.example.com/nick")!,
            allowInsecureLocalhost: true
        ))
    }

    func test_localHTTPRequiresExplicitOptIn() {
        let loopbackURLs = [
            URL(string: "http://localhost:8080/nick")!,
            URL(string: "http://127.0.0.1:8080/nick")!,
            URL(string: "http://[::1]:8080/nick")!,
        ]
        for url in loopbackURLs {
            XCTAssertFalse(WebhookURLPolicy.permits(url, allowInsecureLocalhost: false))
            XCTAssertTrue(WebhookURLPolicy.permits(url, allowInsecureLocalhost: true))
        }
    }

    func test_rejectsNonHTTPProtocols() {
        XCTAssertFalse(WebhookURLPolicy.permits(
            URL(string: "file:///tmp/nick")!,
            allowInsecureLocalhost: true
        ))
    }
}
