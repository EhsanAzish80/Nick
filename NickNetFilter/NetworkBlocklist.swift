// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation
import os

// MARK: - NetworkBlocklist

/// Thread-safe, in-memory blocklist of known malicious domains and IP addresses.
///
/// The list is compiled from a small hard-coded seed of well-known C2 and
/// malware distribution domains. In a production build, the list would be
/// updated from a cloud threat intelligence feed saved to the App Group
/// container (`group.com.ehsanazish.nick`).
///
/// **Subdomain matching:** `isBlocked(host:)` matches both exact entries and
/// any subdomain — e.g. blocking `evil.com` also blocks `cdn.evil.com`.
final class NetworkBlocklist: @unchecked Sendable {

    static let shared = NetworkBlocklist()

    // MARK: - Private

    private static let logger = Logger(
        subsystem: "com.ehsanazish.nick.NickNetFilter",
        category:  "NetworkBlocklist"
    )

    private var blockedDomains: Set<String> = []
    private var blockedIPs:     Set<String> = []
    private let lock = NSLock()

    // MARK: - Init

    init() {
        loadHardcodedList()
        loadUserList()
    }

    // MARK: - Public API

    /// Returns `true` if `host` is (or is a subdomain of) a blocked entry.
    func isBlocked(host: String) -> Bool {
        let lower = host.lowercased()

        return lock.withLock {
            if blockedIPs.contains(lower) { return true }
            // Domain check: walk up the label hierarchy
            var labels = lower.components(separatedBy: ".")
            while labels.count >= 2 {
                let candidate = labels.joined(separator: ".")
                if blockedDomains.contains(candidate) { return true }
                labels.removeFirst()
            }
            return false
        }
    }

    // MARK: - Private: Seed List

    private func loadHardcodedList() {
        // Seed list — well-known malware C2 / phishing domains used in the
        // wild. This is not exhaustive; it serves as a baseline for testing.
        let domains: [String] = [
            // Generic malware C2 patterns used in research environments
            "malware-traffic-analysis.net",
            "feodotracker.abuse.ch",

            // EICAR / security-test domains (block for demonstration)
            "eicar.org",

            // DNS sinkholes operated by abuse.ch / security researchers
            "sinkhole.abuse.ch",
            "sinkhole.cert.pl",
        ]

        let ips: [String] = [
            // RFC 5737 test/documentation ranges — used in unit tests
            "192.0.2.1",
            "198.51.100.1",
        ]

        lock.withLock {
            blockedDomains.formUnion(domains)
            blockedIPs.formUnion(ips)
        }

        Self.logger.info("NetworkBlocklist: loaded \(domains.count) seed domain(s)")
    }

    /// Loads additional entries from the shared App Group container.
    /// The file is a JSON object: `{ "domains": [...], "ips": [...] }`
    private func loadUserList() {
        let groupID = "group.com.ehsanazish.nick"
        guard let containerURL = FileManager.default
                .containerURL(forSecurityApplicationGroupIdentifier: groupID) else { return }

        let listURL = containerURL.appendingPathComponent("blocklist.json")
        guard let data = try? Data(contentsOf: listURL) else { return }

        struct BlocklistFile: Decodable {
            var domains: [String]?
            var ips:     [String]?
        }

        guard let parsed = try? JSONDecoder().decode(BlocklistFile.self, from: data) else {
            Self.logger.error("NetworkBlocklist: failed to parse blocklist.json")
            return
        }

        lock.withLock {
            if let d = parsed.domains { blockedDomains.formUnion(d) }
            if let i = parsed.ips     { blockedIPs.formUnion(i) }
        }

        Self.logger.info("NetworkBlocklist: loaded user list from App Group")
    }
}
