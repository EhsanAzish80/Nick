// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation

// MARK: - ScamGuardian

/// Detects phishing and brand-impersonation domains using four strategies:
///
/// 1. **Exact blocklist** — known phishing domains.
/// 2. **Brand typosquat** — brands spelled with common substitutions
///    (e.g. `app1e.com`, `paypa1.com`, `g00gle.com`).
/// 3. **Structural heuristics** — suspicious TLD + number-of-hyphens combos
///    that are statistically associated with phishing kits.
/// 4. **Credential-lure combinations** — a protected brand combined with
///    several account/login terms on a non-brand registrable domain.
///
/// All checks are performed on the registered domain (eTLD+1), not the full
/// FQDN, so `login.paypa1.com` still trips the typosquat rule for `paypal`.
final class ScamGuardian: @unchecked Sendable {
    private let publicSuffixList = PublicSuffixList.shared

    // MARK: - Private

    /// Known exact phishing domains (lower-cased eTLD+1).
    private let exactBlocklist: Set<String> = [
        // Reserved, non-routable release-validation destination. Packaging QA
        // can safely verify a real filter verdict without contacting a live
        // phishing site.
        "nick-scam-test.invalid",
        // Apple impersonation
        "apple-id-login.com",
        "appleid-support.net",
        "appleid-verification.com",
        // Microsoft / Outlook
        "microsoft-support-login.com",
        "outlook-reset-password.net",
        // Banking generic
        "secure-bank-login.com",
        "bankofamerica-verify.net",
        // Crypto / Web3
        "metamask-wallet-connect.io",
        "coinbase-support-verify.com",
    ]

    /// Brands whose names are commonly typosquatted.
    private let typosquatBrands: [String] = [
        "apple", "google", "microsoft", "amazon", "paypal",
        "facebook", "instagram", "twitter", "netflix", "icloud",
        "dropbox", "github", "coinbase", "binance",
    ]

    private let credentialLureTerms: Set<String> = [
        "account", "auth", "billing", "confirm", "login", "password",
        "recover", "reset", "secure", "signin", "support", "unlock",
        "update", "verification", "verify", "wallet",
    ]

    /// Common character-substitution patterns used in typosquats.
    private let charSubstitutions: [Character: [String]] = [
        "a": ["@", "4"],
        "e": ["3"],
        "i": ["1", "l", "!"],
        "o": ["0"],
        "s": ["5", "$"],
        "l": ["1", "I"],
        "g": ["9"],
    ]

    // MARK: - Public API

    /// Returns `true` if `host` appears to be a phishing or scam domain.
    func isSuspicious(host: String) -> Bool {
        guard let lower = NetworkProtectionConfiguration.normalizedDomain(host),
              !Self.isIPAddress(lower)
        else { return false }
        let registered = publicSuffixList.registrableDomain(for: lower)

        // 1. Exact blocklist
        if exactBlocklist.contains(registered) { return true }

        // 2. Brand typosquat
        if matchesTyposquat(domain: registered) { return true }

        // 3. Structural heuristics (e.g. "secure-login-apple-update.xyz")
        if structuralHeuristic(domain: lower) { return true }

        // 4. Explicit brand + credential-lure combinations.
        if credentialLureHeuristic(domain: registered) { return true }

        return false
    }

    // MARK: - Private: Typosquat Detection

    private func matchesTyposquat(domain: String) -> Bool {
        // `domain` is already the registrable domain (eTLD+1), so its first
        // label is the registrant name even for multi-label public suffixes
        // such as `co.uk`.
        guard let label = domain.split(separator: ".").first.map(String.init)
        else { return false }

        for brand in typosquatBrands {
            // Skip identical match — that's the legitimate domain
            if label == brand { continue }
            if isTyposquatOf(label: label, brand: brand) { return true }
        }
        return false
    }

    /// Returns `true` if `label` is a plausible typosquat of `brand`.
    ///
    /// Uses known visual substitutions plus a single adjacent transposition.
    /// General edit distance is deliberately avoided to reduce false positives.
    private func isTyposquatOf(label: String, brand: String) -> Bool {
        // Known substitutions are positional. This avoids ambiguous global
        // replacement (for example "1" may resemble either "i" or "l").
        guard label.count == brand.count else { return false }
        let positionalLookalike = zip(label, brand).allSatisfy { candidate, expected in
            candidate == expected
                || charSubstitutions[expected]?.contains(String(candidate)) == true
        }
        if positionalLookalike { return true }

        let candidate = Array(label)
        let expected = Array(brand)
        let differences = candidate.indices.filter { candidate[$0] != expected[$0] }
        guard differences.count == 2,
              differences[1] == differences[0] + 1
        else { return false }
        return candidate[differences[0]] == expected[differences[1]]
            && candidate[differences[1]] == expected[differences[0]]
    }

    // MARK: - Private: Structural Heuristics

    private func structuralHeuristic(domain: String) -> Bool {
        // Flag domains that contain 3+ hyphens AND a suspicious TLD.
        let suspiciousTLDs = Set(["xyz", "tk", "ml", "ga", "cf", "gq", "top",
                                  "click", "download", "review", "accountant"])

        let components = domain.components(separatedBy: ".")
        guard let tld = components.last else { return false }
        guard suspiciousTLDs.contains(tld) else { return false }

        let hyphenCount = domain.filter { $0 == "-" }.count
        return hyphenCount >= 3
    }

    private func credentialLureHeuristic(domain: String) -> Bool {
        guard let label = domain.split(separator: ".").first.map(String.init)
        else { return false }

        let tokens = Set(label.split(separator: "-").map(String.init))
        let brandMatches = typosquatBrands.filter { tokens.contains($0) }
        guard !brandMatches.isEmpty else { return false }

        // Legitimate registrable domains are handled before this point because
        // their complete label equals the brand, not a lure-token combination.
        let lureCount = tokens.intersection(credentialLureTerms).count
        return lureCount >= 2
    }

    private static func isIPAddress(_ host: String) -> Bool {
        if host.contains(":") { return true }
        let labels = host.split(separator: ".")
        return labels.count == 4 && labels.allSatisfy { Int($0).map { (0...255).contains($0) } ?? false }
    }
}

private final class PublicSuffixList: @unchecked Sendable {
    static let shared = PublicSuffixList()

    private let exact: Set<String>
    private let wildcard: Set<String>
    private let exceptions: Set<String>

    private init() {
        var exact = Set(["com", "net", "org", "io", "co.uk", "org.uk", "com.au", "co.jp"])
        var wildcard = Set<String>()
        var exceptions = Set<String>()

        if let url = Bundle.main.url(forResource: "public_suffix_list", withExtension: "dat"),
           let text = try? String(contentsOf: url, encoding: .utf8) {
            for rawLine in text.split(whereSeparator: \.isNewline) {
                let line = rawLine.trimmingCharacters(in: .whitespaces)
                guard !line.isEmpty, !line.hasPrefix("//") else { continue }
                if line.hasPrefix("!") {
                    exceptions.insert(String(line.dropFirst()).lowercased())
                } else if line.hasPrefix("*.") {
                    wildcard.insert(String(line.dropFirst(2)).lowercased())
                } else {
                    exact.insert(line.lowercased())
                }
            }
        }
        self.exact = exact
        self.wildcard = wildcard
        self.exceptions = exceptions
    }

    func registrableDomain(for host: String) -> String {
        let labels = host.split(separator: ".").map(String.init)
        guard labels.count > 1 else { return host }

        var matchedLabelCount = 1
        for index in labels.indices {
            let candidate = labels[index...].joined(separator: ".")
            if exceptions.contains(candidate) {
                let suffixCount = max(1, labels.count - index - 1)
                return labels.suffix(min(labels.count, suffixCount + 1)).joined(separator: ".")
            }
            if exact.contains(candidate) {
                matchedLabelCount = max(matchedLabelCount, labels.count - index)
            }
            if index + 1 < labels.count {
                let wildcardSuffix = labels[(index + 1)...].joined(separator: ".")
                if wildcard.contains(wildcardSuffix) {
                    matchedLabelCount = max(matchedLabelCount, labels.count - index)
                }
            }
        }
        return labels.suffix(min(labels.count, matchedLabelCount + 1)).joined(separator: ".")
    }
}
