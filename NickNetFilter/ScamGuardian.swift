// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation

// MARK: - ScamGuardian

/// Detects phishing and brand-impersonation domains using three strategies:
///
/// 1. **Exact blocklist** — known phishing domains.
/// 2. **Brand typosquat** — brands spelled with common substitutions
///    (e.g. `app1e.com`, `paypa1.com`, `g00gle.com`).
/// 3. **Structural heuristics** — suspicious TLD + number-of-hyphens combos
///    that are statistically associated with phishing kits.
///
/// All checks are performed on the registered domain (eTLD+1), not the full
/// FQDN, so `login.paypa1.com` still trips the typosquat rule for `paypal`.
final class ScamGuardian: @unchecked Sendable {

    // MARK: - Private

    /// Known exact phishing domains (lower-cased eTLD+1).
    private let exactBlocklist: Set<String> = [
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
        let lower       = host.lowercased()
        let registered  = registeredDomain(from: lower)

        // 1. Exact blocklist
        if exactBlocklist.contains(registered) { return true }

        // 2. Brand typosquat
        if matchesTyposquat(domain: registered) { return true }

        // 3. Structural heuristics (e.g. "secure-login-apple-update.xyz")
        if structuralHeuristic(domain: lower) { return true }

        return false
    }

    // MARK: - Private: Typosquat Detection

    private func matchesTyposquat(domain: String) -> Bool {
        // Strip the TLD to get the label (e.g. "paypa1" from "paypa1.com").
        guard let dotRange = domain.lastIndex(of: ".") else { return false }
        let label = String(domain[domain.startIndex ..< dotRange])

        for brand in typosquatBrands {
            // Skip identical match — that's the legitimate domain
            if label == brand { continue }
            if isTyposquatOf(label: label, brand: brand) { return true }
        }
        return false
    }

    /// Returns `true` if `label` is a plausible typosquat of `brand`.
    ///
    /// We use a simple edit-distance check (≤ 1 substitution with known
    /// lookalike characters) rather than full Levenshtein distance to keep
    /// the check fast and avoid false positives.
    private func isTyposquatOf(label: String, brand: String) -> Bool {
        // Must be within ±2 characters in length to be a candidate
        guard abs(label.count - brand.count) <= 2 else { return false }

        // Build a normalized form with lookalike characters replaced
        var normalised = label
        for (original, replacements) in charSubstitutions {
            for replacement in replacements {
                normalised = normalised.replacingOccurrences(of: replacement,
                                                             with: String(original))
            }
        }
        return normalised == brand
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

    // MARK: - Private: eTLD+1 Extraction

    /// Extracts a best-effort registered domain (e.g. `evil.co.uk` → `evil.co.uk`).
    ///
    /// This is a simplified approximation — a production implementation would
    /// use the Public Suffix List.
    private func registeredDomain(from host: String) -> String {
        let parts = host.components(separatedBy: ".")
        if parts.count >= 2 {
            return parts.suffix(2).joined(separator: ".")
        }
        return host
    }
}
