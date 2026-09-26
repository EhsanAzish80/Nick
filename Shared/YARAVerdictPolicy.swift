// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation

/// The single source of truth for how a YARA match is weighed.
///
/// Compiled into both the app and the Endpoint Security extension so Deep Scan,
/// the FSEvents watcher, and real-time scanning can never disagree about what a
/// rule means. Rule semantics come from rule metadata, not from Swift lists:
///
/// ```
/// meta:
///     class    = "signature"   // family/sample-specific evidence
///     class    = "behavior"    // generic capability heuristic (context-dependent)
///     severity = "HIGH"        // INFO | LOW | MEDIUM | HIGH | CRITICAL
/// ```
///
/// A rule without `class` falls back to the legacy behavioural list shipped
/// through 4.5, then to `signature` so hand-written family rules keep working.
enum YARAVerdictPolicy {

    enum RuleClass: String, Sendable {
        case signature
        case behavior
    }

    /// Ordered so comparisons (`>=`) express "at least this severe".
    enum Severity: Int, Comparable, Sendable {
        case info, low, medium, high, critical

        static func < (lhs: Severity, rhs: Severity) -> Bool { lhs.rawValue < rhs.rawValue }
    }

    /// Nick 4.5 and earlier encoded rule semantics in Swift. Kept only as a
    /// fallback for user-supplied copies of the old community files.
    static let legacyBehavioralRules: Set<String> = [
        "macos_backup_deletion", "macos_browser_credential_theft",
        "macos_browser_extension_inject", "macos_dns_hijack",
        "macos_dylib_injection", "macos_icloud_token_theft",
        "macos_keychain_access", "macos_launch_constraints_bypass",
        "macos_launchagent_install", "macos_mass_file_rename",
        "macos_network_proxy_intercept", "macos_ptrace_antidebug",
        "macos_ransom_note", "macos_reverse_shell", "macos_screenshot_capture",
        "macos_shadow_copy_delete", "nick_email_applescript_dropper",
        "nick_email_html_smuggling", "nick_email_office_macro_dropper",
        "nick_email_powershell_encoded_dropper", "nick_email_shell_dropper",
    ]

    static func ruleClass(ruleName: String, metadata: [String: String]) -> RuleClass {
        if let declared = metadata["class"]?
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased(),
           let value = RuleClass(rawValue: declared) {
            return value
        }
        return legacyBehavioralRules.contains(ruleName) ? .behavior : .signature
    }

    /// Missing or unknown severity is Medium everywhere. A `critical` tag is
    /// honoured for third-party rules that express severity as a tag.
    static func severity(metadata: [String: String], tags: [String]) -> Severity {
        switch metadata["severity"]?.trimmingCharacters(in: .whitespacesAndNewlines).uppercased() {
        case "INFO": return .info
        case "LOW": return .low
        case "MEDIUM": return .medium
        case "HIGH": return .high
        case "CRITICAL": return .critical
        default:
            return tags.contains(where: { $0.caseInsensitiveCompare("critical") == .orderedSame })
                ? .critical : .medium
        }
    }

    /// Whether a match is strong enough to be reported as a threat by a
    /// context-free path (real-time extension scanning). Behaviour rules need
    /// file context (signing, location, development evidence) that only the
    /// Deep Scan classifier has, so in real time they surface as threats only
    /// when their author declared them critical.
    static func isContextFreeThreat(ruleName: String, metadata: [String: String], tags: [String]) -> Bool {
        let severity = severity(metadata: metadata, tags: tags)
        switch ruleClass(ruleName: ruleName, metadata: metadata) {
        case .signature: return severity >= .high
        case .behavior: return severity >= .critical
        }
    }

    /// User ignores apply only to non-critical behaviour matches.
    static func canIgnore(ruleName: String, metadata: [String: String], tags: [String]) -> Bool {
        ruleClass(ruleName: ruleName, metadata: metadata) == .behavior
            && severity(metadata: metadata, tags: tags) < .critical
    }
}
