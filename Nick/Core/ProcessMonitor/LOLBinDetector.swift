// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation

// MARK: - LOLBinDetector

/// Detects living-off-the-land binary (LOLBin) abuse patterns.
///
/// LOLBins are legitimate system tools that attackers abuse to execute
/// malicious commands without dropping a custom binary — helping them
/// blend in with normal system activity. This detector focuses on the
/// most commonly abused macOS binaries and argument patterns.
///
/// **Detection patterns:**
/// - Shell piped from `curl`/`wget` download (`curl ... | bash`, `curl ... | sh`)
/// - `osascript` executing shell commands via `do shell script`
/// - `xattr -d com.apple.quarantine` (quarantine attribute removal)
/// - `python`/`ruby`/`perl` executing base64-decoded payloads
/// - `launchctl load` of a user-writable path (persistence via LOLBin)
///
/// Signals are suppressed for processes whose parent is in `TrustedProcessList`.
enum LOLBinDetector {

    // MARK: - LOLBin Signatures

    private struct Signature {
        let processName: String
        let argumentPattern: String   // substring match against joined argv
        let title: String
        let severity: SignalSeverity
        let reason: String
    }

    private static let signatures: [Signature] = [
        // curl/wget piped to a shell — classic drive-by download
        Signature(
            processName: "bash",
            argumentPattern: "curl",
            title: "Shell executed from curl download",
            severity: .critical,
            reason: "curl_pipe_shell"
        ),
        Signature(
            processName: "sh",
            argumentPattern: "curl",
            title: "Shell executed from curl download",
            severity: .critical,
            reason: "curl_pipe_shell"
        ),
        Signature(
            processName: "bash",
            argumentPattern: "wget",
            title: "Shell executed from wget download",
            severity: .critical,
            reason: "wget_pipe_shell"
        ),
        Signature(
            processName: "sh",
            argumentPattern: "wget",
            title: "Shell executed from wget download",
            severity: .critical,
            reason: "wget_pipe_shell"
        ),
        // osascript executing shell commands
        Signature(
            processName: "osascript",
            argumentPattern: "do shell script",
            title: "osascript executing shell command",
            severity: .high,
            reason: "osascript_shell"
        ),
        Signature(
            processName: "osascript",
            argumentPattern: "shell script",
            title: "osascript executing shell command",
            severity: .high,
            reason: "osascript_shell"
        ),
        // Quarantine attribute removal — common in post-exploitation
        Signature(
            processName: "xattr",
            argumentPattern: "com.apple.quarantine",
            title: "Quarantine attribute removal",
            severity: .high,
            reason: "quarantine_removal"
        ),
        // Base64-decoded payload execution
        Signature(
            processName: "python3",
            argumentPattern: "base64",
            title: "Python executing base64-encoded payload",
            severity: .high,
            reason: "base64_payload"
        ),
        Signature(
            processName: "python",
            argumentPattern: "base64",
            title: "Python executing base64-encoded payload",
            severity: .high,
            reason: "base64_payload"
        ),
        Signature(
            processName: "ruby",
            argumentPattern: "base64",
            title: "Ruby executing base64-encoded payload",
            severity: .high,
            reason: "base64_payload"
        ),
        Signature(
            processName: "perl",
            argumentPattern: "base64",
            title: "Perl executing base64-encoded payload",
            severity: .high,
            reason: "base64_payload"
        ),
        // launchctl loading from writable locations
        Signature(
            processName: "launchctl",
            argumentPattern: "/tmp/",
            title: "launchctl loading agent from temp directory",
            severity: .critical,
            reason: "launchctl_tmp"
        ),
        Signature(
            processName: "launchctl",
            argumentPattern: "/var/folders/",
            title: "launchctl loading agent from temp directory",
            severity: .critical,
            reason: "launchctl_tmp"
        ),
        // crontab modification
        Signature(
            processName: "crontab",
            argumentPattern: "-",
            title: "crontab modification",
            severity: .medium,
            reason: "crontab_modify"
        ),
        // mktemp + execute pattern
        Signature(
            processName: "bash",
            argumentPattern: "mktemp",
            title: "Shell creating and executing temp file",
            severity: .medium,
            reason: "mktemp_execute"
        ),
    ]

    // MARK: - Public API

    /// Evaluates a process for LOLBin abuse patterns.
    ///
    /// Checks the process name and command-line arguments against known
    /// LOLBin signatures. Parent process context is used to reduce false
    /// positives. Trust is applied later by correlation and never prevents collection
    /// of strong evidence from a potentially compromised signed application.
    ///
    /// - Parameters:
    ///   - proc: The process to evaluate.
    ///   - parentName: Name of the parent process, if known.
    ///   - trustedProcessList: Allowlist used to suppress FPs.
    /// - Returns: A `ThreatSignal` if a LOLBin pattern is detected, otherwise `nil`.
    static func evaluate(
        _ proc: NickProcessInfo,
        parentName: String?,
        trustedProcessList: TrustedProcessList = TrustedProcessList()
    ) -> ThreatSignal? {
        // Include parentName in the search string so pipe-based patterns
        // (e.g., `curl … | bash`) are detected via the parent process name.
        let argv = proc.path + " " + proc.name + " " + (parentName ?? "")

        for sig in signatures {
            guard proc.name.lowercased() == sig.processName.lowercased() else { continue }
            guard argv.lowercased().contains(sig.argumentPattern.lowercased()) else { continue }

            return ThreatSignal(
                source: .process,
                severity: sig.severity,
                title: sig.title,
                description: "'\(proc.name)' (PID \(proc.pid)) matches LOLBin pattern '\(sig.argumentPattern)'. Parent: '\(parentName ?? "unknown")'.",
                context: ThreatSignalContext(
                    processInfo: proc,
                    metadata: [
                        "reason": sig.reason,
                        "detector": "LOLBinDetector",
                        "matched_pattern": sig.argumentPattern
                    ]
                )
            )
        }

        return nil
    }

    /// Evaluates a list of processes for LOLBin patterns.
    ///
    /// Builds a PID→name map for parent resolution, then calls `evaluate(_:parentName:trustedProcessList:)`
    /// for each process. Trust is handled after signal collection.
    ///
    /// - Parameters:
    ///   - processes: All currently running processes.
    ///   - trustedProcessList: Allowlist of process names to suppress.
    /// - Returns: All LOLBin signals found.
    static func signals(
        from processes: [NickProcessInfo],
        trustedProcessList: TrustedProcessList = TrustedProcessList()
    ) -> [ThreatSignal] {
        let pidToName = Dictionary(uniqueKeysWithValues: processes.map { ($0.pid, $0.name) })
        var results: [ThreatSignal] = []

        for proc in processes {
            // Fall back to the stored parentName field when the parent PID
            // is not present in the current snapshot (e.g. parent already exited).
            let storedParent = proc.parentName.flatMap { $0.isEmpty ? nil : $0 }
            let parentName = pidToName[proc.parentPID] ?? storedParent
            if let signal = evaluate(proc, parentName: parentName, trustedProcessList: trustedProcessList) {
                results.append(signal)
            }
        }

        return results
    }
}
