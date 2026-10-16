// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation

/// Pure, allocation-bounded command classifier shared by the Endpoint Security
/// exec path and the app tests. It records evidence only; blocking and incident
/// policy remain outside this type.
enum LOLBinExecutionPolicy {
    struct Finding: Equatable, Sendable {
        let title: String
        let reason: String
        let severity: String
        let matchedCommand: String?
    }

    static func finding(executablePath: String, arguments: [String]) -> Finding? {
        let name = URL(fileURLWithPath: executablePath).lastPathComponent.lowercased()
        let lowered = arguments.joined(separator: " ").lowercased()

        if ["sh", "bash", "zsh", "ksh", "csh", "fish", "dash"].contains(name),
           let command = shellCommand(in: arguments),
           let matched = downloadToShellEvidence(in: command) {
            return Finding(
                title: "Download-to-shell command detected",
                reason: matched.lowercased().range(of: #"\bwget\b"#, options: .regularExpression) != nil
                    ? "wget_pipe_shell"
                    : "curl_pipe_shell",
                severity: "critical",
                matchedCommand: redact(matched)
            )
        }
        if name == "osascript", lowered.contains("shell script") {
            return Finding(title: "osascript executing shell command", reason: "osascript_shell", severity: "high", matchedCommand: nil)
        }
        if name == "xattr", lowered.contains("com.apple.quarantine"),
           arguments.contains("-d") || arguments.contains("-c") {
            return Finding(title: "Quarantine attribute removal", reason: "quarantine_removal", severity: "high", matchedCommand: nil)
        }
        if ["python", "python3", "ruby", "perl"].contains(name),
           ["base64", "b64decode", "decode64"].contains(where: lowered.contains),
           ["exec(", "eval(", "system(", "popen(", "`"].contains(where: lowered.contains) {
            return Finding(title: "Encoded payload execution", reason: "base64_payload", severity: "high", matchedCommand: nil)
        }
        if name == "launchctl",
           ["load", "bootstrap", "submit"].contains(where: arguments.map { $0.lowercased() }.contains),
           lowered.range(of: #"/(private/)?(tmp|var/folders)/"#, options: .regularExpression) != nil {
            return Finding(title: "launchctl loading from a temporary directory", reason: "launchctl_tmp", severity: "critical", matchedCommand: nil)
        }
        if name == "crontab", arguments.contains("-e") || arguments.contains("-r") || arguments == ["-"] {
            return Finding(title: "crontab modification", reason: "crontab_modify", severity: "medium", matchedCommand: nil)
        }
        if ["sh", "bash", "zsh"].contains(name), lowered.contains("mktemp"),
           lowered.contains("&&") || lowered.contains(";") || lowered.contains("$(") {
            return Finding(title: "Shell creating and executing a temporary file", reason: "mktemp_execute", severity: "medium", matchedCommand: nil)
        }
        return nil
    }

    /// Extracts the command supplied to a shell's command flag. A shell with no
    /// captured command is not evidence of download-to-shell execution.
    private static func shellCommand(in arguments: [String]) -> String? {
        guard let flagIndex = arguments.firstIndex(where: { argument in
            argument == "--command"
                || (argument.hasPrefix("-") && argument.dropFirst().contains("c"))
        }) else { return nil }
        let commandIndex = arguments.index(after: flagIndex)
        guard arguments.indices.contains(commandIndex) else { return nil }
        let command = arguments[commandIndex...].joined(separator: " ")
        return command.isEmpty ? nil : command
    }

    /// Returns only concrete execution forms: a downloader piped into a shell,
    /// or a downloader command substitution used as the shell's `-c` program.
    private static func downloadToShellEvidence(in command: String) -> String? {
        let pipePattern = #"(?i)(?:^|\s)(?:/\S*/)?(?:curl|wget)\b[^|\n]*\|\s*(?:sudo(?:\s+-\S+)*\s+)?(?:/\S*/)?(?:sh|bash|zsh|ksh|csh|fish|dash)\b"#
        if let range = command.range(of: pipePattern, options: .regularExpression) {
            return String(command[range]).trimmingCharacters(in: .whitespacesAndNewlines)
        }

        let trimmed = command.trimmingCharacters(in: .whitespacesAndNewlines)
        let substitutionPattern = #"(?i)^(?:\$\(\s*|`\s*)(?:/\S*/)?(?:curl|wget)\b[^\n]*(?:\)|`)$"#
        if trimmed.range(of: substitutionPattern, options: .regularExpression) != nil {
            return trimmed
        }
        return nil
    }

    /// Keeps useful command evidence while removing common credential forms.
    static func redact(_ command: String) -> String {
        var result = command.replacingOccurrences(
            of: #"(?i)(https?://)[^/@\s]+@"#,
            with: "$1<redacted>@",
            options: .regularExpression
        )
        result = result.replacingOccurrences(
            of: #"(?i)(authorization:\s*(?:bearer|basic)\s+)[^\s'\"]+"#,
            with: "$1<redacted>",
            options: .regularExpression
        )
        result = result.replacingOccurrences(
            of: #"(?i)((?:token|api[_-]?key|password)=)[^&\s'\"]+"#,
            with: "$1<redacted>",
            options: .regularExpression
        )
        return String(result.prefix(2_048))
    }

    /// Defense-in-depth boundary shared by Core presentation and the extension.
    static func isProtectedSystemPath(_ path: String) -> Bool {
        let standardized = URL(fileURLWithPath: path).standardizedFileURL.path
        if standardized == "/bin" || standardized.hasPrefix("/bin/") { return true }
        if standardized == "/sbin" || standardized.hasPrefix("/sbin/") { return true }
        if standardized == "/System" || standardized.hasPrefix("/System/") { return true }
        if standardized == "/usr" || standardized.hasPrefix("/usr/") {
            return !(standardized == "/usr/local" || standardized.hasPrefix("/usr/local/"))
        }
        return false
    }
}
