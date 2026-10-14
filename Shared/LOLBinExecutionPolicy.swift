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
    }

    static func finding(executablePath: String, arguments: [String]) -> Finding? {
        let name = URL(fileURLWithPath: executablePath).lastPathComponent.lowercased()
        let lowered = arguments.joined(separator: " ").lowercased()

        if ["sh", "bash", "zsh", "ksh", "csh", "fish", "dash"].contains(name),
           (lowered.contains("curl") || lowered.contains("wget")),
           lowered.contains("|") {
            return Finding(
                title: "Download-to-shell command detected",
                reason: lowered.contains("wget") ? "wget_pipe_shell" : "curl_pipe_shell",
                severity: "critical"
            )
        }
        if name == "osascript", lowered.contains("shell script") {
            return Finding(title: "osascript executing shell command", reason: "osascript_shell", severity: "high")
        }
        if name == "xattr", lowered.contains("com.apple.quarantine"),
           arguments.contains("-d") || arguments.contains("-c") {
            return Finding(title: "Quarantine attribute removal", reason: "quarantine_removal", severity: "high")
        }
        if ["python", "python3", "ruby", "perl"].contains(name),
           ["base64", "b64decode", "decode64"].contains(where: lowered.contains),
           ["exec(", "eval(", "system(", "popen(", "`"].contains(where: lowered.contains) {
            return Finding(title: "Encoded payload execution", reason: "base64_payload", severity: "high")
        }
        if name == "launchctl",
           ["load", "bootstrap", "submit"].contains(where: arguments.map { $0.lowercased() }.contains),
           lowered.range(of: #"/(private/)?(tmp|var/folders)/"#, options: .regularExpression) != nil {
            return Finding(title: "launchctl loading from a temporary directory", reason: "launchctl_tmp", severity: "critical")
        }
        if name == "crontab", arguments.contains("-e") || arguments.contains("-r") || arguments == ["-"] {
            return Finding(title: "crontab modification", reason: "crontab_modify", severity: "medium")
        }
        if ["sh", "bash", "zsh"].contains(name), lowered.contains("mktemp"),
           lowered.contains("&&") || lowered.contains(";") || lowered.contains("$(") {
            return Finding(title: "Shell creating and executing a temporary file", reason: "mktemp_execute", severity: "medium")
        }
        return nil
    }
}
