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
            return Finding(title: "Temporary-directory launch agent load", reason: "launchctl_tmp", severity: "critical", matchedCommand: nil)
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

// MARK: - Credential access

/// Pure metadata-only classifier for credential-store access. The Endpoint
/// Security extension supplies identities that have already been validated by
/// SecCode; this type never opens a credential file or records its contents.
enum CredentialAccessPolicy {
    struct ValidatedIdentity: Equatable, Sendable {
        let bundleID: String?
        let teamID: String?
        let signingValidated: Bool
        let isApplePlatform: Bool
    }

    enum Store: String, Equatable, Sendable {
        case browserCookies = "Browser cookies"
        case browserLogins = "Browser saved logins"
        case keychain = "macOS Keychain"
        case sshPrivateKey = "SSH private key"
        case cryptocurrencyWallet = "Cryptocurrency wallet"
        case browserWallet = "Browser wallet data"
        case cloudCredential = "Cloud service credentials"
        case messagingSession = "Messaging session"
        case notesData = "Notes data"
        case walletPass = "Wallet pass data"
        case passwordPrompt = "Hidden password prompt"
    }

    struct Finding: Equatable, Sendable {
        let title: String
        let reason: String
        let store: Store
    }

    /// Exact validated identities which legitimately handle credential stores.
    /// An identifier without the matching SecCode-derived signer never exempts
    /// access. Names, paths and bundle layout are deliberately not inputs.
    private static let trustedApplications: Set<String> = [
        "APPLE_PLATFORM|com.apple.Safari",
        "APPLE_PLATFORM|com.apple.SafariTechnologyPreview",
        "APPLE_PLATFORM|com.apple.backupd",
        "APPLE_PLATFORM|com.apple.Notes",
        "APPLE_PLATFORM|com.apple.Passbook",
        "EQHXZ8M8AV|com.google.Chrome",
        "43AQ936H96|org.mozilla.firefox",
        "2BUA8C4S2C|com.1password.1password"
    ]

    static func findingForOpen(path: String, responsibleIdentity: ValidatedIdentity?) -> Finding? {
        guard let store = sensitiveStore(at: path) else { return nil }
        return findingForOpen(store: store, responsibleIdentity: responsibleIdentity)
    }

    static func findingForOpen(store: Store, responsibleIdentity: ValidatedIdentity?) -> Finding? {
        if store == .keychain,
           responsibleIdentity?.signingValidated == true,
           responsibleIdentity?.isApplePlatform == true {
            return nil
        }
        guard !isTrustedCredentialApplication(responsibleIdentity) else {
            return nil
        }
        return Finding(
            title: "Credential store access needs review",
            reason: "credential_store_access",
            store: store
        )
    }

    static func findingForExec(
        executablePath: String,
        arguments: [String],
        responsibleIdentity: ValidatedIdentity?
    ) -> Finding? {
        let executable = URL(fileURLWithPath: executablePath).lastPathComponent.lowercased()
        let loweredCommand = arguments.joined(separator: " ").lowercased()
        let normalizedCommand = loweredCommand
            .split(whereSeparator: { $0.isWhitespace })
            .joined(separator: " ")
        if executable == "osascript",
           (normalizedCommand.range(of: #"display\s*dialog"#, options: .regularExpression) != nil
                && normalizedCommand.range(of: #"hidden\s*answer"#, options: .regularExpression) != nil
            || normalizedCommand.range(
                of: #"display\s*dialog.*hidden\s*answer\s*:\s*true"#,
                options: .regularExpression
            ) != nil) {
            return Finding(
                title: "Hidden password prompt needs review",
                reason: "hidden_password_prompt",
                store: .passwordPrompt
            )
        }

        guard executable == "security",
              !isTrustedCredentialApplication(responsibleIdentity) else { return nil }
        let lowered = arguments.map { $0.lowercased() }
        if lowered.contains("dump-keychain") {
            return Finding(title: "Keychain dump command needs review", reason: "keychain_dump", store: .keychain)
        }
        if lowered.contains("find-generic-password"), lowered.contains("-w") {
            return Finding(title: "Keychain secret read needs review", reason: "keychain_secret_read", store: .keychain)
        }
        return nil
    }

    private static func isTrustedCredentialApplication(_ identity: ValidatedIdentity?) -> Bool {
        guard let identity, identity.signingValidated, let bundleID = identity.bundleID else { return false }
        let signer = identity.isApplePlatform ? "APPLE_PLATFORM" : (identity.teamID ?? "")
        return trustedApplications.contains("\(signer)|\(bundleID)")
    }

    static func sensitiveStore(at rawPath: String) -> Store? {
        let path = URL(fileURLWithPath: rawPath).standardizedFileURL.path
        let lower = path.lowercased()
        if lower.hasSuffix("/cookies.binarycookies") || lower.hasSuffix("/cookies")
            || lower.contains("/cookies.sqlite") {
            return .browserCookies
        }
        if lower.hasSuffix("/login data") || lower.hasSuffix("/logins.json")
            || lower.hasSuffix("/key4.db") || lower.hasSuffix("/form values")
            || lower.hasSuffix("/autofillcorrections.db") {
            return .browserLogins
        }
        if lower.hasSuffix("/login.keychain-db") || lower.contains("/library/keychains/") {
            return .keychain
        }
        if lower.contains("/.ssh/"), !lower.hasSuffix(".pub"),
           !lower.hasSuffix("/known_hosts"), !lower.hasSuffix("/config"),
           URL(fileURLWithPath: lower).lastPathComponent.hasPrefix("id_") {
            return .sshPrivateKey
        }
        let walletMarkers = [
            "/library/application support/bitcoin/wallets/",
            "/library/application support/electrum/wallets/",
            "/library/application support/exodus/exodus.wallet/",
            "/library/application support/ethereum/keystore/"
        ]
        if walletMarkers.contains(where: lower.contains) { return .cryptocurrencyWallet }
        let browserWalletMarkers = [
            "/local extension settings/nkbihfbeogaeaoehlefnkodbefgpgknn/", // MetaMask
            "/local extension settings/bfhbdbfipfhmdofhnjickppdijkgdjlp/", // Phantom
            "/local extension settings/hnfanknocfeofbddgcijnmhnfnkdnaad/"  // Coinbase Wallet
        ]
        if browserWalletMarkers.contains(where: lower.contains) { return .browserWallet }

        let cloudCredentialPaths = [
            "/.aws/credentials",
            "/.config/gcloud/credentials.db",
            "/.config/gcloud/application_default_credentials.json",
            "/.kube/config",
            "/.docker/config.json"
        ]
        if cloudCredentialPaths.contains(where: lower.hasSuffix) { return .cloudCredential }
        if lower.contains("/telegram desktop/tdata/") { return .messagingSession }
        if lower.contains("/group.com.apple.notes/")
            && (lower.hasSuffix("/notestore.sqlite") || lower.contains("/notestore.sqlite-")) {
            return .notesData
        }
        if lower.contains("/library/passes/") || lower.hasSuffix(".pkpass") { return .walletPass }
        return nil
    }
}
