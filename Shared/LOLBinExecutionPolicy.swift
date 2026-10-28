// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation
import CryptoKit

/// Pure, allocation-bounded command classifier shared by the Endpoint Security
/// exec path and the app tests. It records evidence only; blocking and incident
/// policy remain outside this type.
enum LOLBinExecutionPolicy {
    enum Tier: String, Equatable, Sendable { case review, protected }
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
        if isStandaloneDecoder(name: name, arguments: arguments) {
            return Finding(
                title: "Decoded an encoded payload",
                reason: "encoded_payload",
                severity: "medium",
                matchedCommand: redact(arguments.joined(separator: " "))
            )
        }
        if name == "launchctl",
           ["load", "bootstrap", "submit"].contains(where: arguments.map { $0.lowercased() }.contains),
           lowered.range(of: #"/(private/)?(tmp|var/folders)/"#, options: .regularExpression) != nil {
            return Finding(title: "Temporary-directory launch agent load", reason: "launchctl_tmp", severity: "critical", matchedCommand: nil)
        }
        if name == "crontab" {
            let operands = Array(arguments.drop(while: { URL(fileURLWithPath: $0).lastPathComponent.lowercased() == "crontab" }))
            if operands.contains("-e") || operands.contains("-r") || operands == ["-"]
                || operands.contains(where: { !$0.hasPrefix("-") }) {
                return Finding(title: "Added a cron job", reason: "cron_modification", severity: "medium", matchedCommand: nil)
            }
        }
        if ["sh", "bash", "zsh"].contains(name), lowered.contains("mktemp"),
           lowered.contains("&&") || lowered.contains(";") || lowered.contains("$(") {
            return Finding(title: "Shell creating and executing a temporary file", reason: "mktemp_execute", severity: "medium", matchedCommand: nil)
        }
        return nil
    }

    private static func isStandaloneDecoder(name: String, arguments: [String]) -> Bool {
        let args = arguments.dropFirst().map { $0.lowercased() }
        switch name {
        case "base64": return args.contains("-d") || args.contains("--decode")
        case "openssl":
            return (args.contains("base64") || args.contains("enc"))
                && (args.contains("-d") || args.contains("-decode"))
        case "xxd": return args.contains("-r") || args.contains("-revert")
        default: return false
        }
    }

    /// A temporary-file execution is routine only when both the actor and its
    /// responsible app chain were validated, and there is no download or
    /// quarantine provenance. Names and paths never qualify the downgrade.
    static func mktempTier(
        actorIdentityValidated: Bool,
        responsibleChainValidated: Bool,
        hasNetworkOrigin: Bool,
        hasQuarantineOrigin: Bool
    ) -> Tier {
        actorIdentityValidated && responsibleChainValidated
            && !hasNetworkOrigin && !hasQuarantineOrigin ? .review : .protected
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
    struct DeliveryProfile: Equatable, Sendable {
        let tier: String
        let severity: String
        let deliveryLevel: String
    }

    struct RecentHiddenPrompt: Equatable, Sendable {
        let chainKey: String
        let armedAt: Date
        let processPID: Int32
        let processPIDVersion: Int32

        func matchesFollowUp(
            chainKey: String,
            processPID: Int32,
            processPIDVersion: Int32,
            at now: Date,
            window: TimeInterval = 600
        ) -> Bool {
            guard self.chainKey == chainKey,
                  now >= armedAt,
                  now.timeIntervalSince(armedAt) <= window else { return false }
            return self.processPID != processPID
                || self.processPIDVersion != processPIDVersion
        }
    }

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
        let tier: String
        let severity: String

        init(
            title: String,
            reason: String,
            store: Store,
            tier: String = "review",
            severity: String = "medium"
        ) {
            self.title = title
            self.reason = reason
            self.store = store
            self.tier = tier
            self.severity = severity
        }
    }

    /// Exact validated identities which legitimately handle credential stores.
    /// An identifier without the matching SecCode-derived signer never exempts
    /// access. Names, paths and bundle layout are deliberately not inputs.
    private static let trustedApplications: Set<String> = [
        "APPLE|com.apple.Safari",
        "APPLE|com.apple.SafariTechnologyPreview",
        "APPLE_PLATFORM|com.apple.backupd",
        "APPLE_PLATFORM|com.apple.Notes",
        "APPLE_PLATFORM|com.apple.Passbook",
        "EQHXZ8M8AV|com.google.Chrome",
        "43AQ936H96|org.mozilla.firefox",
        "2BUA8C4S2C|com.1password.1password"
    ]

    /// Apple launch services which legitimately own long-lived platform
    /// daemons. The caller must validate the code object first; an executable
    /// name or path alone never satisfies this policy.
    private static let appleLaunchServiceSigningIDs: Set<String> = [
        "com.apple.xpc.launchd",
        "com.apple.xpc.launchd_sim"
    ]

    static func isValidatedAppleLaunchService(
        signingID: String?,
        isValidatedAppleCode: Bool
    ) -> Bool {
        isValidatedAppleCode
            && signingID.map(appleLaunchServiceSigningIDs.contains) == true
    }

    static func shouldEvaluateOpen(
        isRead: Bool,
        isRegularFile: Bool,
        isBlocked: Bool,
        isApprovedStorageMetadataRead: Bool
    ) -> Bool {
        isRead && isRegularFile && !isBlocked && !isApprovedStorageMetadataRead
    }

    static func findingForOpen(
        path: String,
        responsibleIdentity: ValidatedIdentity?,
        actorIdentityValidated: Bool = false,
        actorIsValidatedApplePlatform: Bool = false,
        actorIsOwnResponsibleProcess: Bool = false,
        actorParentIsLaunchd: Bool = false,
        actorParentIsValidatedAppleLaunchService: Bool = false,
        actorIsInterpreter: Bool = false,
        hasRecentKeychainCommand: Bool = false
    ) -> Finding? {
        guard let store = sensitiveStore(at: path) else { return nil }
        if store == .keychain {
            if hasRecentKeychainCommand {
                return Finding(
                    title: "Read a Keychain secret",
                    reason: "keychain_command_correlation",
                    store: .keychain,
                    tier: "protected",
                    severity: "critical"
                )
            }
            // A plain read by any cryptographically validated distribution
            // identity is routine. Destructive/copy operations are classified
            // separately and never use this exemption.
            return actorIdentityValidated ? nil : Finding(
                title: "Opened the macOS Keychain",
                reason: "credential_store_access",
                store: .keychain
            )
        }
        if ownsStore(path: path, identity: responsibleIdentity) {
            return nil
        }
        return findingForOpen(
            store: store,
            responsibleIdentity: responsibleIdentity,
            actorIsValidatedApplePlatform: actorIsValidatedApplePlatform,
            actorIsOwnResponsibleProcess: actorIsOwnResponsibleProcess,
            actorParentIsLaunchd: actorParentIsLaunchd,
            actorParentIsValidatedAppleLaunchService: actorParentIsValidatedAppleLaunchService,
            actorIsInterpreter: actorIsInterpreter
        )
    }

    /// Returns true only when a SecCode-validated reader is accessing data in
    /// the standard per-bundle locations for its own exact bundle identifier.
    /// Paths and display names never establish identity by themselves.
    static func ownsStore(path: String, identity: ValidatedIdentity?) -> Bool {
        guard let identity,
              identity.signingValidated,
              let bundleID = identity.bundleID?.trimmingCharacters(in: .whitespacesAndNewlines),
              !bundleID.isEmpty else { return false }
        let components = URL(fileURLWithPath: path).standardizedFileURL.pathComponents
        func containsSequence(_ sequence: [String]) -> Bool {
            guard components.count >= sequence.count else { return false }
            return (0...(components.count - sequence.count)).contains { offset in
                Array(components[offset..<(offset + sequence.count)]) == sequence
            }
        }
        return containsSequence(["Library", "Containers", bundleID])
            || containsSequence(["Library", "HTTPStorages", bundleID])
            || containsSequence(["Library", "Application Support", bundleID])
    }

    static func findingForOpen(
        store: Store,
        responsibleIdentity: ValidatedIdentity?,
        actorIsValidatedApplePlatform: Bool = false,
        actorIsOwnResponsibleProcess: Bool = false,
        actorParentIsLaunchd: Bool = false,
        actorParentIsValidatedAppleLaunchService: Bool = false,
        actorIsInterpreter: Bool = false
    ) -> Finding? {
        if actorIsValidatedApplePlatform,
           (actorParentIsLaunchd || actorParentIsValidatedAppleLaunchService),
           !actorIsInterpreter {
            return nil
        }
        guard !isTrustedCredentialApplication(responsibleIdentity) else {
            return nil
        }
        return Finding(
            title: behaviorTitle(for: store),
            reason: "credential_store_access",
            store: store
        )
    }

    static func findingForKeychainTransfer() -> Finding {
        Finding(
            title: "Copied the macOS Keychain",
            reason: "keychain_store_transfer",
            store: .keychain,
            tier: "protected",
            severity: "critical"
        )
    }

    static func shouldReportKeychainTransfer(
        sourcePath: String,
        destinationPath: String,
        actorIsValidatedApplePlatform: Bool = false,
        actorParentIsLaunchd: Bool = false
    ) -> Bool {
        guard sensitiveStore(at: sourcePath) == .keychain else { return false }
        // Atomic database maintenance commonly clones, exchanges, or renames
        // files inside a Keychains directory. A credential transfer requires
        // the destination to leave every system or per-user Keychains folder.
        // The validated daemon condition is retained explicitly so this policy
        // never turns a process name into trust evidence.
        if isInsideKeychainsDirectory(destinationPath) {
            if actorIsValidatedApplePlatform && actorParentIsLaunchd { return false }
            return false
        }
        return true
    }

    static func findingForKeychainCorrelation() -> Finding {
        Finding(
            title: "Read a Keychain secret after a hidden password prompt",
            reason: "keychain_command_correlation",
            store: .keychain,
            tier: "protected",
            severity: "critical"
        )
    }

    static func armsKeychainCorrelation(reason: String) -> Bool {
        reason == "hidden_password_prompt"
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

        guard executable == "security" else { return nil }
        let lowered = arguments.map { $0.lowercased() }
        let safeStorage = isBrowserSafeStorageRead(arguments: arguments)
        let requestsSecretValue = lowered.contains { argument in
            guard argument.hasPrefix("-") else { return false }
            return argument.dropFirst().contains("w")
        }
        // Safe Storage keys unlock browser credentials. They stay loud even
        // when the initiating chain is otherwise validated or trusted.
        if lowered.contains("find-generic-password"), requestsSecretValue, safeStorage {
            return Finding(
                title: "Browser Safe Storage key read needs review",
                reason: "keychain_secret_read",
                store: .keychain,
                tier: "review",
                severity: "high"
            )
        }
        guard !isTrustedCredentialApplication(responsibleIdentity) else { return nil }
        if lowered.contains("dump-keychain") {
            return Finding(title: "Keychain dump command needs review", reason: "keychain_dump", store: .keychain)
        }
        if lowered.contains("find-generic-password"), requestsSecretValue {
            return Finding(
                title: "Keychain secret read needs review",
                reason: "keychain_secret_read",
                store: .keychain,
                tier: "review",
                severity: "medium"
            )
        }
        return nil
    }

    static func deliveryProfile(
        for finding: Finding,
        actorIdentityValidated: Bool,
        responsibleChainValidated: Bool
    ) -> DeliveryProfile {
        let validatedRoutineSecretRead = finding.reason == "keychain_secret_read"
            && finding.severity != "high"
            && actorIdentityValidated
            && responsibleChainValidated
        return DeliveryProfile(
            tier: finding.tier,
            severity: validatedRoutineSecretRead ? "info" : finding.severity,
            deliveryLevel: validatedRoutineSecretRead ? "inform" : "interrupt"
        )
    }

    static func isBrowserSafeStorageRead(arguments: [String]) -> Bool {
        let browserServices = [
            "chrome safe storage", "brave safe storage", "edge safe storage",
            "arc safe storage", "opera safe storage", "vivaldi safe storage",
            "chromium safe storage"
        ]
        return arguments.contains { argument in
            let normalized = argument
                .trimmingCharacters(in: .whitespacesAndNewlines)
                .lowercased()
            return browserServices.contains(normalized)
        }
    }

    private static func isTrustedCredentialApplication(_ identity: ValidatedIdentity?) -> Bool {
        guard let identity, identity.signingValidated, let bundleID = identity.bundleID else { return false }
        let signer = identity.isApplePlatform ? "APPLE_PLATFORM"
            : (identity.teamID == "APPLE" ? "APPLE" : (identity.teamID ?? ""))
        return trustedApplications.contains("\(signer)|\(bundleID)")
    }

    static func behaviorTitle(for store: Store) -> String {
        switch store {
        case .browserCookies: "Opened browser cookies"
        case .browserLogins: "Opened saved browser logins"
        case .keychain: "Read a Keychain secret"
        case .sshPrivateKey: "Opened an SSH private key"
        case .cryptocurrencyWallet: "Opened cryptocurrency wallet data"
        case .browserWallet: "Opened browser wallet data"
        case .cloudCredential: "Opened cloud credentials"
        case .messagingSession: "Opened a messaging session"
        case .notesData: "Opened Notes data"
        case .walletPass: "Opened Wallet passes"
        case .passwordPrompt: "Requested a hidden password"
        }
    }

    static func isInsideKeychainsDirectory(_ rawPath: String) -> Bool {
        let components = URL(fileURLWithPath: rawPath)
            .standardizedFileURL.pathComponents.map { $0.lowercased() }
        guard let library = components.lastIndex(of: "library"),
              components.indices.contains(library + 1) else { return false }
        return components[library + 1] == "keychains"
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

/// Correlates the ordinary OPEN + CREATE/WRITE sequence used by tools which
/// copy bytes in user space instead of asking the kernel for COPYFILE/CLONE.
/// Process-instance identity prevents PID reuse from joining unrelated I/O.
struct KeychainTransferFallbackTracker: Sendable {
    struct PendingRead: Equatable, Sendable {
        let sourcePath: String
        let recordedAt: Date
    }

    private var reads: [ProcessInstanceIdentity: PendingRead] = [:]
    let window: TimeInterval

    init(window: TimeInterval = 30) {
        self.window = window
    }

    @discardableResult
    mutating func recordRead(
        sourcePath: String,
        process: ProcessInstanceIdentity,
        at date: Date
    ) -> PendingRead? {
        guard CredentialAccessPolicy.sensitiveStore(at: sourcePath) == .keychain else { return nil }
        prune(at: date)
        let pending = PendingRead(sourcePath: sourcePath, recordedAt: date)
        reads[process] = pending
        return pending
    }

    mutating func pendingReadForExternalClose(
        destinationPath: String,
        process: ProcessInstanceIdentity,
        at date: Date
    ) -> PendingRead? {
        prune(at: date)
        guard !CredentialAccessPolicy.isInsideKeychainsDirectory(destinationPath),
              let pending = reads[process],
              date.timeIntervalSince(pending.recordedAt) >= 0,
              date.timeIntervalSince(pending.recordedAt) <= window
        else { return nil }
        return pending
    }

    mutating func cancel(process: ProcessInstanceIdentity) {
        reads.removeValue(forKey: process)
    }

    func hasPendingRead(
        process: ProcessInstanceIdentity,
        matching pending: PendingRead
    ) -> Bool {
        reads[process] == pending
    }

    private mutating func prune(at date: Date) {
        reads = reads.filter {
            date.timeIntervalSince($0.value.recordedAt) >= 0
                && date.timeIntervalSince($0.value.recordedAt) <= window
        }
    }
}

/// Content proof for user-space keychain copies which appear to Endpoint
/// Security as ordinary OPEN + CREATE/WRITE + CLOSE events. Callers obtain the
/// bounded samples off the ES callback thread.
enum KeychainTransferContentPolicy {
    private static let keychainMagic = Data("kych".utf8)
    private static let sqliteMagic = Data("SQLite format 3\0".utf8)

    static func isVerifiedTransfer(
        sourcePrefix: Data,
        sourceSize: UInt64,
        destinationPrefix: Data,
        destinationSize: UInt64
    ) -> Bool {
        if destinationPrefix.starts(with: keychainMagic) {
            return true
        }
        guard sourcePrefix.starts(with: sqliteMagic),
              sourceSize == destinationSize,
              !sourcePrefix.isEmpty,
              sourcePrefix.count == destinationPrefix.count
        else { return false }
        return SHA256.hash(data: sourcePrefix) == SHA256.hash(data: destinationPrefix)
    }
}
