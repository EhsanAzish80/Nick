import Foundation

/// Correlates short-lived sibling processes only when the kernel shows that
/// they share a pipe. Process names alone are insufficient evidence.
final class InteractiveShellPipelinePolicy: @unchecked Sendable {
    struct Observation: Sendable {
        let pid: Int32
        let parentPID: Int32
        let executablePath: String
        let arguments: [String]
        let pipeIdentifiers: Set<UInt64>
        let standardInputPipeIdentifier: UInt64?
        let hasNetworkSocket: Bool
        let codeIdentityValidated: Bool
        let timestamp: Date

        init(
            pid: Int32,
            parentPID: Int32,
            executablePath: String,
            arguments: [String],
            pipeIdentifiers: Set<UInt64>,
            standardInputPipeIdentifier: UInt64? = nil,
            hasNetworkSocket: Bool = false,
            codeIdentityValidated: Bool = false,
            timestamp: Date
        ) {
            self.pid = pid
            self.parentPID = parentPID
            self.executablePath = executablePath
            self.arguments = arguments
            self.pipeIdentifiers = pipeIdentifiers
            self.standardInputPipeIdentifier = standardInputPipeIdentifier
            self.hasNetworkSocket = hasNetworkSocket
            self.codeIdentityValidated = codeIdentityValidated
            self.timestamp = timestamp
        }
    }

    struct Finding: Equatable, Sendable {
        let reason: String
        let matchedCommand: String
        let actorPID: Int32
        let confidence: String
    }

    private struct Recent {
        let observation: Observation
        let role: Role
    }

    private struct ForkEvidence {
        let parentPID: Int32
        let pipeIdentifiers: Set<UInt64>
        let standardInputPipeIdentifier: UInt64?
        let timestamp: Date
    }

    private enum Role { case downloader, shell }
    private let lock = NSLock()
    private var recent: [Int32: Recent] = [:]
    private var forkEvidence: [Int32: ForkEvidence] = [:]
    private var emittedFingerprints: [String: Date] = [:]
    private let window: TimeInterval

    init(window: TimeInterval = 3) { self.window = window }

    func recordFork(
        childPID: Int32,
        parentPID: Int32,
        pipeIdentifiers: Set<UInt64>,
        standardInputPipeIdentifier: UInt64?,
        timestamp: Date = Date()
    ) {
        lock.withLock {
            forkEvidence[childPID] = ForkEvidence(
                parentPID: parentPID,
                pipeIdentifiers: pipeIdentifiers,
                standardInputPipeIdentifier: standardInputPipeIdentifier,
                timestamp: timestamp
            )
            prune(now: timestamp)
        }
    }

    func observe(_ observation: Observation) -> Finding? {
        return lock.withLock {
            prune(now: observation.timestamp)
            let observation = mergingForkEvidence(into: observation)
            guard !observation.pipeIdentifiers.isEmpty,
                  let role = Self.role(for: observation) else { return nil }
            defer { recent[observation.pid] = Recent(observation: observation, role: role) }
            guard let sibling = recent.values.first(where: {
                $0.observation.parentPID == observation.parentPID
                    && $0.observation.pid != observation.pid
                    && $0.role != role
                    && !$0.observation.pipeIdentifiers.isDisjoint(with: observation.pipeIdentifiers)
            }) else { return nil }
            let downloader = role == .downloader ? observation : sibling.observation
            let shell = role == .shell ? observation : sibling.observation
            let sharedPipes = downloader.pipeIdentifiers.intersection(shell.pipeIdentifiers)
            guard let sharedPipe = sharedPipes.sorted().first else { return nil }
            let fingerprint = "\(downloader.parentPID)|\(sharedPipe)|\(downloader.pid)|\(shell.pid)"
            guard emittedFingerprints[fingerprint] == nil else { return nil }
            emittedFingerprints[fingerprint] = observation.timestamp
            return Finding(
                reason: "download_pipe_interpreter",
                matchedCommand: Self.redactedCommand(downloader, shell: shell),
                actorPID: shell.pid,
                confidence: downloader.codeIdentityValidated && shell.codeIdentityValidated
                    ? "high" : "medium"
            )
        }
    }

    /// Descriptor state can appear shortly after AUTH_EXEC. Retry only when
    /// the command already has one half of the correlation evidence; doing so
    /// avoids scheduling work for every process launch on the Mac.
    func shouldRetry(_ observation: Observation) -> Bool {
        lock.withLock {
            prune(now: observation.timestamp)
            let observation = mergingForkEvidence(into: observation)
            return observation.arguments.contains(where: Self.containsRemoteURL)
                || observation.standardInputPipeIdentifier != nil
        }
    }

    private static func role(for observation: Observation) -> Role? {
        if observation.hasNetworkSocket,
           observation.arguments.contains(where: containsRemoteURL) {
            return .downloader
        }
        let name = executableName(observation.executablePath)
        let interpreters: Set<String> = [
            "sh", "bash", "zsh", "dash", "ksh", "csh", "fish",
            "python", "python3", "perl", "ruby", "node", "osascript", "php", "swift"
        ]
        if observation.standardInputPipeIdentifier != nil,
           interpreters.contains(name) {
            return .shell
        }
        return nil
    }

    private static func containsRemoteURL(_ argument: String) -> Bool {
        let value = argument.lowercased()
        return value.range(of: #"https?://[^\s\"']+"#, options: .regularExpression) != nil
    }

    private func mergingForkEvidence(into observation: Observation) -> Observation {
        guard let inherited = forkEvidence[observation.pid],
              observation.timestamp.timeIntervalSince(inherited.timestamp) <= window,
              inherited.parentPID == observation.parentPID else { return observation }
        return Observation(
            pid: observation.pid,
            parentPID: observation.parentPID,
            executablePath: observation.executablePath,
            arguments: observation.arguments,
            pipeIdentifiers: observation.pipeIdentifiers.union(inherited.pipeIdentifiers),
            standardInputPipeIdentifier: observation.standardInputPipeIdentifier
                ?? inherited.standardInputPipeIdentifier,
            hasNetworkSocket: observation.hasNetworkSocket,
            codeIdentityValidated: observation.codeIdentityValidated,
            timestamp: observation.timestamp
        )
    }

    private func prune(now: Date) {
        recent = recent.filter { now.timeIntervalSince($0.value.observation.timestamp) <= window }
        forkEvidence = forkEvidence.filter { now.timeIntervalSince($0.value.timestamp) <= window }
        emittedFingerprints = emittedFingerprints.filter { now.timeIntervalSince($0.value) <= window }
    }

    private static func executableName(_ path: String) -> String {
        URL(fileURLWithPath: path).lastPathComponent.lowercased()
    }

    private static func redactedCommand(_ downloader: Observation, shell: Observation) -> String {
        let safeArguments = downloader.arguments.dropFirst().map { argument -> String in
            guard var components = URLComponents(string: argument), components.scheme != nil else {
                return argument.count > 256 ? String(argument.prefix(256)) + "…" : argument
            }
            let hadCredentials = components.user != nil || components.password != nil
            let hadQuery = components.query != nil
            components.user = nil
            components.password = nil
            components.query = nil
            guard var value = components.string else { return "<redacted-url>" }
            if hadCredentials,
               let schemeRange = value.range(of: "://") {
                value.insert(contentsOf: "<redacted>@", at: schemeRange.upperBound)
            }
            if hadQuery { value += "?<redacted>" }
            return value
        }
        return ([executableName(downloader.executablePath)] + safeArguments).joined(separator: " ")
            + " | " + executableName(shell.executablePath)
    }
}
