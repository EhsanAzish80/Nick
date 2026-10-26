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
        let timestamp: Date
    }

    struct Finding: Equatable, Sendable {
        let reason: String
        let matchedCommand: String
        let actorPID: Int32
    }

    private struct Recent {
        let observation: Observation
        let role: Role
    }

    private enum Role { case downloader, shell }
    private let lock = NSLock()
    private var recent: [Int32: Recent] = [:]
    private let window: TimeInterval

    init(window: TimeInterval = 3) { self.window = window }

    func observe(_ observation: Observation) -> Finding? {
        guard !observation.pipeIdentifiers.isEmpty,
              let role = Self.role(for: observation) else { return nil }
        return lock.withLock {
            recent = recent.filter {
                observation.timestamp.timeIntervalSince($0.value.observation.timestamp) <= window
            }
            defer { recent[observation.pid] = Recent(observation: observation, role: role) }
            guard let sibling = recent.values.first(where: {
                $0.observation.parentPID == observation.parentPID
                    && $0.observation.pid != observation.pid
                    && $0.role != role
                    && !$0.observation.pipeIdentifiers.isDisjoint(with: observation.pipeIdentifiers)
            }) else { return nil }
            let downloader = role == .downloader ? observation : sibling.observation
            let shell = role == .shell ? observation : sibling.observation
            return Finding(
                reason: Self.executableName(downloader.executablePath) == "wget"
                    ? "wget_pipe_shell" : "curl_pipe_shell",
                matchedCommand: Self.redactedCommand(downloader, shell: shell),
                actorPID: shell.pid
            )
        }
    }

    private static func role(for observation: Observation) -> Role? {
        let name = executableName(observation.executablePath)
        if ["curl", "wget"].contains(name),
           observation.arguments.contains(where: { argument in
               let value = argument.lowercased()
               return value.hasPrefix("http://") || value.hasPrefix("https://")
           }) { return .downloader }
        if ["sh", "bash", "zsh", "dash", "ksh", "csh", "fish"].contains(name) {
            return .shell
        }
        return nil
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
