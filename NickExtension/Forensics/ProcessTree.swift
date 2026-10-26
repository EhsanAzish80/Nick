// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation
import Security

enum ESCallbackSafetyGuard {
    private static let key = "com.ehsanazish.nick.es-callback"

    static var isOnCallbackThread: Bool {
        Thread.current.threadDictionary[key] as? Bool == true
    }

    static func enter() { Thread.current.threadDictionary[key] = true }
    static func leave() { Thread.current.threadDictionary.removeObject(forKey: key) }

    static func requireOffCallbackThread(
        _ operation: StaticString,
        file: StaticString = #fileID,
        line: UInt = #line
    ) {
#if DEBUG
        assert(
            !isOnCallbackThread,
            "\(operation) must not run on the Endpoint Security callback thread",
            file: file,
            line: line
        )
#endif
    }
}

/// Testable boundary for work that may inspect another process. Scheduling is
/// deliberately fire-and-forget so a wedged resolver cannot hold an ES reply.
final class ESForeignProcessWorkScheduler: @unchecked Sendable {
    private let queue: DispatchQueue

    init(queue: DispatchQueue = DispatchQueue(
        label: "com.ehsanazish.nick.foreign-process-resolver",
        qos: .utility
    )) {
        self.queue = queue
    }

    func schedule<Result: Sendable>(
        operation: @escaping @Sendable () -> Result,
        completion: @escaping @Sendable (Result) -> Void
    ) {
        queue.async { completion(operation()) }
    }
}
import Darwin
import os

struct ResponsibleAppIdentity: Equatable, Sendable {
    enum Signing: String, Equatable, Sendable {
        case applePlatform = "Apple platform"
        case signed = "Signed"
        case unsigned = "Unsigned"
        case unknown = "Unknown"
    }

    let name: String
    let bundleID: String?
    let teamID: String?
    let signing: Signing
    let path: String
}

struct ResponsibleAppAttribution: Equatable, Sendable {
    let app: ResponsibleAppIdentity?
    let chain: [String]

    var displayName: String { app?.name ?? "Unknown app" }
    var displayLine: String {
        guard chain.count > 1 else { return "\(displayName) ran this" }
        return "\(displayName) ran this · via \(chain.dropFirst().joined(separator: " → "))"
    }

    var metadata: [String: String] {
        var values = [
            "responsibleAppName": displayName,
            "responsibleAppSigning": app?.signing.rawValue ?? ResponsibleAppIdentity.Signing.unknown.rawValue,
            "responsibleChain": chain.prefix(5).joined(separator: " → ")
        ]
        if let app {
            values["responsibleAppPath"] = app.path
            values["responsibleAppBundleID"] = app.bundleID ?? ""
            values["responsibleAppTeamID"] = app.teamID ?? ""
        }
        return values
    }
}

protocol ResponsibleProcessIdentityResolving: Sendable {
    func identity(pid: Int32, pathHint: String?) -> ResponsibleAppIdentity?
    func liveProcess(pid: Int32) -> ResponsibleLiveProcess?
}

extension ResponsibleProcessIdentityResolving {
    func liveProcess(pid: Int32) -> ResponsibleLiveProcess? { nil }
}

struct ResponsibleLiveProcess: Equatable, Sendable {
    let pid: Int32
    let ppid: Int32
    let path: String
}

/// Reads the running process's kernel-selected code object and validates it
/// before exposing bundle/team attribution. Caller-supplied identifiers are
/// never trusted.
final class SecCodeResponsibleProcessIdentityResolver: ResponsibleProcessIdentityResolving, @unchecked Sendable {
    static let shared = SecCodeResponsibleProcessIdentityResolver()

    func identity(pid: Int32, pathHint: String?) -> ResponsibleAppIdentity? {
        ESCallbackSafetyGuard.requireOffCallbackThread("SecCodeCopyGuest/proc_pidpath")
        let path = executablePath(pid: pid) ?? pathHint
        guard let path, !path.isEmpty else { return nil }
        let appURL = Self.appBundleURL(for: path)
        let bundle = appURL.flatMap(Bundle.init(url:))
        let name = bundle?.object(forInfoDictionaryKey: "CFBundleDisplayName") as? String
            ?? bundle?.object(forInfoDictionaryKey: "CFBundleName") as? String
            ?? URL(fileURLWithPath: path).lastPathComponent

        let attributes: [CFString: Any] = [kSecGuestAttributePid: pid]
        var code: SecCode?
        let copyStatus = SecCodeCopyGuestWithAttributes(nil, attributes as CFDictionary, [], &code)
        guard copyStatus == errSecSuccess, let code else {
            return ResponsibleAppIdentity(
                name: name, bundleID: bundle?.bundleIdentifier, teamID: nil,
                signing: .unknown, path: appURL?.path ?? path
            )
        }
        var staticCode: SecStaticCode?
        let staticStatus = SecCodeCopyStaticCode(code, [], &staticCode)
        var information: CFDictionary?
        let infoStatus = staticCode.map {
            SecCodeCopySigningInformation(
                $0, SecCSFlags(rawValue: kSecCSSigningInformation), &information
            )
        } ?? errSecCSUnsigned
        let valid = SecCodeCheckValidity(code, [], nil) == errSecSuccess
        guard staticStatus == errSecSuccess,
              infoStatus == errSecSuccess,
              let info = information as? [String: Any] else {
            return ResponsibleAppIdentity(
                name: name, bundleID: bundle?.bundleIdentifier, teamID: nil,
                signing: valid ? .signed : .unsigned, path: appURL?.path ?? path
            )
        }
        let identifier = info[kSecCodeInfoIdentifier as String] as? String
        let teamID = info[kSecCodeInfoTeamIdentifier as String] as? String
        let flags = (info[kSecCodeInfoFlags as String] as? NSNumber)?.uint32Value ?? 0
        let platformFlag = UInt32(0x0400_0000) // CS_PLATFORM_BINARY
        let signing: ResponsibleAppIdentity.Signing
        if valid, flags & platformFlag != 0 {
            signing = .applePlatform
        } else if valid, identifier != nil {
            signing = .signed
        } else {
            signing = .unsigned
        }
        return ResponsibleAppIdentity(
            name: name,
            bundleID: bundle?.bundleIdentifier ?? identifier,
            teamID: teamID,
            signing: signing,
            path: appURL?.path ?? path
        )
    }

    func liveProcess(pid: Int32) -> ResponsibleLiveProcess? {
        ESCallbackSafetyGuard.requireOffCallbackThread("proc_pidinfo/proc_pidpath")
        guard let path = executablePath(pid: pid) else { return nil }
        var info = proc_bsdinfo()
        let size = Int32(MemoryLayout<proc_bsdinfo>.stride)
        let copied = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, size)
        guard copied == size else { return nil }
        return ResponsibleLiveProcess(pid: pid, ppid: Int32(info.pbi_ppid), path: path)
    }

    private func executablePath(pid: Int32) -> String? {
        var buffer = [CChar](repeating: 0, count: 4_096)
        let count = proc_pidpath(pid, &buffer, UInt32(buffer.count))
        guard count > 0 else { return nil }
        let bytes = buffer.prefix(Int(count)).map { UInt8(bitPattern: $0) }
        return String(decoding: bytes, as: UTF8.self)
    }

    static func appBundleURL(for executablePath: String) -> URL? {
        let components = URL(fileURLWithPath: executablePath).pathComponents
        guard let index = components.lastIndex(where: { $0.hasSuffix(".app") }) else { return nil }
        return URL(fileURLWithPath: NSString.path(withComponents: Array(components.prefix(index + 1))))
    }
}

// MARK: - ProcessTree

/// Phase 6.2 — Process genealogy tracker.
///
/// Maintains a lightweight in-memory tree of every process exec'd since the
/// extension started. For each threat alert Nick can reconstruct the full
/// attack chain (root → threat) and the subtree the threat spawned.
///
/// All mutations are serialised through an `NSLock` so the class can be safely
/// called from ES event callbacks on arbitrary threads.
///
/// **Memory management:** call `pruneExited(olderThan:)` periodically
/// (e.g. every hour from `main.swift`) to discard exited, benign nodes.
final class ProcessTree: @unchecked Sendable {

    // MARK: - Types

    /// A single node in the process tree.
    struct ProcessNode: Codable, Sendable {
        let pid: Int32
        let ppid: Int32
        let path: String
        var args: [String]
        let startTime: Date
        var exitTime: Date?
        var exitCode: Int32?
        var childPids: [Int32]
        var filesAccessed: [FileAccess]
        var networkConnections: [NetworkConn]
        /// Marked `true` when a downstream detector flags this process.
        var isThreat: Bool

        struct FileAccess: Codable, Sendable {
            let path: String
            /// One of: "open", "write", "delete", "exec", "rename"
            let operation: String
            let timestamp: Date
        }

        struct NetworkConn: Codable, Sendable {
            let host: String
            let port: String
            let timestamp: Date
        }
    }

    /// Snapshot exported to the container app for visualization.
    struct Export: Codable, Sendable {
        /// Chain from the root ancestor down to the threat process.
        let attackChain: [ProcessNode]
        /// The threat process and all processes it spawned.
        let subtree: [ProcessNode]
        let exportedAt: Date
    }

    // MARK: - Private

    private var nodes: [Int32: ProcessNode] = [:]
    private let lock = NSLock()

    /// ES argv is untrusted input. Keep both each node and the benign tree
    /// bounded while retaining protected attack-chain nodes.
    static let maximumArgumentCount = 64
    static let maximumArgumentBytes = 4_096
    static let maximumBenignNodeCount = 4_096
    private static let truncationMarker = "<truncated>"

    private static let logger = Logger(
        subsystem: "com.ehsanazish.nick",
        category: "ProcessTree"
    )

    // MARK: - Record Events

    /// Records an `exec` event. Called from `ES_EVENT_TYPE_NOTIFY_EXEC`.
    func recordExec(pid: Int32, ppid: Int32, path: String, args: [String]) {
        lock.withLock {
            evictOldestBenignNodeIfNeeded()
            let node = ProcessNode(
                pid: pid, ppid: ppid, path: path, args: Self.boundedArguments(args),
                startTime: Date(), exitTime: nil, exitCode: nil,
                childPids: [], filesAccessed: [], networkConnections: [],
                isThreat: false
            )
            nodes[pid] = node
            nodes[ppid]?.childPids.append(pid)
        }
    }

    /// Records a process exit. Called from `ES_EVENT_TYPE_NOTIFY_EXIT`.
    func recordExit(pid: Int32, exitCode: Int32) {
        lock.withLock {
            nodes[pid]?.exitTime = Date()
            nodes[pid]?.exitCode = exitCode
            // Command evidence needed by incidents is copied into signal
            // metadata before exit. Release the potentially large argv now.
            nodes[pid]?.args.removeAll(keepingCapacity: false)
        }
    }

    /// Records a file-access event for the given process.
    func recordFileAccess(pid: Int32, path: String, operation: String) {
        lock.withLock {
            let access = ProcessNode.FileAccess(
                path: path, operation: operation, timestamp: Date()
            )
            nodes[pid]?.filesAccessed.append(access)
        }
    }

    /// Records an outbound network connection for the given process.
    func recordNetworkConnection(pid: Int32, host: String, port: String) {
        lock.withLock {
            let conn = ProcessNode.NetworkConn(host: host, port: port, timestamp: Date())
            nodes[pid]?.networkConnections.append(conn)
        }
    }

    /// Marks a process (and all its ancestors up to launchd) as part of an
    /// attack chain. Called when a threat alert is raised for `pid`.
    func markAsThreat(pid: Int32) {
        lock.withLock {
            var current = pid
            while let node = nodes[current] {
                nodes[current]?.isThreat = true
                if node.ppid <= 1 { break }
                current = node.ppid
            }
        }
    }

    // MARK: - Query

    /// Returns the chain from the root ancestor down to `pid` (inclusive).
    ///
    /// The first element is the oldest ancestor; the last is `pid` itself.
    func attackChain(pid: Int32) -> [ProcessNode] {
        lock.withLock {
            var chain: [ProcessNode] = []
            var current = pid
            while let node = nodes[current] {
                chain.append(node)
                if node.ppid <= 1 { break }
                current = node.ppid
            }
            return chain.reversed()
        }
    }

    /// Resolves attribution while the actor and its ancestry are still live.
    /// The ES responsible process wins when it identifies an application.
    /// Otherwise ancestry is walked from actor to root, skipping command-line
    /// intermediaries even when their binary happens to live inside an app.
    func responsibleApp(
        actorPID: Int32,
        responsiblePID: Int32?,
        resolver: ResponsibleProcessIdentityResolving
    ) -> ResponsibleAppAttribution {
        let lineage = attributionLineage(actorPID: actorPID, resolver: resolver)
        let chain = lineage.compactMap(\.node)
        let nodeByPID = Dictionary(uniqueKeysWithValues: chain.map { ($0.pid, $0) })
        let responsible = responsiblePID.flatMap {
            resolver.identity(pid: $0, pathHint: nodeByPID[$0]?.path)
        }
        let responsibleApp = responsible.flatMap { identity in
            identity.path.hasSuffix(".app") ? identity : nil
        }

        let selected = responsibleApp ?? chain.lazy.compactMap { node -> ResponsibleAppIdentity? in
            guard let identity = resolver.identity(pid: node.pid, pathHint: node.path),
                  Self.isMainBundleExecutable(node.path, app: identity) else { return nil }
            return identity
        }.first

        guard let selected else {
            let labels = lineage.map { entry in
                entry.node.map { Self.chainLabel(for: $0.path) } ?? "?"
            }
            return ResponsibleAppAttribution(
                app: nil,
                chain: ["Unknown app"] + Array(labels.suffix(4))
            )
        }
        let mainIndex = lineage.firstIndex {
            $0.node.map { Self.isMainBundleExecutable($0.path, app: selected) } ?? false
        }
        let responsibleIndex = responsiblePID.flatMap { pid in
            lineage.firstIndex { $0.node?.pid == pid }
        }
        let selectedIndex = mainIndex ?? responsibleIndex
        let suffix = selectedIndex.map { Array(lineage[$0...]) } ?? Array(lineage.suffix(4))
        var labels = [selected.name]
        for entry in suffix {
            guard let node = entry.node else {
                if labels.last != "?" { labels.append("?") }
                continue
            }
            if Self.isMainBundleExecutable(node.path, app: selected) { continue }
            let label = Self.chainLabel(for: node.path)
            if labels.last != label { labels.append(label) }
        }
        if labels.count == 1, let actor = chain.last {
            let actorLabel = Self.chainLabel(for: actor.path)
            if actorLabel != labels[0] { labels.append(actorLabel) }
        }
        // Terminal is itself the user-visible launcher. A lone shell beneath it
        // adds noise; deeper tool chains remain visible (for example an app,
        // its embedded CLI, then zsh).
        if selected.name == "Terminal", labels.count == 2,
           let actor = chain.last, Self.isShellOrInterpreter(actor.path) {
            labels.removeLast()
        }
        return ResponsibleAppAttribution(app: selected, chain: Array(labels.prefix(5)))
    }

    private struct AttributionLineageEntry {
        let node: ProcessNode?
    }

    /// Builds a bounded root-to-actor chain. Processes that predate the
    /// extension are recovered from the kernel. A process that exited before
    /// it could be resolved remains an explicit gap instead of disappearing.
    private func attributionLineage(
        actorPID: Int32,
        resolver: ResponsibleProcessIdentityResolving
    ) -> [AttributionLineageEntry] {
        let tracked = lock.withLock { nodes }
        var reverse: [AttributionLineageEntry] = []
        var current = actorPID
        var visited: Set<Int32> = []

        while current > 1, reverse.count < 5, visited.insert(current).inserted {
            if let node = tracked[current] {
                reverse.append(AttributionLineageEntry(node: node))
                // ES can occasionally give a flattened parent audit token for
                // an exec while the kernel still has the direct helper/CLI
                // parent. Reconcile every live node generically; this is about
                // topology, never an app or tool allowlist. Require the live
                // executable to match before trusting its ppid so PID reuse
                // cannot splice an unrelated process into stored evidence.
                if let live = resolver.liveProcess(pid: current),
                   live.path == node.path,
                   live.ppid > 0 {
                    current = live.ppid
                } else {
                    current = node.ppid
                }
                continue
            }
            guard let live = resolver.liveProcess(pid: current) else {
                reverse.append(AttributionLineageEntry(node: nil))
                break
            }
            reverse.append(AttributionLineageEntry(node: ProcessNode(
                pid: live.pid,
                ppid: live.ppid,
                path: live.path,
                args: [],
                startTime: Date(),
                exitTime: nil,
                exitCode: nil,
                childPids: [],
                filesAccessed: [],
                networkConnections: [],
                isThreat: false
            )))
            current = live.ppid
        }
        return reverse.reversed()
    }

    /// Returns `pid` and all of its descendants (breadth-first).
    func subtree(pid: Int32) -> [ProcessNode] {
        lock.withLock {
            var result: [ProcessNode] = []
            var queue: [Int32] = [pid]
            while !queue.isEmpty {
                let current = queue.removeFirst()
                if let node = nodes[current] {
                    result.append(node)
                    queue.append(contentsOf: node.childPids)
                }
            }
            return result
        }
    }

    /// Builds a JSON-encodable `Export` for the threat at `pid`.
    func export(pid: Int32) -> Export {
        Export(
            attackChain: attackChain(pid: pid),
            subtree: subtree(pid: pid),
            exportedAt: Date()
        )
    }

    /// Serialises an `Export` to JSON `Data` for XPC transmission.
    func exportData(pid: Int32) -> Data? {
        let snapshot = export(pid: pid)
        return try? JSONEncoder().encode(snapshot)
    }

    // MARK: - Maintenance

    /// Removes exited, non-threat nodes older than `seconds`.
    ///
    /// Call periodically (e.g. hourly) to prevent unbounded memory growth.
    func pruneExited(olderThan seconds: TimeInterval = 3600) {
        lock.withLock {
            let cutoff = Date().addingTimeInterval(-seconds)
            let stale = nodes.filter {
                $0.value.exitTime != nil
                    && $0.value.exitTime! < cutoff
                    && !$0.value.isThreat
            }
            for pid in stale.keys {
                nodes.removeValue(forKey: pid)
            }
            if !stale.isEmpty {
                Self.logger.debug("ProcessTree: pruned \(stale.count) stale node(s)")
            }
        }
    }

    /// Total number of tracked processes.
    var count: Int {
        lock.withLock { nodes.count }
    }

    /// Test/diagnostic visibility for the retained argv budget.
    var retainedArgumentBytes: Int {
        lock.withLock {
            nodes.values.reduce(into: 0) { total, node in
                total += node.args.reduce(0) { $0 + $1.utf8.count }
            }
        }
    }

    private static func boundedArguments(_ arguments: [String]) -> [String] {
        var result: [String] = []
        result.reserveCapacity(min(arguments.count, maximumArgumentCount))
        let markerBytes = truncationMarker.utf8.count
        var remainingBytes = maximumArgumentBytes - markerBytes
        var truncated = arguments.count > maximumArgumentCount

        for argument in arguments.prefix(maximumArgumentCount) {
            guard remainingBytes > 0 else {
                truncated = true
                break
            }
            let bytes = Array(argument.utf8)
            if bytes.count <= remainingBytes {
                result.append(argument)
                remainingBytes -= bytes.count
                continue
            }

            result.append(String(decoding: bytes.prefix(remainingBytes), as: UTF8.self))
            remainingBytes = 0
            truncated = true
            break
        }

        if truncated {
            if result.count == maximumArgumentCount, let last = result.popLast() {
                result.append(last + truncationMarker)
            } else {
                result.append(truncationMarker)
            }
        }
        return result
    }

    private static let commandLineTools: Set<String> = [
        "bash", "sh", "zsh", "python", "python3", "node", "osascript", "curl", "wget",
        "codex", "codexcli", "systemextensionsctl", "shove"
    ]

    private static func isMainBundleExecutable(_ executablePath: String, app: ResponsibleAppIdentity) -> Bool {
        guard app.path.hasSuffix(".app") else { return false }
        let bundleURL = URL(fileURLWithPath: app.path)
        let executableName = Bundle(url: bundleURL)?.object(forInfoDictionaryKey: "CFBundleExecutable") as? String
            ?? app.name
        let expected = bundleURL.appendingPathComponent("Contents/MacOS/\(executableName)").path
        return URL(fileURLWithPath: executablePath).standardizedFileURL.path
            == URL(fileURLWithPath: expected).standardizedFileURL.path
    }

    private static func isCommandLineTool(_ path: String) -> Bool {
        commandLineTools.contains(URL(fileURLWithPath: path).lastPathComponent.lowercased())
    }

    private static func isShellOrInterpreter(_ path: String) -> Bool {
        let name = URL(fileURLWithPath: path).lastPathComponent.lowercased()
        return ["zsh", "bash", "sh", "python", "python3", "node", "osascript"].contains(name)
    }

    private static func chainLabel(for path: String) -> String {
        let value = URL(fileURLWithPath: path).lastPathComponent
        switch value.lowercased() {
        case "codexcli", "codex": return "Codex CLI"
        case "zsh": return "zsh"
        case "bash": return "bash"
        case "sh": return "sh"
        case "systemextensionsctl": return "systemextensionsctl"
        case "shove": return "shove"
        default: return value.replacingOccurrences(of: ".app", with: "")
        }
    }

    private func evictOldestBenignNodeIfNeeded() {
        guard nodes.count >= Self.maximumBenignNodeCount else { return }
        let candidate = nodes.values
            .filter { !$0.isThreat }
            .min { lhs, rhs in
                if (lhs.exitTime != nil) != (rhs.exitTime != nil) {
                    return lhs.exitTime != nil
                }
                return lhs.startTime < rhs.startTime
            }
        guard let candidate else { return }
        nodes.removeValue(forKey: candidate.pid)
        nodes[candidate.ppid]?.childPids.removeAll { $0 == candidate.pid }
    }
}
