// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation

// MARK: - ParentChainAnalyzer

/// Analyzes the parent-process chain to detect suspicious process lineage.
///
/// Certain application-to-shell spawn patterns are reliable indicators of
/// exploitation — a web browser spawning a shell, a Microsoft Office macro
/// spawning a script interpreter, or a PDF viewer spawning a downloader.
///
/// **Suspicious chains detected:**
/// - Browser → shell  (e.g., Safari → bash — code execution via browser exploit)
/// - Office app → shell  (e.g., Word, Excel → osascript — macro-based attack)
/// - PDF viewer → shell  (e.g., Preview → python — PDF exploit)
/// - App → curl/wget  (arbitrary app downloading and executing — less specific, medium)
/// - Deep shell nesting  (shell → shell → shell — obfuscation indicator)
///
/// Signals are suppressed when the root of the chain is a trusted process.
enum ParentChainAnalyzer {

    // MARK: - Process Categories

    private static let browserNames: Set<String> = [
        "Safari", "SafariForWebKitDevelopment", "Google Chrome", "Firefox",
        "Brave Browser", "Microsoft Edge", "Opera", "Vivaldi", "Arc"
    ]

    private static let officeNames: Set<String> = [
        "Microsoft Word", "Microsoft Excel", "Microsoft PowerPoint",
        "Microsoft Outlook", "Numbers", "Pages", "Keynote",
        "LibreOffice", "OpenOffice"
    ]

    private static let pdfViewerNames: Set<String> = [
        "Preview", "Acrobat", "Adobe Acrobat", "PDF Expert", "Skim"
    ]

    private static let shellNames: Set<String> = [
        "bash", "sh", "zsh", "csh", "tcsh", "ksh", "fish", "dash"
    ]

    private static let interpreterNames: Set<String> = [
        "python", "python3", "ruby", "perl", "node", "osascript",
        "expect", "tclsh", "wish"
    ]

    private static let downloaderNames: Set<String> = [
        "curl", "wget", "fetch", "aria2c"
    ]

    // MARK: - Chain Analysis

    /// A resolved chain from the root ancestor down to the leaf process.
    struct ProcessChain {
        let processes: [NickProcessInfo]
        /// The most suspicious name in the chain.
        var root: NickProcessInfo? { processes.first }
        var leaf: NickProcessInfo? { processes.last }

        /// Depth of the chain (1 = no parent info available).
        var depth: Int { processes.count }
    }

    /// Builds the parent chain for `proc` from the provided process list.
    ///
    /// Walks up the PID → parentPID graph up to `maxDepth` hops. Cycles
    /// (PID == parentPID) are detected and break the walk.
    ///
    /// - Parameters:
    ///   - proc: The leaf process whose chain to build.
    ///   - allProcesses: Full snapshot for parent lookup.
    ///   - maxDepth: Maximum hops before truncating (default: 8).
    /// - Returns: A `ProcessChain` from root ancestor to `proc`.
    static func buildChain(
        for proc: NickProcessInfo,
        allProcesses: [NickProcessInfo],
        maxDepth: Int = 8
    ) -> ProcessChain {
        let pidMap = Dictionary(uniqueKeysWithValues: allProcesses.map { ($0.pid, $0) })
        var chain: [NickProcessInfo] = [proc]
        var current = proc
        var visited: Set<Int32> = [proc.pid]

        for _ in 0..<maxDepth {
            guard current.parentPID > 0,
                  let parent = pidMap[current.parentPID],
                  !visited.contains(parent.pid)
            else { break }
            chain.insert(parent, at: 0)
            visited.insert(parent.pid)
            current = parent
        }

        return ProcessChain(processes: chain)
    }

    // MARK: - Public API

    /// Evaluates the parent chain of a process for suspicious lineage.
    ///
    /// - Parameters:
    ///   - chain: A resolved `ProcessChain` for the process under evaluation.
    ///   - trustedProcessList: Allowlist — if the root of the chain is trusted, returns `nil`.
    /// - Returns: A `ThreatSignal` if a suspicious chain pattern is found.
    static func evaluateChain(
        _ chain: ProcessChain,
        trustedProcessList: TrustedProcessList = TrustedProcessList()
    ) -> ThreatSignal? {
        guard let leaf = chain.leaf, chain.depth >= 2 else { return nil }

        // If the chain's root is a trusted, signed process — suppress as intentional user activity.
        if let root = chain.root, trustedProcessList.isTrusted(root.name, pid: root.pid) { return nil }

        let chainNames = chain.processes.map { $0.name }
        let leafIsShellOrInterpreter = shellNames.contains(leaf.name.lowercased())
            || interpreterNames.contains(leaf.name.lowercased())

        // Pattern: Browser → shell/interpreter
        if let parent = chain.processes.dropLast().last,
           browserNames.contains(parent.name),
           leafIsShellOrInterpreter {
            return ThreatSignal(
                source: .process,
                severity: .critical,
                title: "Shell spawned from web browser",
                description: "'\(leaf.name)' (PID \(leaf.pid)) was spawned from browser '\(parent.name)'. This pattern indicates browser exploit or malicious web content execution.",
                context: ThreatSignalContext(
                    processInfo: leaf,
                    metadata: [
                        "reason": "browser_to_shell",
                        "detector": "ParentChainAnalyzer",
                        "chain": chainNames.joined(separator: " → ")
                    ]
                )
            )
        }

        // Pattern: Office app → shell/interpreter
        if let parent = chain.processes.dropLast().last,
           officeNames.contains(parent.name),
           leafIsShellOrInterpreter {
            return ThreatSignal(
                source: .process,
                severity: .critical,
                title: "Shell spawned from Office application",
                description: "'\(leaf.name)' (PID \(leaf.pid)) was spawned from '\(parent.name)'. This is the classic Office macro attack pattern.",
                context: ThreatSignalContext(
                    processInfo: leaf,
                    metadata: [
                        "reason": "office_to_shell",
                        "detector": "ParentChainAnalyzer",
                        "chain": chainNames.joined(separator: " → ")
                    ]
                )
            )
        }

        // Pattern: PDF viewer → shell/interpreter
        if let parent = chain.processes.dropLast().last,
           pdfViewerNames.contains(parent.name),
           leafIsShellOrInterpreter {
            return ThreatSignal(
                source: .process,
                severity: .critical,
                title: "Shell spawned from PDF viewer",
                description: "'\(leaf.name)' (PID \(leaf.pid)) was spawned from '\(parent.name)'. This pattern suggests PDF exploit exploitation.",
                context: ThreatSignalContext(
                    processInfo: leaf,
                    metadata: [
                        "reason": "pdf_to_shell",
                        "detector": "ParentChainAnalyzer",
                        "chain": chainNames.joined(separator: " → ")
                    ]
                )
            )
        }

        // Pattern: App → downloader
        if let parent = chain.processes.dropLast().last,
           downloaderNames.contains(leaf.name.lowercased()),
           !shellNames.contains(parent.name.lowercased()),
           !downloaderNames.contains(parent.name.lowercased()) {
            return ThreatSignal(
                source: .process,
                severity: .medium,
                title: "Application spawning network downloader",
                description: "'\(leaf.name)' (PID \(leaf.pid)) was spawned from '\(parent.name)'. Applications should not directly spawn download utilities.",
                context: ThreatSignalContext(
                    processInfo: leaf,
                    metadata: [
                        "reason": "app_to_downloader",
                        "detector": "ParentChainAnalyzer",
                        "chain": chainNames.joined(separator: " → ")
                    ]
                )
            )
        }

        // Pattern: Deep shell nesting (shell → shell → shell, depth ≥ 3)
        let shellDepth = chainNames.filter { shellNames.contains($0.lowercased()) }.count
        if shellDepth >= 3 {
            return ThreatSignal(
                source: .process,
                severity: .high,
                title: "Deep shell nesting detected",
                description: "Shell chain of depth \(shellDepth) detected: \(chainNames.joined(separator: " → ")). Multiple layers of shell spawning is a common obfuscation technique.",
                context: ThreatSignalContext(
                    processInfo: leaf,
                    metadata: [
                        "reason": "deep_shell_nesting",
                        "detector": "ParentChainAnalyzer",
                        "shell_depth": String(shellDepth),
                        "chain": chainNames.joined(separator: " → ")
                    ]
                )
            )
        }

        return nil
    }

    /// Evaluates all processes in a snapshot for suspicious chain patterns.
    ///
    /// Builds the parent chain for each process that is a shell or interpreter,
    /// then calls `evaluateChain(_:trustedProcessList:)`. Only leaf nodes
    /// (shells/interpreters) are evaluated to avoid duplicate signals.
    ///
    /// - Parameters:
    ///   - processes: Full process snapshot.
    ///   - trustedProcessList: Allowlist of process names to suppress.
    /// - Returns: All parent-chain signals found.
    static func signals(
        from processes: [NickProcessInfo],
        trustedProcessList: TrustedProcessList = TrustedProcessList()
    ) -> [ThreatSignal] {
        var results: [ThreatSignal] = []

        let candidates = processes.filter {
            shellNames.contains($0.name.lowercased())
                || interpreterNames.contains($0.name.lowercased())
                || downloaderNames.contains($0.name.lowercased())
        }

        for proc in candidates {
            guard !trustedProcessList.isTrusted(proc.name) else { continue }
            let chain = buildChain(for: proc, allProcesses: processes)
            if let signal = evaluateChain(chain, trustedProcessList: trustedProcessList) {
                results.append(signal)
            }
        }

        return results
    }
}
