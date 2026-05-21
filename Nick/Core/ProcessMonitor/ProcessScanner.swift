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

    // MARK: - Private Helpers

    /// Calls `sysctl(CTL_KERN, KERN_PROC, KERN_PROC_ALL)` and returns the raw kinfo_proc array.
    private func fetchKinfoList() throws -> [kinfo_proc] {
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0]
        var size = 0

        // First call to determine buffer size
        guard sysctl(&mib, 4, nil, &size, nil, 0) == 0 else {
            throw ProcessScannerError.sysctlFailed(errno: errno)
        }

        let count = size / MemoryLayout<kinfo_proc>.stride
        var buffer = [kinfo_proc](repeating: kinfo_proc(), count: count)

        guard sysctl(&mib, 4, &buffer, &size, nil, 0) == 0 else {
            throw ProcessScannerError.sysctlFailed(errno: errno)
        }

        // Trim to actual count in case size changed between the two calls
        let actualCount = size / MemoryLayout<kinfo_proc>.stride
        return Array(buffer.prefix(actualCount))
    }

    private func buildProcessInfo(from kinfo: kinfo_proc) -> NickProcessInfo? {
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

        let signingStatus: SigningStatus = path.isEmpty
            ? .unknown
            : SignatureValidator.shared.evaluate(binaryPath: path)

        return NickProcessInfo(
            pid: pid,
            path: path,
            name: processName,
            parentPID: parentPID,
            parentName: nil, // resolved in second pass if needed
            signingStatus: signingStatus,
            user: user,
            startTime: startTime
        )
    }

    private func resolvePath(pid: Int32) -> String {
        // PROC_PIDPATHINFO_MAXSIZE = 4 * MAXPATHLEN = 4096 on all macOS versions.
        let maxSize = 4096
        var buffer = [CChar](repeating: 0, count: maxSize)
        let ret = proc_pidpath(pid, &buffer, UInt32(maxSize))
        guard ret > 0 else { return "" }
        return String(cString: buffer)
    }

    private func userName(for uid: uid_t) -> String? {
        guard let pw = getpwuid(uid) else { return nil }
        return String(cString: pw.pointee.pw_name)
    }

    // MARK: - Signal Generation

    /// Derives threat signals from a list of scanned processes.
    ///
    /// Detection rules:
    /// - Unsigned binary outside `/usr/`, `/System/`, `/Applications/` → `.medium`
    /// - Unsigned binary in `/tmp/`, `/var/folders/`, `/private/tmp/` → `.high`
    /// - Shell process with no terminal parent (LOLBin) → `.medium`
    ///
    /// - Parameter processes: Output of `scan()`.
    /// - Returns: Zero or more signals derived from this snapshot.
    func signals(from processes: [NickProcessInfo]) -> [ThreatSignal] {
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
                    processInfo: proc,
                    metadata: ["reason": "unsigned_temp_path"]
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
                    processInfo: proc,
                    metadata: ["reason": "unsigned"]
                ))
            }

            // Shell spawned without a terminal (LOLBin pattern)
            if Self.shellProcessNames.contains(proc.name.lowercased()) {
                let parentName = pidToName[proc.parentPID]?.lowercased() ?? ""
                let hasTerminalParent = parentName.contains("terminal")
                    || parentName.contains("iterm")
                    || parentName.contains("warp")
                    || parentName.contains("ssh")
                    || parentName.contains("bash")
                    || parentName.contains("zsh")
                if !hasTerminalParent {
                    signals.append(ThreatSignal(
                        source: .process,
                        severity: .medium,
                        title: "Shell spawned from non-terminal parent",
                        description: "'\(proc.name)' (PID \(proc.pid)) was spawned by '\(parentName.isEmpty ? "unknown" : parentName)' (PID \(proc.parentPID)), which is not a recognized terminal.",
                        processInfo: proc,
                        metadata: ["reason": "lolbin", "parent": parentName]
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
}
