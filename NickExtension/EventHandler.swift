// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import EndpointSecurity
import Foundation
import os

// MARK: - ESEventHandler

/// Receives raw `es_message_t` events from the ES client, makes allow/deny
/// decisions, and forwards typed `ESEvent` values to the container app via XPC.
///
/// **Phase 2 detection strategy — cache-first blocking:**
///
/// 1. `NOTIFY_CLOSE` (modified) → async SHA-256 scan → populate `ScanCache`
/// 2. `AUTH_EXEC` / `AUTH_OPEN` / `AUTH_MMAP` → cache lookup → deny if threat
///
/// First execution of a file that has never been seen before is **allowed**;
/// a background scan runs immediately and the cache is populated so all
/// subsequent executions are checked. Phase 4 ML closes this first-execution gap.
///
/// **Threading rule:**
/// - `handle(message:)` is called on the ES-internal serial queue.
/// - ALL data is extracted from `message` synchronously before returning.
/// - `esClient?.respond(to:allow:)` is called synchronously.
/// - Only value-typed copies are passed to `dispatchQueue.async` blocks —
///   the `UnsafePointer<es_message_t>` is NEVER captured in an async closure.
final class ESEventHandler {

    // MARK: - Dependencies

    weak var xpcServer: ESXPCServer?
    weak var esClient: EndpointSecurityClient?

    /// Injected by `main.swift` after construction.
    var fileScanner: FileScanner?

    /// Phase 3 — automated threat response.
    var remediationEngine: RemediationEngine?

    /// Phase 3 — file integrity monitoring.
    var fileIntegrityMonitor: FileIntegrityMonitor?

    /// Phase 4 — per-process behavioural timeline analysis.
    var behaviorTracker: BehaviorTracker?

    /// Phase 4 — static feature / ML-based pre-execution prediction.
    var threatPredictor: ThreatPredictor?

    /// Phase 4 — ransomware-specific heuristics + canary monitoring.
    var ransomwareDetector: RansomwareDetector?

    /// Phase 5 — TCC privacy permission monitoring.
    var privacyGuard: PrivacyGuard?

    /// Phase 5 — external/removable media scanning.
    var usbScanner: USBScanner?

    /// Phase 6 — process genealogy tracker.
    var processTree: ProcessTree?

    /// Phase 6 — email attachment monitor.
    var emailAttachmentMonitor: EmailAttachmentMonitor?

    /// Phase 6 — tamper protection for Nick's own files.
    var tamperProtection: TamperProtection?

    // MARK: - Private

    private static let logger = Logger(
        subsystem: "com.ehsanazish.nick.NickExtension",
        category: "EventHandler"
    )

    /// Offloads scanning and XPC delivery off the ES callback queue.
    let dispatchQueue = DispatchQueue(
        label: "com.ehsanazish.nick.NickExtension.eventhandler",
        qos: .userInitiated
    )

    private let encoder = JSONEncoder()

    // MARK: - Public Entry Point

    func handle(message: UnsafePointer<es_message_t>) {
        let msg = message.pointee

        // --- Extract process info synchronously (pointer only valid here) ---
        let process     = msg.process.pointee
        let processPath = esString(process.executable.pointee.path)
        let pid         = audit_token_to_pid(process.audit_token)
        let parentPid   = audit_token_to_pid(process.parent_audit_token)

        switch msg.event_type {

        // MARK: AUTH_EXEC — block known-bad binaries on execution

        case ES_EVENT_TYPE_AUTH_EXEC:
            let targetPath  = execTargetPath(from: msg)
            let csFlags     = msg.event.exec.target.pointee.codesigning_flags
            let isSigned    = (csFlags & 0x00000001) != 0   // CS_VALID

            // --- Phase 2: Signature / cache check ---
            let cached   = fileScanner?.cache.lookup(path: targetPath)
            var isThreat = cached?.isThreat ?? false

            // Background-scan if unseen (first-execution gap; Phase 4 ML partially closes this)
            if cached == nil {
                let path = targetPath
                dispatchQueue.async { [weak self] in _ = self?.fileScanner?.scan(filePath: path) }
            }

            // --- Phase 4: ML pre-execution prediction ---
            // Exempt /System/ and /usr/lib/ to avoid false-positives on Apple-signed binaries
            let isTrustedSystem = targetPath.hasPrefix("/System/") || targetPath.hasPrefix("/usr/lib/")
            if !isTrustedSystem, let ml = threatPredictor?.predict(filePath: targetPath) {
                if ml.classification == .malware                              { isThreat = true }
                if ml.classification == .suspicious && !isSigned              { isThreat = true }
            }

            // --- Phase 4: Behavioural analysis ---
            let behaviorResult = behaviorTracker?.analyze(pid: pid)
            if behaviorResult?.isMalicious == true { isThreat = true }

            // Record exec event in the tracker
            behaviorTracker?.record(
                pid: pid, processPath: processPath,
                eventType: .processExec, detail: targetPath
            )
            // Phase 6: record in process tree
            processTree?.recordExec(pid: pid, ppid: parentPid, path: targetPath, args: [])
            // Phase 6: watch for systemextensionsctl (tamper vector)
            tamperProtection?.handleExecEvent(execPath: targetPath, pid: pid)

            esClient?.respond(to: message, allow: !isThreat)

            // Also flag unsigned binaries from untrusted locations (warning, not block)
            let locationSuspect = !isSigned && (fileScanner?.isUntrustedLocation(targetPath) ?? false)

            pushEvent(ESEvent(
                eventType:    .authExec,
                processPath:  processPath,
                pid:          pid,
                parentPid:    parentPid,
                filePath:     targetPath,
                decision:     isThreat ? .deny : .allow,
                sha256:       cached?.hash,
                threatName:   cached?.threatName,
                threatFamily: cached?.threatFamily,
                isCodeSigned: isSigned || !locationSuspect ? isSigned : false
            ))

        // MARK: AUTH_OPEN — block opening of cached-threat files

        case ES_EVENT_TYPE_AUTH_OPEN:
            let filePath = esString(msg.event.open.file.pointee.path)
            let cached   = fileScanner?.cache.lookup(path: filePath)
            let isThreat = cached?.isThreat ?? false

            esClient?.respond(to: message, allow: !isThreat)

            pushEvent(ESEvent(
                eventType:    .authOpen,
                processPath:  processPath,
                pid:          pid,
                parentPid:    parentPid,
                filePath:     filePath,
                decision:     isThreat ? .deny : .allow,
                sha256:       cached?.hash,
                threatName:   cached?.threatName,
                threatFamily: cached?.threatFamily
            ))

        // MARK: AUTH_CREATE — heuristic-only (can't hash a file that doesn't exist yet)

        case ES_EVENT_TYPE_AUTH_CREATE:
            let filePath: String
            if msg.event.create.destination_type == ES_DESTINATION_TYPE_EXISTING_FILE {
                filePath = esString(msg.event.create.destination.existing_file.pointee.path)
            } else {
                let dir  = esString(msg.event.create.destination.new_path.dir.pointee.path)
                let name = esString(msg.event.create.destination.new_path.filename)
                filePath = dir + "/" + name
            }

            // Block only when BOTH the process AND the destination are suspicious.
            // Process-only check false-positives on legitimate installers from /tmp.
            let processSuspect = fileScanner?.isUntrustedLocation(processPath) ?? false
            let destSuspect    = fileScanner?.isUntrustedLocation(filePath) ?? false
            let isSuspicious   = processSuspect && destSuspect
            esClient?.respond(to: message, allow: !isSuspicious)

            pushEvent(ESEvent(
                eventType:    .authOpen,   // reuse open type; CREATE is filtered in UI
                processPath:  processPath,
                pid:          pid,
                parentPid:    parentPid,
                filePath:     filePath,
                decision:     isSuspicious ? .deny : .allow
            ))

        // MARK: AUTH_MMAP — block mapping of cached-threat files

        case ES_EVENT_TYPE_AUTH_MMAP:
            let filePath = esString(msg.event.mmap.source.pointee.path)
            let cached   = fileScanner?.cache.lookup(path: filePath)
            let isThreat = cached?.isThreat ?? false

            esClient?.respond(to: message, allow: !isThreat)

        // MARK: AUTH_COPYFILE — block copying of cached-threat files

        case ES_EVENT_TYPE_AUTH_COPYFILE:
            let srcPath  = esString(msg.event.copyfile.source.pointee.path)
            let cached   = fileScanner?.cache.lookup(path: srcPath)
            let isThreat = cached?.isThreat ?? false

            esClient?.respond(to: message, allow: !isThreat)

        // MARK: NOTIFY_CLOSE (modified) — scan modified files, run FIM, trigger remediation

        case ES_EVENT_TYPE_NOTIFY_CLOSE:
            guard msg.event.close.modified else { break }
            let filePath = esString(msg.event.close.target.pointee.path)

            dispatchQueue.async { [weak self] in
                guard let self else { return }

                // --- Phase 6: Email attachment detection ---
                if let emailEvent = self.emailAttachmentMonitor?.evaluate(filePath: filePath) {
                    Self.logger.info("Email attachment: \(emailEvent.source) — \(filePath)")
                    if emailEvent.isDangerousExtension {
                        // Treat dangerous email attachments like discovered threats
                        let threat = ESEvent(
                            eventType:    .notifyWrite,
                            processPath:  processPath,
                            pid:          pid,
                            parentPid:    parentPid,
                            filePath:     filePath,
                            decision:     .notApplicable,
                            threatName:   "Dangerous Email Attachment",
                            threatFamily: "EmailThreat"
                        )
                        self.pushEvent(threat)
                        if let data = try? self.encoder.encode(threat) {
                            self.xpcServer?.sendThreatToApp(data)
                        }
                    }
                }

                // --- File Integrity Monitoring ---
                if let violation = self.fileIntegrityMonitor?.check(path: filePath),
                   let data = try? JSONEncoder().encode(violation) {
                    self.xpcServer?.sendIntegrityViolationToApp(data)
                }

                // --- Threat Detection + Remediation ---
                guard let scanner = self.fileScanner else { return }
                let result = scanner.scan(filePath: filePath)
                guard result.isThreat else { return }
                let hash = result.hash

                // Report raw threat event
                let threat = ESEvent(
                    eventType:    .notifyWrite,
                    processPath:  processPath,
                    pid:          pid,
                    parentPid:    parentPid,
                    filePath:     filePath,
                    decision:     .notApplicable,
                    sha256:       hash,
                    threatName:   result.threatName,
                    threatFamily: result.threatFamily
                )
                self.pushEvent(threat)
                if let data = try? self.encoder.encode(threat) {
                    self.xpcServer?.sendThreatToApp(data)
                }
                // Phase 6: mark the writing process as a threat in the process tree
                self.processTree?.markAsThreat(pid: pid)
                if let engine = self.remediationEngine {
                    let report = engine.remediate(
                        threatPath:  filePath,
                        hash:        hash,
                        threatName:  result.threatName ?? "Unknown",
                        processPath: processPath,
                        pid:         pid
                    )
                    if let data = try? JSONEncoder().encode(report) {
                        self.xpcServer?.sendRemediationToApp(data)
                    }
                }
            }

        // MARK: NOTIFY_WRITE — log writes, run FIM + ransomware check

        case ES_EVENT_TYPE_NOTIFY_WRITE:
            let filePath = esString(msg.event.write.target.pointee.path)
            pushEvent(ESEvent(
                eventType:   .notifyWrite,
                processPath: processPath,
                pid:         pid,
                parentPid:   parentPid,
                filePath:    filePath,
                decision:    .notApplicable
            ))
            // Record in behavioral tracker (synchronous — NSLock, very fast)
            behaviorTracker?.record(
                pid: pid, processPath: processPath,
                eventType: .fileWrite, detail: filePath
            )
            // Async: FIM check + ransomware eval
            dispatchQueue.async { [weak self] in
                guard let self else { return }
                // FIM
                if let violation = self.fileIntegrityMonitor?.check(path: filePath),
                   let data = try? JSONEncoder().encode(violation) {
                    self.xpcServer?.sendIntegrityViolationToApp(data)
                }
                // Ransomware (read file data for entropy check)
                let fileData = FileManager.default.contents(atPath: filePath)
                if let alert = self.ransomwareDetector?.evaluate(
                    pid: pid, processPath: processPath,
                    filePath: filePath, fileData: fileData
                ) {
                    Self.logger.warning(
                        "Ransomware signal pid=\(pid) confidence=\(alert.confidence, format: .fixed(precision: 2)) action=\(String(describing: alert.recommendation))"
                    )
                    // If high-confidence, trigger remediation
                    if alert.recommendation == .block,
                       let engine = self.remediationEngine {
                        let report = engine.remediate(
                            threatPath:  filePath,
                            hash:        "",
                            threatName:  "Ransomware (\(alert.indicators.first ?? "unknown"))",
                            processPath: processPath,
                            pid:         pid
                        )
                        if let data = try? JSONEncoder().encode(report) {
                            self.xpcServer?.sendRemediationToApp(data)
                        }
                    }
                }
            }

        // MARK: NOTIFY_RENAME — invalidate cache; track rename for ransomware detection

        // MARK: AUTH_RENAME — block tampering with Nick's own files; track renames

        case ES_EVENT_TYPE_AUTH_RENAME:
            let srcPath = esString(msg.event.rename.source.pointee.path)
            let renameBlocked = tamperProtection?.shouldBlock(
                targetPath: srcPath, actorPath: processPath, actorPid: pid
            ) ?? false
            tamperProtection?.handleRenameEvent(srcPath: srcPath, actorPath: processPath, actorPid: pid)
            esClient?.respond(to: message, allow: !renameBlocked)
            // Fall-through side effects handled below regardless of auth decision
            fileScanner?.cache.invalidate(path: srcPath)
            let destPath: String
            if msg.event.rename.destination_type == ES_DESTINATION_TYPE_EXISTING_FILE {
                destPath = esString(msg.event.rename.destination.existing_file.pointee.path)
            } else {
                let dir  = esString(msg.event.rename.destination.new_path.dir.pointee.path)
                let name = esString(msg.event.rename.destination.new_path.filename)
                destPath = dir + "/" + name
            }
            behaviorTracker?.record(
                pid: pid, processPath: processPath,
                eventType: .fileRename, detail: destPath
            )
            // Phase 6: record in process tree
            processTree?.recordFileAccess(pid: pid, path: srcPath, operation: "rename")

        // MARK: NOTIFY_RENAME — (non-auth) cache invalidation only

        case ES_EVENT_TYPE_NOTIFY_RENAME:
            let notifySrcPath = esString(msg.event.rename.source.pointee.path)
            fileScanner?.cache.invalidate(path: notifySrcPath)
            let notifyDestPath: String
            if msg.event.rename.destination_type == ES_DESTINATION_TYPE_EXISTING_FILE {
                notifyDestPath = esString(msg.event.rename.destination.existing_file.pointee.path)
            } else {
                let dir  = esString(msg.event.rename.destination.new_path.dir.pointee.path)
                let name = esString(msg.event.rename.destination.new_path.filename)
                notifyDestPath = dir + "/" + name
            }
            behaviorTracker?.record(
                pid: pid, processPath: processPath,
                eventType: .fileRename, detail: notifyDestPath
            )
            processTree?.recordFileAccess(pid: pid, path: notifySrcPath, operation: "rename")

        // MARK: AUTH_UNLINK — block deletion of Nick's protected files

        case ES_EVENT_TYPE_AUTH_UNLINK:
            let unlinkTarget = esString(msg.event.unlink.target.pointee.path)
            let unlinkBlocked = tamperProtection?.shouldBlock(
                targetPath: unlinkTarget, actorPath: processPath, actorPid: pid
            ) ?? false
            tamperProtection?.handleUnlinkEvent(targetPath: unlinkTarget, actorPath: processPath, actorPid: pid)
            esClient?.respond(to: message, allow: !unlinkBlocked)
            if !unlinkBlocked {
                fileScanner?.cache.invalidate(path: unlinkTarget)
            }

        // MARK: NOTIFY_UNLINK — invalidate cache for deleted files

        case ES_EVENT_TYPE_NOTIFY_UNLINK:
            let filePath = esString(msg.event.unlink.target.pointee.path)
            fileScanner?.cache.invalidate(path: filePath)

        // MARK: NOTIFY_FORK / NOTIFY_EXIT — lifecycle logging

        case ES_EVENT_TYPE_NOTIFY_FORK:
            let childPid = audit_token_to_pid(msg.event.fork.child.pointee.audit_token)
            behaviorTracker?.recordFork(
                parentPid: pid, childPid: childPid, processPath: processPath
            )
            // Phase 6: record child exec in process tree
            processTree?.recordExec(pid: childPid, ppid: pid, path: processPath, args: [])
            pushEvent(ESEvent(
                eventType:   .notifyFork,
                processPath: processPath,
                pid:         pid,
                parentPid:   parentPid,
                decision:    .notApplicable
            ))

        case ES_EVENT_TYPE_NOTIFY_EXIT:
            // Clean up timeline to prevent unbounded memory growth
            behaviorTracker?.cleanupExited(pid: pid)
            // Phase 6: mark process exit in tree
            let exitCode: Int32 = 0  // exit code not provided by notify_exit in this binding
            processTree?.recordExit(pid: pid, exitCode: exitCode)
            pushEvent(ESEvent(
                eventType:   .notifyExit,
                processPath: processPath,
                pid:         pid,
                parentPid:   parentPid,
                decision:    .notApplicable
            ))

        // MARK: NOTIFY_MOUNT — Phase 5: scan external volumes

        case ES_EVENT_TYPE_NOTIFY_MOUNT:
            // Extract mount point from the statfs struct.
            // f_mntonname is a fixed-size C char array — read via pointer bytes.
            let mountPoint: String = withUnsafeBytes(of: msg.event.mount.statfs.pointee.f_mntonname) { ptr in
                String(cString: ptr.baseAddress!.assumingMemoryBound(to: CChar.self))
            }
            usbScanner?.handleMount(volumePath: mountPoint)

        // MARK: NOTIFY_TCC_MODIFY — Phase 5: privacy permission changes (macOS 15.4+)

        case ES_EVENT_TYPE_NOTIFY_TCC_MODIFY:
            let tcc         = msg.event.tcc_modify.pointee
            let service     = esString(tcc.service)
            let identity    = esString(tcc.identity)
            // identity_type tells us whether identity is a bundle ID or executable path
            let appBundleID = tcc.identity_type == ES_TCC_IDENTITY_TYPE_BUNDLE_ID ? identity : ""
            let appPath     = tcc.identity_type == ES_TCC_IDENTITY_TYPE_EXECUTABLE_PATH ? identity : ""
            let isGranted   = (tcc.right == ES_TCC_AUTHORIZATION_RIGHT_ALLOWED)

            if let alert = privacyGuard?.handleTCCChange(
                service:       service,
                appBundleID:   appBundleID,
                appPath:       appPath,
                accessGranted: isGranted
            ), let data = try? JSONEncoder().encode(alert) {
                xpcServer?.sendPrivacyAlertToApp(data)
            }

        default:
            // For any unhandled AUTH event, allow immediately.
            if msg.action_type == ES_ACTION_TYPE_AUTH {
                esClient?.respond(to: message, allow: true)
            }
        }
    }

    // MARK: - Private Helpers

    /// Encodes and pushes an `ESEvent` to the container app via XPC.
    /// Called from the ES callback queue; encoding is fast (small struct).
    private func pushEvent(_ event: ESEvent) {
        dispatchQueue.async { [weak self] in
            guard let self, let data = try? self.encoder.encode(event) else { return }
            self.xpcServer?.sendEventToApp(data)
        }
    }

    /// Extracts the exec target path from `AUTH_EXEC`.
    private func execTargetPath(from msg: es_message_t) -> String {
        return esString(msg.event.exec.target.pointee.executable.pointee.path)
    }

    /// Safely converts an `es_string_token_t` to a Swift `String`.
    private func esString(_ token: es_string_token_t) -> String {
        guard let ptr = token.data, token.length > 0 else { return "<unknown>" }
        return String(cString: ptr)
    }
}
