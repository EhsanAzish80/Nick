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
    var updateLeaseManager: NickUpdateLeaseManager?

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
        var msg = message.pointee

        // --- Extract process info synchronously (pointer only valid here) ---
        let process     = msg.process.pointee
        let processPath = esString(process.executable.pointee.path)
        let pid         = audit_token_to_pid(process.audit_token)
        let parentPid   = audit_token_to_pid(process.parent_audit_token)
        let processIdentity = ProcessInstanceIdentity.capture(pid: pid)
        let tamperActorIdentity = TamperActorIdentity(
            teamID: esOptionalString(process.team_id),
            signingID: esOptionalString(process.signing_id),
            codesigningFlags: process.codesigning_flags,
            isPlatformBinary: process.is_platform_binary
        )

        switch msg.event_type {

        // MARK: AUTH_EXEC — block known-bad binaries on execution

        case ES_EVENT_TYPE_AUTH_EXEC:
            let target      = msg.event.exec.target.pointee
            let targetPath  = esString(target.executable.pointee.path)
            let targetIdentity = FileIdentity(stat: target.executable.pointee.stat)
            let targetTeamID = esOptionalString(target.team_id)
            let targetSigningID = esOptionalString(target.signing_id)
            let execArguments: [String] = withUnsafePointer(to: &msg.event.exec) { event in
                (0..<es_exec_arg_count(event)).map { esString(es_exec_arg(event, $0)) }
            }
            // CS_VALID alone is not identity: every arm64 binary is at least
            // ad-hoc signed. Only platform binaries and Team-ID signatures
            // count as a trusted signer.
            let trustedSigner = ExecutionTrustPolicy.hasTrustedSigner(
                codesigningFlags: target.codesigning_flags,
                isPlatformBinary: target.is_platform_binary,
                teamID: esOptionalString(target.team_id)
            )

            // AUTH callbacks have a strict deadline. Only consult the in-memory
            // cache before responding; hashing, behavioural analysis and XPC
            // delivery must never hold up process launch.
            let cached   = fileScanner?.cache.lookup(path: targetPath, identity: targetIdentity)
            let explicitlyAllowed = fileScanner?.cache.consumeOneTimeAllowance(
                path: targetPath,
                identity: targetIdentity,
                currentHash: { fileScanner?.contentHash(path: targetPath) }
            ) ?? false
            let shouldBlock = !explicitlyAllowed && (cached?.mayBlock ?? false)

            // First launch of an unknown, non-identity-signed binary: hash it
            // against the curated database before answering, within a bounded
            // share of the ES deadline, so a known sample is blocked on its
            // first run instead of only on the second. Fails open on timeout.
            let hashBeforeLaunch = cached == nil
                && !explicitlyAllowed
                && !trustedSigner
                && !ExecutionTrustPolicy.isSealedSystemPath(targetPath)
                && targetIdentity.size <= Self.preLaunchHashLimit
                && fileScanner?.hasSignatures == true

            // Observation work runs after the AUTH response with value types only.
            let observe: (Bool, ScanCache.Entry?) -> Void = { [weak self] blocked, verdict in
                self?.dispatchQueue.async { [weak self] in
                    self?.observeExec(
                        targetPath: targetPath,
                        processPath: processPath,
                        pid: pid,
                        parentPid: parentPid,
                        trustedSigner: trustedSigner,
                        scanFirst: verdict == nil,
                        blocked: blocked,
                        verdict: verdict,
                        teamID: targetTeamID,
                        signingID: targetSigningID,
                        arguments: execArguments
                    )
                }
            }

            if hashBeforeLaunch, let scanner = fileScanner {
                respondAfterPreLaunchHash(
                    message: message,
                    path: targetPath,
                    identity: targetIdentity,
                    scanner: scanner,
                    completion: observe
                )
            } else {
                esClient?.respond(to: message, allow: !shouldBlock)
                observe(shouldBlock, cached)
            }

        // MARK: AUTH_OPEN — block opening of cached-threat files

        case ES_EVENT_TYPE_AUTH_OPEN:
            let filePath = esString(msg.event.open.file.pointee.path)
            let isWriteOpen = msg.event.open.fflag & (FWRITE | O_TRUNC | O_APPEND) != 0
            let isProtectedWrite = isWriteOpen && tamperProtection?.protects(path: filePath) == true
            if isProtectedWrite {
                var writeBlocked = tamperProtection?.shouldBlockWrite(
                   targetPath: filePath,
                   identity: tamperActorIdentity,
                   nickIdentityValidated: validatedNickTamperActor(
                       auditToken: process.audit_token,
                       identity: tamperActorIdentity
                   )
                ) ?? false
                let leaseAllowed = leasedUpdateAuthorization(
                    targetPath: filePath,
                    operation: .write,
                    process: process,
                    processPath: processPath,
                    identity: tamperActorIdentity
                )
                writeBlocked = writeBlocked && !leaseAllowed
                tamperProtection?.handleWriteEvent(
                    targetPath: filePath,
                    actorPath: processPath,
                    actorPid: pid,
                    identity: tamperActorIdentity,
                    blocked: writeBlocked
                )
                if writeBlocked {
                    esClient?.respond(to: message, allow: false)
                    break
                }
            }
            let fileIdentity = FileIdentity(stat: msg.event.open.file.pointee.stat)
            let cached   = fileScanner?.cache.lookup(
                path: filePath,
                identity: fileIdentity
            )
            let explicitlyAllowed = fileScanner?.cache.consumeOneTimeAllowance(
                path: filePath,
                identity: fileIdentity,
                currentHash: { fileScanner?.contentHash(path: filePath) }
            ) ?? false
            let shouldBlock = !explicitlyAllowed && (cached?.mayBlock ?? false)

            esClient?.respond(to: message, allow: !shouldBlock)

            // Normal file opens are extremely high-volume and add no useful
            // user-facing information. Forward only an actual blocked threat.
            if shouldBlock {
                pushEvent(ESEvent(
                    eventType:   .authOpen,
                    processPath: processPath,
                    pid:         pid,
                    parentPid:   parentPid,
                    filePath:    filePath,
                    decision:    .deny,
                    threat:      ESEvent.ThreatContext(
                        sha256:       cached?.hash,
                        threatName:   cached?.threatName,
                        threatFamily: cached?.threatFamily
                    )
                ))
            }

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

            let createBlocked: Bool
            if tamperProtection?.protects(path: filePath) == true {
                let ordinarilyBlocked = tamperProtection?.shouldBlockWrite(
                    targetPath: filePath,
                    identity: tamperActorIdentity,
                    nickIdentityValidated: validatedNickTamperActor(
                        auditToken: process.audit_token,
                        identity: tamperActorIdentity
                    )
                ) ?? false
                let leaseAllowed = leasedUpdateAuthorization(
                    targetPath: filePath,
                    operation: .write,
                    process: process,
                    processPath: processPath,
                    identity: tamperActorIdentity
                )
                createBlocked = ordinarilyBlocked && !leaseAllowed
            } else {
                createBlocked = false
            }
            if createBlocked {
                esClient?.respond(to: message, allow: false)
                tamperProtection?.handleWriteEvent(
                    targetPath: filePath,
                    actorPath: processPath,
                    actorPid: pid,
                    identity: tamperActorIdentity,
                    blocked: true
                )
                break
            }
            if tamperProtection?.protects(path: filePath) == true {
                tamperProtection?.handleWriteEvent(
                    targetPath: filePath,
                    actorPath: processPath,
                    actorPid: pid,
                    identity: tamperActorIdentity,
                    blocked: false
                )
            }

            // This is heuristic-only: there is no file to hash yet. Observe and
            // report suspicious creates, but fail open so AirDrop, Handoff,
            // installers and developer builds cannot be disrupted.
            let processSuspect = fileScanner?.isUntrustedLocation(processPath) ?? false
            let destSuspect    = fileScanner?.isUntrustedLocation(filePath) ?? false
            let isSuspicious   = processSuspect && destSuspect
            esClient?.respond(to: message, allow: true)

            if isSuspicious {
                guard !isTrustedPlatformActor(processPath) else { break }
                pushEvent(ESEvent(
                    eventType:    .authOpen,   // reuse open type; CREATE is filtered in UI
                    processPath:  processPath,
                    pid:          pid,
                    parentPid:    parentPid,
                    filePath:     filePath,
                    decision:     .allow
                ))
            }

        // MARK: AUTH_TRUNCATE / AUTH_LINK / AUTH_CLONE — protect Nick bundle contents

        case ES_EVENT_TYPE_AUTH_TRUNCATE:
            handleProtectedWriteAuthorization(
                message: message,
                targetPath: esString(msg.event.truncate.target.pointee.path),
                process: process,
                processPath: processPath,
                pid: pid,
                identity: tamperActorIdentity
            )

        case ES_EVENT_TYPE_AUTH_LINK:
            handleProtectedWriteAuthorization(
                message: message,
                targetPath: esString(msg.event.link.target_dir.pointee.path)
                    + "/" + esString(msg.event.link.target_filename),
                process: process,
                processPath: processPath,
                pid: pid,
                identity: tamperActorIdentity
            )

        case ES_EVENT_TYPE_AUTH_CLONE:
            handleProtectedWriteAuthorization(
                message: message,
                targetPath: esString(msg.event.clone.target_dir.pointee.path)
                    + "/" + esString(msg.event.clone.target_name),
                process: process,
                processPath: processPath,
                pid: pid,
                identity: tamperActorIdentity
            )

        // MARK: AUTH_MMAP — block mapping of cached-threat files

        case ES_EVENT_TYPE_AUTH_MMAP:
            let filePath = esString(msg.event.mmap.source.pointee.path)
            let cached   = fileScanner?.cache.lookup(
                path: filePath,
                identity: FileIdentity(stat: msg.event.mmap.source.pointee.stat)
            )
            let shouldBlock = cached?.mayBlock ?? false

            esClient?.respond(to: message, allow: !shouldBlock)

        // MARK: AUTH_COPYFILE — block copying of cached-threat files

        case ES_EVENT_TYPE_AUTH_COPYFILE:
            let srcPath  = esString(msg.event.copyfile.source.pointee.path)
            let copyDestination = esString(msg.event.copyfile.target_dir.pointee.path)
                + "/" + esString(msg.event.copyfile.target_name)
            if tamperProtection?.protects(path: copyDestination) == true {
                handleProtectedWriteAuthorization(
                    message: message,
                    targetPath: copyDestination,
                    process: process,
                    processPath: processPath,
                    pid: pid,
                    identity: tamperActorIdentity
                )
                break
            }
            let cached   = fileScanner?.cache.lookup(
                path: srcPath,
                identity: FileIdentity(stat: msg.event.copyfile.source.pointee.stat)
            )
            let shouldBlock = cached?.mayBlock ?? false

            esClient?.respond(to: message, allow: !shouldBlock)

        // MARK: NOTIFY_CLOSE (modified) — scan modified files, run FIM, trigger remediation

        case ES_EVENT_TYPE_NOTIFY_CLOSE:
            guard msg.event.close.modified else { break }
            let filePath = esString(msg.event.close.target.pointee.path)
            // The content changed: any cached verdict describes the old bytes.
            fileScanner?.cache.invalidate(path: filePath)
            let actorIsPlatformBinary = process.is_platform_binary
            let actorHasTrustedSigner = self.actorHasTrustedSigner(process)

            dispatchQueue.async { [weak self] in
                guard let self else { return }

                // One event per completed modification replaces the former
                // per-write XPC stream, which could deliver thousands of main
                // actor updates for database journals and logs.
                self.behaviorTracker?.record(
                    pid: pid, processPath: processPath,
                    eventType: .fileWrite, detail: filePath
                )
                let isTrustedBuildOutput = self.isTrustedDeveloperBuild(
                    actorPath: processPath,
                    actorIsPlatformBinary: actorIsPlatformBinary,
                    filePath: filePath
                )

                // --- Phase 6: Email attachment detection ---
                let emailEvent = self.emailAttachmentMonitor?.evaluate(filePath: filePath)
                if let emailEvent {
                    Self.logger.info("Email attachment: \(emailEvent.source, privacy: .public) — \(filePath, privacy: .private)")
                    if emailEvent.isDangerousExtension {
                        // A risky attachment type is a reason to scan, not a
                        // verdict. Colleagues mail installers and scripts, and
                        // Mail rewrites attachments on every mailbox resync,
                        // so the type alone is recorded as an observation and
                        // only scan evidence produces a threat.
                        self.pushEvent(ESEvent(
                            eventType:   .notifyWrite,
                            processPath: processPath,
                            pid:         pid,
                            parentPid:   parentPid,
                            filePath:    filePath,
                            decision:    .notApplicable
                        ))
                        if !self.shouldDeepScanModifiedFile(at: filePath),
                           let result = self.fileScanner?.scan(filePath: filePath),
                           result.isThreat {
                            let threat = ESEvent(
                                eventType:   .notifyWrite,
                                processPath: processPath,
                                pid:         pid,
                                parentPid:   parentPid,
                                filePath:    filePath,
                                decision:    .notApplicable,
                                threat:      ESEvent.ThreatContext(
                                    sha256:       result.hash,
                                    threatName:   result.threatName ?? "Malicious Email Attachment",
                                    threatFamily: result.threatFamily ?? "EmailThreat"
                                )
                            )
                            self.pushEvent(threat)
                            if let data = try? self.encoder.encode(threat) {
                                self.xpcServer?.sendThreatToApp(data)
                            }
                        }
                    }
                }

                // --- File Integrity Monitoring ---
                self.reportIntegrityViolation(at: filePath)

                // Ransomware heuristics run once at close and read at most a
                // small prefix. Canary names and known extensions do not need
                // the file contents; entropy is only a supporting signal.
                let ransomwareSample: Data?
                if !isTrustedBuildOutput,
                   self.ransomwareDetector?.needsContentSample(filePath: filePath) == true {
                    ransomwareSample = self.boundedFileSample(
                        at: filePath,
                        maximumBytes: 1_048_576
                    )
                } else {
                    ransomwareSample = nil
                }
                if !isTrustedBuildOutput,
                   let alert = self.ransomwareDetector?.evaluate(
                    pid: pid,
                    processPath: processPath,
                    filePath: filePath,
                    fileData: ransomwareSample,
                    actorIsPlatformBinary: actorIsPlatformBinary,
                    actorHasTrustedSigner: actorHasTrustedSigner
                ) {
                    self.reportRansomware(
                        alert,
                        pid: pid,
                        parentPid: parentPid,
                        processPath: processPath,
                        filePath: filePath,
                        processIdentity: processIdentity
                    )
                }

                // --- Threat Detection + Remediation ---
                guard self.shouldDeepScanModifiedFile(at: filePath) else { return }
                // Xcode/SwiftPM build products are rewritten constantly and
                // legitimately contain linker/install/persistence strings that
                // generic YARA rules match. Apple developer tools remain covered
                // by exact hash intelligence, but heuristic scanning here only
                // creates noise and previously broke builds.
                if isTrustedBuildOutput {
                    return
                }
                self.pushEvent(ESEvent(
                    eventType: .notifyWrite,
                    processPath: processPath,
                    pid: pid,
                    parentPid: parentPid,
                    filePath: filePath,
                    decision: .notApplicable
                ))

                guard let scanner = self.fileScanner else { return }
                let result = scanner.scan(filePath: filePath)
                guard result.isThreat else { return }
                let hash = result.hash

                // Report raw threat event
                let threat = ESEvent(
                    eventType:   .notifyWrite,
                    processPath: processPath,
                    pid:         pid,
                    parentPid:   parentPid,
                    filePath:    filePath,
                    decision:    .notApplicable,
                    threat:      ESEvent.ThreatContext(
                        sha256:       hash,
                        threatName:   result.threatName,
                        threatFamily: result.threatFamily
                    )
                )
                self.pushEvent(threat)
                if let data = try? self.encoder.encode(threat) {
                    self.xpcServer?.sendThreatToApp(data)
                }
                // Phase 6: mark the writing process as a threat in the process tree
                self.processTree?.markAsThreat(pid: pid)
                // Heuristic/YARA matches are user-review findings. Automated
                // kill/quarantine is reserved for exact curated hash evidence.
                if result.mayBlock, let engine = self.remediationEngine {
                    let report = engine.remediate(
                        threatPath:  filePath,
                        hash:        hash,
                        threatName:  result.threatName ?? "Unknown",
                        processPath: processPath,
                        pid:         pid,
                        processIdentity: processIdentity,
                        // Mail and Outlook are delivery processes, not the
                        // malware itself. Quarantine the confirmed attachment
                        // without terminating the user's mail client.
                        terminateProcess: emailEvent == nil
                    )
                    if let data = try? JSONEncoder().encode(report) {
                        self.xpcServer?.sendRemediationToApp(data)
                    }
                }
            }

        // MARK: NOTIFY_RENAME — invalidate cache; track rename for ransomware detection

        // MARK: AUTH_RENAME — block tampering with Nick's own files; track renames

        case ES_EVENT_TYPE_AUTH_RENAME:
            let srcPath = esString(msg.event.rename.source.pointee.path)
            let destinationPath: String
            if msg.event.rename.destination_type == ES_DESTINATION_TYPE_EXISTING_FILE {
                destinationPath = esString(msg.event.rename.destination.existing_file.pointee.path)
            } else {
                let directory = esString(msg.event.rename.destination.new_path.dir.pointee.path)
                destinationPath = directory + "/" + esString(msg.event.rename.destination.new_path.filename)
            }
            let protectsRename = tamperProtection?.protects(path: srcPath) == true
                || tamperProtection?.protects(path: destinationPath) == true
            let consoleUser = protectsRename ? TamperConsoleUserResolver.current() : nil
            let renameBlocked: Bool
            if protectsRename {
                let ordinarilyBlocked = tamperProtection?.shouldBlockRename(
                    sourcePath: srcPath,
                    destinationPath: destinationPath,
                    identity: tamperActorIdentity,
                    nickIdentityValidated: validatedNickTamperActor(
                        auditToken: process.audit_token,
                        identity: tamperActorIdentity
                    ),
                    consoleUser: consoleUser
                ) ?? false
                let leaseAllowed = leasedUpdateAuthorization(
                    targetPath: destinationPath,
                    sourcePath: srcPath,
                    operation: .rename,
                    process: process,
                    processPath: processPath,
                    identity: tamperActorIdentity
                )
                renameBlocked = ordinarilyBlocked && !leaseAllowed
            } else {
                renameBlocked = false
            }
            esClient?.respond(to: message, allow: !renameBlocked)
            tamperProtection?.handleRenameEvent(
                srcPath: srcPath,
                destinationPath: destinationPath,
                actorPath: processPath,
                actorPid: pid,
                identity: tamperActorIdentity,
                blocked: renameBlocked,
                consoleUser: consoleUser
            )
            // Behaviour is recorded from NOTIFY_RENAME, which reflects only
            // renames that actually happened (recording both double-counted).
            fileScanner?.cache.invalidate(path: srcPath)

        // MARK: NOTIFY_RENAME — cache invalidation, behaviour, ransomware

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
            fileScanner?.cache.invalidate(path: notifyDestPath)
            let renameActorIsPlatform = process.is_platform_binary
            let renameActorTrusted = actorHasTrustedSigner(process)
            let renameTeamID = esOptionalString(process.team_id)
            let renameSigningID = esOptionalString(process.signing_id)
            dispatchQueue.async { [weak self] in
                guard let self else { return }
                self.reportIntegrityViolation(at: notifySrcPath)
                self.reportIntegrityViolation(at: notifyDestPath)
                self.behaviorTracker?.recordRename(
                    pid: pid, processPath: processPath,
                    source: notifySrcPath, destination: notifyDestPath
                )
                self.processTree?.recordFileAccess(pid: pid, path: notifySrcPath, operation: "rename")
                let browserIdentityCandidate = BrowserDownloadRenamePolicy.shouldIgnoreDestination(
                    destination: notifyDestPath,
                    developerIDValidated: true,
                    teamID: renameTeamID,
                    signingID: renameSigningID
                )
                let validatedBrowserDownload = browserIdentityCandidate
                    && DeveloperIDTrustValidator.shared.isValidated(path: processPath)
                if let alert = self.ransomwareDetector?.evaluateRename(
                    pid: pid,
                    processPath: processPath,
                    source: notifySrcPath,
                    destination: notifyDestPath,
                    actorIsPlatformBinary: renameActorIsPlatform,
                    actorHasTrustedSigner: renameActorTrusted,
                    ignoreBrowserDownloadDestination: validatedBrowserDownload
                ) {
                    self.reportRansomware(
                        alert,
                        pid: pid,
                        parentPid: parentPid,
                        processPath: processPath,
                        filePath: notifyDestPath,
                        processIdentity: processIdentity,
                        actorIsPlatformBinary: renameActorIsPlatform,
                        teamID: renameTeamID,
                        signingID: renameSigningID
                    )
                }
            }

        // MARK: AUTH_UNLINK — block deletion of Nick's protected files

        case ES_EVENT_TYPE_AUTH_UNLINK:
            let unlinkTarget = esString(msg.event.unlink.target.pointee.path)
            let unlinkBlocked: Bool
            if tamperProtection?.protects(path: unlinkTarget) == true {
                let ordinarilyBlocked = tamperProtection?.shouldBlockUnlink(
                    targetPath: unlinkTarget,
                    identity: tamperActorIdentity,
                    nickIdentityValidated: validatedNickTamperActor(
                        auditToken: process.audit_token,
                        identity: tamperActorIdentity
                    )
                ) ?? false
                let leaseAllowed = leasedUpdateAuthorization(
                    targetPath: unlinkTarget,
                    operation: .unlink,
                    process: process,
                    processPath: processPath,
                    identity: tamperActorIdentity
                )
                unlinkBlocked = ordinarilyBlocked && !leaseAllowed
            } else {
                unlinkBlocked = false
            }
            esClient?.respond(to: message, allow: !unlinkBlocked)
            tamperProtection?.handleUnlinkEvent(
                targetPath: unlinkTarget,
                actorPath: processPath,
                actorPid: pid,
                identity: tamperActorIdentity,
                blocked: unlinkBlocked
            )
            if !unlinkBlocked {
                fileScanner?.cache.invalidate(path: unlinkTarget)
            }

        // MARK: NOTIFY_UNLINK — invalidate cache for deleted files

        case ES_EVENT_TYPE_NOTIFY_UNLINK:
            let filePath = esString(msg.event.unlink.target.pointee.path)
            fileScanner?.cache.invalidate(path: filePath)
            dispatchQueue.async { [weak self] in
                self?.reportIntegrityViolation(at: filePath)
            }
            // Encrypt-to-new-file ransomware deletes the originals, including
            // a canary it never modified in place.
            if ransomwareDetector?.canaryManager.isCanary(path: filePath) == true,
               !process.is_platform_binary {
                let unlinkActorTrusted = actorHasTrustedSigner(process)
                dispatchQueue.async { [weak self] in
                    guard let self,
                          let alert = self.ransomwareDetector?.evaluate(
                            pid: pid,
                            processPath: processPath,
                            filePath: filePath,
                            fileData: nil,
                            actorHasTrustedSigner: unlinkActorTrusted
                          ) else { return }
                    self.reportRansomware(
                        alert,
                        pid: pid,
                        parentPid: parentPid,
                        processPath: processPath,
                        filePath: filePath,
                        processIdentity: processIdentity
                    )
                }
            }

        // MARK: NOTIFY_FORK / NOTIFY_EXIT — lifecycle logging

        case ES_EVENT_TYPE_NOTIFY_FORK:
            let childPid = audit_token_to_pid(msg.event.fork.child.pointee.audit_token)
            behaviorTracker?.recordFork(
                parentPid: pid, childPid: childPid, processPath: processPath
            )
            // Phase 6: record child exec in process tree
            processTree?.recordExec(pid: childPid, ppid: pid, path: processPath, args: [])
            // Keep lifecycle data inside the extension. Forwarding every fork
            // invalidates the app's observable timeline at system-wide rates.

        case ES_EVENT_TYPE_NOTIFY_EXIT:
            // Clean up timeline to prevent unbounded memory growth
            behaviorTracker?.cleanupExited(pid: pid)
            // Phase 6: mark process exit in tree
            let exitCode: Int32 = 0  // exit code not provided by notify_exit in this binding
            processTree?.recordExit(pid: pid, exitCode: exitCode)
            // Exits reclaim the behavioural timeline; they are not alerts.

        // MARK: NOTIFY_MOUNT — Phase 5: scan external volumes

        case ES_EVENT_TYPE_NOTIFY_MOUNT:
            // Extract mount point from the statfs struct.
            // f_mntonname is a fixed-size C char array — read via pointer bytes.
            let mountPoint: String = withUnsafeBytes(of: msg.event.mount.statfs.pointee.f_mntonname) { ptr in
                String(cString: ptr.baseAddress!.assumingMemoryBound(to: CChar.self))
            }
            usbScanner?.handleMount(volumePath: mountPoint)

        case ES_EVENT_TYPE_NOTIFY_UNMOUNT:
            let mountPoint: String = withUnsafeBytes(of: msg.event.unmount.statfs.pointee.f_mntonname) { ptr in
                String(cString: ptr.baseAddress!.assumingMemoryBound(to: CChar.self))
            }
            usbScanner?.handleUnmount(volumePath: mountPoint)

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

    private let ransomwareReportLock = NSLock()
    private var lastRansomwareReport: [Int32: (date: Date, blocked: Bool)] = [:]

    // MARK: - Exec helpers

    /// Largest image hashed before a first launch is answered.
    static let preLaunchHashLimit: Int64 = 32 * 1_024 * 1_024

    private let preLaunchQueue = DispatchQueue(
        label: "com.ehsanazish.nick.NickExtension.prelaunch",
        qos: .userInteractive,
        attributes: .concurrent
    )

    /// Keeps an ES message alive across queues until it is answered.
    private final class RetainedMessage: @unchecked Sendable {
        let pointer: UnsafePointer<es_message_t>
        private let lock = NSLock()
        private var answered = false

        init(_ pointer: UnsafePointer<es_message_t>) {
            self.pointer = pointer
            es_retain_message(pointer)
        }

        deinit { es_release_message(pointer) }

        /// Returns `true` exactly once.
        func claimResponse() -> Bool {
            lock.withLock {
                guard !answered else { return false }
                answered = true
                return true
            }
        }
    }

    /// Answers AUTH_EXEC after a curated-hash lookup, or allows it when the
    /// lookup would use more than half of the remaining ES deadline (capped at
    /// two seconds). The watchdog guarantees the deadline is never missed.
    private func respondAfterPreLaunchHash(
        message: UnsafePointer<es_message_t>,
        path: String,
        identity: FileIdentity,
        scanner: FileScanner,
        completion: @escaping (Bool, ScanCache.Entry?) -> Void
    ) {
        let retained = RetainedMessage(message)
        let startedAt = DispatchTime.now().uptimeNanoseconds
        let budgetNanoseconds = Self.preLaunchBudgetNanoseconds(deadline: message.pointee.deadline)
        guard budgetNanoseconds > 50_000_000 else {
            _ = retained.claimResponse()
            esClient?.respond(to: message, allow: true)
            completion(false, nil)
            return
        }

        preLaunchQueue.asyncAfter(deadline: .now() + .nanoseconds(Int(budgetNanoseconds))) { [weak self] in
            guard retained.claimResponse() else { return }
            let elapsed = DispatchTime.now().uptimeNanoseconds - startedAt
            Self.logger.info("Pre-launch hash exceeded budget after \(elapsed / 1_000_000) ms; allowing \(path, privacy: .private)")
            self?.esClient?.respond(to: retained.pointer, allow: true)
            completion(false, nil)
        }

        preLaunchQueue.async { [weak self] in
            let match = scanner.preLaunchHashMatch(path: path, identity: identity)
            guard retained.claimResponse() else { return }
            let elapsed = DispatchTime.now().uptimeNanoseconds - startedAt
            Self.logger.debug("Pre-launch exact-hash lookup completed in \(elapsed / 1_000_000) ms")
            self?.esClient?.respond(to: retained.pointer, allow: match == nil)
            if let match {
                Self.logger.notice("Blocked first launch of known threat \(match.name, privacy: .public): \(path, privacy: .private)")
            }
            completion(match != nil, scanner.cache.lookup(path: path, identity: identity))
        }
    }

    /// Converts the ES deadline (mach absolute time) into the time this
    /// handler may spend before answering.
    private static func preLaunchBudgetNanoseconds(deadline: UInt64) -> UInt64 {
        var timebase = mach_timebase_info_data_t()
        mach_timebase_info(&timebase)
        let now = mach_absolute_time()
        guard deadline > now, timebase.denom != 0 else { return 0 }
        let remainingNanoseconds = (deadline - now).multipliedReportingOverflow(by: UInt64(timebase.numer))
        guard !remainingNanoseconds.overflow else { return 2_000_000_000 }
        return min(remainingNanoseconds.partialValue / UInt64(timebase.denom) / 2, 2_000_000_000)
    }

    /// Everything that happens after an exec was answered.
    private func observeExec(
        targetPath: String,
        processPath: String,
        pid: Int32,
        parentPid: Int32,
        trustedSigner: Bool,
        scanFirst: Bool,
        blocked: Bool,
        verdict: ScanCache.Entry?,
        teamID: String?,
        signingID: String?,
        arguments: [String]
    ) {
        var verdict = verdict
        // Skip the content scan only for identity-signed code outside
        // staging/persistence locations. Ad-hoc and unsigned images, and
        // anything run from a high-risk location, are scanned.
        if scanFirst,
           ExecutionTrustPolicy.shouldScanOnExec(path: targetPath, hasTrustedSigner: trustedSigner) {
            _ = fileScanner?.scan(filePath: targetPath)
            verdict = verdict ?? fileScanner?.cache.lookup(path: targetPath)
        }

        behaviorTracker?.record(
            pid: pid, processPath: processPath,
            eventType: .processExec, detail: targetPath
        )
        processTree?.recordExec(pid: pid, ppid: parentPid, path: targetPath, args: [])
        tamperProtection?.handleExecEvent(execPath: targetPath, pid: pid, args: arguments)

        pushEvent(ESEvent(
            eventType:   .authExec,
            processPath: processPath,
            pid:         pid,
            parentPid:   parentPid,
            filePath:    targetPath,
            decision:    blocked ? .deny : .allow,
            threat:      ESEvent.ThreatContext(
                sha256:       verdict?.hash,
                threatName:   verdict?.threatName,
                threatFamily: verdict?.threatFamily,
                isCodeSigned: trustedSigner,
                teamID: teamID,
                signingID: signingID
            )
        ))
    }

    // MARK: - Private Helpers

    private func reportIntegrityViolation(at path: String) {
        guard let violation = fileIntegrityMonitor?.check(path: path),
              let data = try? encoder.encode(violation) else { return }
        xpcServer?.sendIntegrityViolationToApp(data)
    }

    /// Reports a ransomware alert and, when the evidence allows it, stops the
    /// writer. Must run on `dispatchQueue`.
    private func reportRansomware(
        _ alert: RansomwareDetector.RansomwareAlert,
        pid: Int32,
        parentPid: Int32,
        processPath: String,
        filePath: String,
        processIdentity: ProcessInstanceIdentity?,
        actorIsPlatformBinary: Bool = false,
        teamID: String? = nil,
        signingID: String? = nil
    ) {
        // One burst produces an event for every file it touches. Report a
        // process once per minute unless the evidence escalates to a block.
        let isBlock = alert.recommendation == .block
        let developerIDValidated = DeveloperIDTrustValidator.shared.isValidated(path: processPath)
        let repositoryRoot = Self.approvedDevelopmentRepositoryRoot(
            containing: filePath,
            approvedRoots: xpcServer?.approvedDevelopmentRoots() ?? []
        )
        let developmentBuild = DevelopmentBuildRansomwarePolicy.isAlertOnly(
            processPath: processPath,
            destination: filePath,
            repositoryRoot: repositoryRoot,
            actorValidated: actorIsPlatformBinary || developerIDValidated
        )
        let shouldTerminate = RansomwareTerminationPolicy.shouldTerminate(
            isBlockRecommendation: isBlock,
            developerIDValidated: developerIDValidated,
            isApprovedDevelopmentBuild: developmentBuild
        )
        let shouldReport = ransomwareReportLock.withLock { () -> Bool in
            let now = Date()
            if let previous = lastRansomwareReport[pid],
               now.timeIntervalSince(previous.date) < 60,
               previous.blocked || !shouldTerminate {
                return false
            }
            lastRansomwareReport[pid] = (now, shouldTerminate)
            if lastRansomwareReport.count > 256 {
                lastRansomwareReport = lastRansomwareReport.filter { now.timeIntervalSince($0.value.date) < 60 }
            }
            return true
        }
        guard shouldReport else { return }

        Self.logger.warning(
            "Ransomware signal pid=\(pid) confidence=\(alert.confidence, format: .fixed(precision: 2)) terminate=\(shouldTerminate)"
        )
        var ransomwareMetadata: [String: String] = [
            "detectionKind": "ransomware-behavior",
            "actorValidation": developerIDValidated ? "developer-id" : "unvalidated",
            "response": shouldTerminate ? "terminated" : "alert-only",
            "indicators": alert.indicators.joined(separator: "; ")
        ]
        if developmentBuild { ransomwareMetadata["developmentContext"] = "repository-build" }
        if let burst = alert.renameBurst {
            ransomwareMetadata["renameExtension"] = burst.newExtension
            ransomwareMetadata["renameFileCount"] = String(burst.fileCount)
            ransomwareMetadata["renameDirectoryCount"] = String(burst.directoryCount)
            ransomwareMetadata["renameWindowSeconds"] = String(burst.windowSeconds)
        }
        let ransomwareEvent = ESEvent(
            eventType: .notifyWrite,
            processPath: processPath,
            pid: pid,
            parentPid: parentPid,
            filePath: filePath,
            decision: .notApplicable,
            threat: ESEvent.ThreatContext(
                threatName: alert.renameBurst == nil
                    ? "Possible ransomware behavior"
                    : "Rapid file-renaming behavior",
                threatFamily: "ransomware-behavior",
                isCodeSigned: developerIDValidated,
                teamID: developerIDValidated ? teamID : nil,
                signingID: developerIDValidated ? signingID : nil,
                metadata: ransomwareMetadata
            )
        )
        pushEvent(ransomwareEvent)
        if let data = try? encoder.encode(ransomwareEvent) {
            xpcServer?.sendThreatToApp(data)
        }
        guard shouldTerminate, let engine = remediationEngine else { return }
        // A deleted canary cannot be hashed; the writer is still stopped.
        let hash = fileScanner?.scan(filePath: filePath).hash ?? ""
        let report = engine.remediate(
            threatPath: filePath,
            hash: hash,
            threatName: "Ransomware (\(alert.indicators.first ?? "unknown"))",
            processPath: processPath,
            pid: pid,
            processIdentity: processIdentity
        )
        if let data = try? JSONEncoder().encode(report) {
            xpcServer?.sendRemediationToApp(data)
        }
    }

    /// Returns a repository boundary for developer build output. This is used
    /// only to prevent heuristic process termination; the protected alert is
    /// still emitted and cannot be suppressed.
    private static func approvedDevelopmentRepositoryRoot(
        containing path: String,
        approvedRoots: Set<String>
    ) -> String? {
        guard path.contains("/.build/") || path.contains("/CMakeFiles/")
                || path.contains("/DerivedData/") || path.contains("/Build/Products/") else {
            return nil
        }
        let destination = URL(fileURLWithPath: path).standardizedFileURL.path
        for rawRoot in approvedRoots {
            let root = URL(fileURLWithPath: rawRoot).standardizedFileURL
            let rootPath = root.path
            guard destination == rootPath || destination.hasPrefix(rootPath + "/") else { continue }
            if FileManager.default.fileExists(atPath: root.appendingPathComponent(".git").path) {
                return rootPath
            }
        }
        return nil
    }

    /// Encodes and pushes an `ESEvent` to the container app via XPC.
    /// Called from the ES callback queue; encoding is fast (small struct).
    private func pushEvent(_ event: ESEvent) {
        dispatchQueue.async { [weak self] in
            guard let self, let data = try? self.encoder.encode(event) else { return }
            self.xpcServer?.sendEventToApp(data)
        }
    }

    /// Limits real-time deep scanning to files that can reasonably carry
    /// executable or document-borne payloads. Databases, journals, logs,
    /// caches, media and other high-churn data are left to manual/deep scans.
    private func shouldDeepScanModifiedFile(at path: String) -> Bool {
        let url = URL(fileURLWithPath: path)
        let ext = url.pathExtension.lowercased()
        let candidateExtensions: Set<String> = [
            "app", "applescript", "bin", "bundle", "command", "dylib", "exe", "framework",
            "jar", "js", "macho", "mpkg", "pkg", "plugin", "py", "scpt", "sh", "tool", "zsh",
            "dmg", "iso", "rar", "tar", "zip", "7z",
            "doc", "docm", "docx", "pdf", "ppt", "pptm", "pptx",
            "rtf", "xls", "xlsm", "xlsx"
        ]

        // Do not ask FileManager whether every modified path is executable.
        // NOTIFY_CLOSE is system-wide and includes databases, File Provider
        // items, pseudo-volumes, and other high-churn files. The executable
        // lookup performs Carbon FileID resolution on those paths, producing
        // a large error stream and sustained CPU usage.
        //
        // Extensionless files are the exception in staging/persistence
        // locations: droppers write raw Mach-O and scripts there and may never
        // exec them directly (launchd does). Read only a 16-byte header.
        if ext.isEmpty {
            guard ExecutionTrustPolicy.isHighRiskLocation(path),
                  !path.contains("/Library/Caches/") else { return false }
            let kind = ScanCandidatePolicy.kind(atPath: path)
            guard ScanCandidatePolicy.isExecutableContent(kind) else { return false }
        } else if !candidateExtensions.contains(ext) {
            return false
        }

        guard let size = (try? FileManager.default.attributesOfItem(atPath: path)[.size])
                as? NSNumber else {
            return false
        }
        return size.int64Value > 0 && size.int64Value <= 100 * 1_024 * 1_024
    }

    private func boundedFileSample(at path: String, maximumBytes: Int) -> Data? {
        guard let handle = FileHandle(forReadingAtPath: path) else { return nil }
        defer { try? handle.close() }
        return try? handle.read(upToCount: maximumBytes)
    }

    private func isTrustedPlatformActor(_ path: String) -> Bool {
        path.hasPrefix("/System/Library/") ||
            path.hasPrefix("/usr/libexec/") ||
            path.hasPrefix("/System/Applications/")
    }

    /// Build products written by Apple's toolchain skip heuristic scanning.
    /// The actor must carry Apple's kernel-established platform identity inside
    /// a toolchain location. A self-signed binary with a copied Team ID or tool
    /// name cannot qualify.
    private func isTrustedDeveloperBuild(
        actorPath: String,
        actorIsPlatformBinary: Bool,
        filePath: String
    ) -> Bool {
        guard actorIsPlatformBinary else { return false }
        let actor = URL(fileURLWithPath: actorPath).lastPathComponent.lowercased()
        let trustedActors: Set<String> = [
            "xcode", "xcbuild", "xcodebuild", "swbbuildservice",
            "swift", "swiftc", "swift-frontend", "clang", "clang++", "ld"
        ]
        // Any Xcode bundle name (Xcode.app, Xcode-beta.app, Xcode_26.app).
        let isXcodeBundle = actorPath.range(of: #"/Xcode[^/]*\.app/Contents/"#, options: .regularExpression) != nil
        let isToolchainLocation =
            isXcodeBundle ||
            actorPath.hasPrefix("/Library/Developer/CommandLineTools/") ||
            actorPath.hasPrefix("/usr/bin/")
        guard isToolchainLocation,
              actorPath.contains("/Xcode") || trustedActors.contains(actor) else { return false }

        return filePath.contains("/Library/Developer/Xcode/DerivedData/") ||
            filePath.contains("/.build/") ||
            filePath.contains("/Build/Products/") ||
            filePath.contains("/Developer/Xcode/UserData/Previews/")
    }

    private func actorHasTrustedSigner(_ process: es_process_t) -> Bool {
        ExecutionTrustPolicy.hasTrustedSigner(
            codesigningFlags: process.codesigning_flags,
            isPlatformBinary: process.is_platform_binary,
            teamID: esOptionalString(process.team_id)
        )
    }

    private func validatedNickTamperActor(
        auditToken: audit_token_t,
        identity: TamperActorIdentity
    ) -> Bool {
        TamperActorValidator.shared.validatesNickActor(
            auditToken: auditToken,
            identity: identity
        )
    }

    private func leasedUpdateAuthorization(
        targetPath: String,
        sourcePath: String? = nil,
        operation: NickUpdateLeaseOperation,
        process: es_process_t,
        processPath: String,
        identity: TamperActorIdentity
    ) -> Bool {
        updateLeaseManager?.authorizes(
            targetPath: targetPath,
            sourcePath: sourcePath,
            operation: operation,
            actorPath: processPath,
            identity: identity,
            nickUpdateIdentityValidated: TamperActorValidator.shared.validatesNickUpdateActor(
                auditToken: process.audit_token,
                identity: identity
            )
        ) ?? false
    }

    private func handleProtectedWriteAuthorization(
        message: UnsafePointer<es_message_t>,
        targetPath: String,
        process: es_process_t,
        processPath: String,
        pid: Int32,
        identity: TamperActorIdentity
    ) {
        guard tamperProtection?.protects(path: targetPath) == true else {
            esClient?.respond(to: message, allow: true)
            return
        }
        let ordinarilyBlocked = tamperProtection?.shouldBlockWrite(
            targetPath: targetPath,
            identity: identity,
            nickIdentityValidated: validatedNickTamperActor(
                auditToken: process.audit_token,
                identity: identity
            )
        ) ?? false
        let leaseAllowed = leasedUpdateAuthorization(
            targetPath: targetPath,
            operation: .write,
            process: process,
            processPath: processPath,
            identity: identity
        )
        let blocked = ordinarilyBlocked && !leaseAllowed
        esClient?.respond(to: message, allow: !blocked)
        tamperProtection?.handleWriteEvent(
            targetPath: targetPath,
            actorPath: processPath,
            actorPid: pid,
            identity: identity,
            blocked: blocked
        )
    }

    /// Safely converts an `es_string_token_t` to a Swift `String`.
    /// Uses the token length; ES does not guarantee NUL termination.
    private func esString(_ token: es_string_token_t) -> String {
        esOptionalString(token) ?? "<unknown>"
    }

    private func esOptionalString(_ token: es_string_token_t) -> String? {
        guard let ptr = token.data, token.length > 0 else { return nil }
        return String(decoding: UnsafeRawBufferPointer(start: ptr, count: token.length), as: UTF8.self)
    }
}
