// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import EndpointSecurity
import Foundation
import Darwin
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
    var intentionalAppExitRegistry: IntentionalAppExitRegistry?

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
    private let interactivePipelinePolicy = InteractiveShellPipelinePolicy()
    var processPipeEvidenceProvider: @Sendable (Int32) -> ProcessPipeResolver.Evidence = {
        ProcessPipeResolver.evidence(pid: $0)
    }
    private let credentialReportLock = NSLock()
    private var lastCredentialReport: [String: Date] = [:]
    private var recentKeychainCommands: [String: CredentialAccessPolicy.RecentHiddenPrompt] = [:]
    private var keychainTransferFallback = KeychainTransferFallbackTracker()
    private static let credentialReportWindow: TimeInterval = 60

    // MARK: - Public Entry Point

    func handle(message: UnsafePointer<es_message_t>) {
        ESCallbackSafetyGuard.enter()
        defer { ESCallbackSafetyGuard.leave() }
        var msg = message.pointee

        // --- Extract process info synchronously (pointer only valid here) ---
        let process     = msg.process.pointee
        let processPath = esString(process.executable.pointee.path)
        let pid         = audit_token_to_pid(process.audit_token)
        let parentPid   = audit_token_to_pid(process.parent_audit_token)
        let responsiblePid = audit_token_to_pid(process.responsible_audit_token)
        // Never query another process from the ES callback queue. A process can
        // be suspended in AUTH_EXEC while the same queue is expected to answer
        // that authorization, turning getpgid/proc_pidinfo into a deadlock.
        // All of this identity is already supplied atomically by EndpointSecurity.
        let processGroupID = process.group_id > 0 ? process.group_id : pid
        let processIdentity = ProcessInstanceIdentity(
            pid: pid,
            startSeconds: msg.version >= 3 ? UInt64(process.start_time.tv_sec) : 0,
            startMicroseconds: msg.version >= 3 ? UInt64(process.start_time.tv_usec) : 0,
            pidVersion: Int32(audit_token_to_pidversion(process.audit_token)),
            processGroupID: process.group_id,
            sessionID: UInt32(process.session_id)
        )
        let tamperActorIdentity = TamperActorIdentity(
            teamID: esOptionalString(process.team_id),
            signingID: esOptionalString(process.signing_id),
            codesigningFlags: process.codesigning_flags,
            isPlatformBinary: process.is_platform_binary
        )

        switch msg.event_type {

        // MARK: AUTH_SIGNAL — protect Nick processes from hostile termination

        case ES_EVENT_TYPE_AUTH_SIGNAL:
            let signalEvent = msg.event.signal
            let signalNumber = Int32(signalEvent.sig)
            let target = signalEvent.target.pointee
            let targetPID = audit_token_to_pid(target.audit_token)
            let targetPath = esString(target.executable.pointee.path)
            let targetIdentity = TamperActorIdentity(
                teamID: esOptionalString(target.team_id),
                signingID: esOptionalString(target.signing_id),
                codesigningFlags: target.codesigning_flags,
                isPlatformBinary: target.is_platform_binary
            )
            let effectiveSender = (msg.version >= 9 ? signalEvent.instigator : nil)?.pointee ?? process
            let senderPID = audit_token_to_pid(effectiveSender.audit_token)
            let senderPath = esString(effectiveSender.executable.pointee.path)
            let senderIdentity = TamperActorIdentity(
                teamID: esOptionalString(effectiveSender.team_id),
                signingID: esOptionalString(effectiveSender.signing_id),
                codesigningFlags: effectiveSender.codesigning_flags,
                isPlatformBinary: effectiveSender.is_platform_binary
            )
            // ES fields are kernel-authored and safe on the callback queue.
            // Full SecCode validation is never performed while an AUTH reply is
            // outstanding.
            let senderNickValidated = senderIdentity.isValidIdentitySignature
                && senderIdentity.teamID == TamperProtectionPolicy.nickTeamID
                && [TamperProtectionPolicy.nickMaintenanceSigningIDs,
                    TamperProtectionPolicy.nickLeasedUpdateSigningIDs]
                    .contains { ids in
                        senderIdentity.signingID.map(ids.contains) == true
                    }
            let deadlineExpired = mach_absolute_time() >= msg.deadline
            let deny = !deadlineExpired && NickSignalProtectionPolicy.shouldDeny(
                signal: signalNumber,
                targetIdentity: targetIdentity,
                senderIdentity: senderIdentity,
                senderNickIdentityValidated: senderNickValidated
            )
            esClient?.respond(to: message, allow: !deny)
            if deny {
                dispatchQueue.async { [weak self] in
                    let event = ESEvent(
                        eventType: .notifyWrite,
                        processPath: senderPath,
                        pid: senderPID,
                        parentPid: parentPid,
                        filePath: targetPath,
                        decision: .deny,
                        threat: .init(
                            threatName: "Attempt to terminate Nick was blocked",
                            threatFamily: "tamper",
                            isCodeSigned: senderIdentity.isValidIdentitySignature,
                            teamID: senderIdentity.teamID,
                            signingID: senderIdentity.signingID,
                            metadata: [
                                "signal": String(signalNumber),
                                "targetPID": String(targetPID),
                                "senderPID": String(senderPID),
                                "senderPath": senderPath,
                                "reason": "nick_signal_denied"
                            ]
                        )
                    )
                    if let data = try? self?.encoder.encode(event) {
                        self?.xpcServer?.sendThreatToApp(data)
                    }
                }
            }

        // MARK: AUTH_EXEC — block known-bad binaries on execution

        case ES_EVENT_TYPE_AUTH_EXEC:
            let target      = msg.event.exec.target.pointee
            let targetPath  = esString(target.executable.pointee.path)
            let targetIdentity = FileIdentity(stat: target.executable.pointee.stat)
            let targetTeamID = esOptionalString(target.team_id)
            let targetSigningID = esOptionalString(target.signing_id)
            let responsiblePID = audit_token_to_pid(target.responsible_audit_token)
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
                identity: targetIdentity
            ) ?? false
            let shouldBlock = !explicitlyAllowed && (fileScanner?.allowsEnforcement(of: cached) ?? false)

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
                        arguments: execArguments,
                        responsiblePID: responsiblePID > 0 ? responsiblePID : nil,
                        processIdentity: processIdentity
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
            let isReadOpen = msg.event.open.fflag & FREAD != 0
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
                dispatchQueue.async { [weak self] in
                    self?.tamperProtection?.handleWriteEvent(
                    targetPath: filePath,
                    actorPath: processPath,
                    actorPid: pid,
                    identity: tamperActorIdentity,
                    blocked: writeBlocked,
                    operation: .openWrite
                    )
                }
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
                identity: fileIdentity
            ) ?? false
            let shouldBlock = !explicitlyAllowed && (fileScanner?.allowsEnforcement(of: cached) ?? false)

            esClient?.respond(to: message, allow: !shouldBlock)

            if isReadOpen, !shouldBlock,
               let credentialStore = CredentialAccessPolicy.sensitiveStore(at: filePath) {
                dispatchQueue.async { [weak self] in
                    self?.observeCredentialStoreOpen(
                        store: credentialStore,
                        path: filePath,
                        actorPath: processPath,
                        actorPID: pid,
                        parentPID: parentPid,
                        responsiblePID: responsiblePid > 0 ? responsiblePid : nil,
                        processIdentity: processIdentity,
                        actorIdentity: tamperActorIdentity
                    )
                }
            }
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
                dispatchQueue.async { [weak self] in
                    self?.tamperProtection?.handleWriteEvent(
                    targetPath: filePath,
                    actorPath: processPath,
                    actorPid: pid,
                    identity: tamperActorIdentity,
                    blocked: true,
                    operation: .create
                    )
                }
                break
            }
            if tamperProtection?.protects(path: filePath) == true {
                dispatchQueue.async { [weak self] in
                    self?.tamperProtection?.handleWriteEvent(
                    targetPath: filePath,
                    actorPath: processPath,
                    actorPid: pid,
                    identity: tamperActorIdentity,
                    blocked: false,
                    operation: .create
                    )
                }
            }

            // This is heuristic-only: there is no file to hash yet. Observe and
            // report suspicious creates, but fail open so AirDrop, Handoff,
            // installers and developer builds cannot be disrupted.
            let processSuspect = fileScanner?.isUntrustedLocation(processPath) ?? false
            let destSuspect    = fileScanner?.isUntrustedLocation(filePath) ?? false
            let isSuspicious   = processSuspect && destSuspect
            esClient?.respond(to: message, allow: true)
            behaviorTracker?.recordCreate(
                pid: pid,
                processGroupID: processGroupID,
                processPath: processPath,
                path: filePath
            )

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
                identity: tamperActorIdentity,
                operation: .truncate
            )

        case ES_EVENT_TYPE_AUTH_LINK:
            handleProtectedWriteAuthorization(
                message: message,
                targetPath: esString(msg.event.link.target_dir.pointee.path)
                    + "/" + esString(msg.event.link.target_filename),
                process: process,
                processPath: processPath,
                pid: pid,
                identity: tamperActorIdentity,
                operation: .link
            )

        case ES_EVENT_TYPE_AUTH_CLONE:
            let cloneSource = esString(msg.event.clone.source.pointee.path)
            if CredentialAccessPolicy.sensitiveStore(at: cloneSource) == .keychain {
                let cloneDestination = esString(msg.event.clone.target_dir.pointee.path)
                    + "/" + esString(msg.event.clone.target_name)
                dispatchQueue.async { [weak self] in
                    self?.reportKeychainTransfer(
                        sourcePath: cloneSource, destinationPath: cloneDestination,
                        actorPath: processPath,
                        actorPID: pid, parentPID: parentPid,
                        responsiblePID: responsiblePid > 0 ? responsiblePid : nil,
                        processIdentity: processIdentity,
                        actorIdentity: tamperActorIdentity,
                        operation: "clone"
                    )
                }
            }
            handleProtectedWriteAuthorization(
                message: message,
                targetPath: esString(msg.event.clone.target_dir.pointee.path)
                    + "/" + esString(msg.event.clone.target_name),
                process: process,
                processPath: processPath,
                pid: pid,
                identity: tamperActorIdentity,
                operation: .clone
            )

        // MARK: AUTH_MMAP — block mapping of cached-threat files

        case ES_EVENT_TYPE_AUTH_MMAP:
            let filePath = esString(msg.event.mmap.source.pointee.path)
            let cached   = fileScanner?.cache.lookup(
                path: filePath,
                identity: FileIdentity(stat: msg.event.mmap.source.pointee.stat)
            )
            let shouldBlock = fileScanner?.allowsEnforcement(of: cached) ?? false

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
                    identity: tamperActorIdentity,
                    operation: .copyfile
                )
                break
            }
            let cached   = fileScanner?.cache.lookup(
                path: srcPath,
                identity: FileIdentity(stat: msg.event.copyfile.source.pointee.stat)
            )
            let shouldBlock = fileScanner?.allowsEnforcement(of: cached) ?? false

            esClient?.respond(to: message, allow: !shouldBlock)
            if CredentialAccessPolicy.sensitiveStore(at: srcPath) == .keychain {
                dispatchQueue.async { [weak self] in
                    self?.reportKeychainTransfer(
                        sourcePath: srcPath, destinationPath: copyDestination,
                        actorPath: processPath,
                        actorPID: pid, parentPID: parentPid,
                        responsiblePID: responsiblePid > 0 ? responsiblePid : nil,
                        processIdentity: processIdentity,
                        actorIdentity: tamperActorIdentity,
                        operation: "copyfile"
                    )
                }
            }

        case ES_EVENT_TYPE_AUTH_EXCHANGEDATA:
            let firstPath = esString(msg.event.exchangedata.file1.pointee.path)
            let secondPath = esString(msg.event.exchangedata.file2.pointee.path)
            esClient?.respond(to: message, allow: true)
            for (sourcePath, destinationPath) in [(firstPath, secondPath), (secondPath, firstPath)]
            where CredentialAccessPolicy.sensitiveStore(at: sourcePath) == .keychain {
                dispatchQueue.async { [weak self] in
                    self?.reportKeychainTransfer(
                        sourcePath: sourcePath, destinationPath: destinationPath,
                        actorPath: processPath,
                        actorPID: pid, parentPID: parentPid,
                        responsiblePID: responsiblePid > 0 ? responsiblePid : nil,
                        processIdentity: processIdentity,
                        actorIdentity: tamperActorIdentity,
                        operation: "exchangedata"
                    )
                }
            }

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

                self.verifyPotentialKeychainTransferOnClose(
                    destinationPath: filePath,
                    actorPath: processPath,
                    actorPID: pid,
                    parentPID: parentPid,
                    responsiblePID: responsiblePid > 0 ? responsiblePid : nil,
                    processIdentity: processIdentity,
                    actorIdentity: tamperActorIdentity
                )

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
                            self.reportThreat(threat)
                        }
                    }
                }

                // --- File Integrity Monitoring ---
                self.reportIntegrityViolation(
                    at: filePath, actorPID: pid, responsiblePID: responsiblePid
                )

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
                        processIdentity: processIdentity,
                        responsiblePID: responsiblePid
                    )
                }

                // --- Threat Detection + Remediation ---
                let shouldDeepScan = self.shouldDeepScanModifiedFile(at: filePath)
                let completedIdentity = FileIdentity(path: filePath)
                let exactSignatureDecision = completedIdentity.map {
                    ScanCandidatePolicy.completedWriteExactSignatureDecision(
                        path: filePath,
                        fileSize: $0.size
                    )
                } ?? .skip(.empty)
                if exactSignatureDecision == .skip(.overSizeLimit) {
                    Self.logger.info(
                        "Completed-write exact-signature check skipped over size cap: \(filePath, privacy: .private)"
                    )
                }
                let shouldCheckExactSignature = exactSignatureDecision == .check
                guard shouldDeepScan || shouldCheckExactSignature else { return }
                // Xcode/SwiftPM build products are rewritten constantly and
                // legitimately contain linker/install/persistence strings that
                // generic YARA rules match. Apple developer tools remain covered
                // by exact hash intelligence, but heuristic scanning here only
                // creates noise and previously broke builds.
                if isTrustedBuildOutput {
                    return
                }
                guard let scanner = self.fileScanner else { return }
                let result: FileScanner.ScanResult
                if shouldDeepScan {
                    self.pushEvent(ESEvent(
                        eventType: .notifyWrite,
                        processPath: processPath,
                        pid: pid,
                        parentPid: parentPid,
                        filePath: filePath,
                        decision: .notApplicable
                    ))
                    result = scanner.scan(filePath: filePath)
                } else {
                    guard let completedIdentity,
                          let signatureResult = scanner.exactSignatureMatch(
                            path: filePath,
                            identity: completedIdentity
                          ) else { return }
                    result = signatureResult
                }
                guard result.isThreat else { return }
                self.reportDetectedThreat(
                    result,
                    processPath: processPath,
                    pid: pid,
                    parentPid: parentPid,
                    filePath: filePath,
                    processIdentity: processIdentity,
                    terminateProcess: emailEvent == nil
                )
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
            let consoleUser = protectsRename
                ? callbackSafeConsoleUser(destinationPath: destinationPath, process: process)
                : nil
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
            if CredentialAccessPolicy.sensitiveStore(at: srcPath) == .keychain {
                dispatchQueue.async { [weak self] in
                    self?.reportKeychainTransfer(
                        sourcePath: srcPath, destinationPath: destinationPath,
                        actorPath: processPath,
                        actorPID: pid, parentPID: parentPid,
                        responsiblePID: responsiblePid > 0 ? responsiblePid : nil,
                        processIdentity: processIdentity,
                        actorIdentity: tamperActorIdentity,
                        operation: "rename"
                    )
                }
            }
            if !renameBlocked {
                dispatchQueue.async { [weak self] in
                    guard let self,
                          self.behaviorTracker?.wasRecentlyCreated(
                            path: srcPath, by: pid, processGroupID: processGroupID
                          ) == true,
                          FileManager.default.fileExists(atPath: destinationPath)
                    else { return }
                    let evidence = BehaviorTracker.RenameReplacementEvidence(
                        sourceData: self.boundedFileSample(at: srcPath, maximumBytes: 65_536),
                        destinationData: self.boundedFileSample(at: destinationPath, maximumBytes: 65_536),
                        destinationExisted: true
                    )
                    self.behaviorTracker?.recordRenameIntent(
                        pid: pid, source: srcPath, destination: destinationPath,
                        evidence: evidence
                    )
                }
            }
            dispatchQueue.async { [weak self] in
                self?.tamperProtection?.handleRenameEvent(
                srcPath: srcPath,
                destinationPath: destinationPath,
                actorPath: processPath,
                actorPid: pid,
                identity: tamperActorIdentity,
                blocked: renameBlocked,
                consoleUser: consoleUser
                )
            }
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
                self.reportIntegrityViolation(
                    at: notifySrcPath, actorPID: pid, responsiblePID: responsiblePid
                )
                self.reportIntegrityViolation(
                    at: notifyDestPath, actorPID: pid, responsiblePID: responsiblePid
                )
                self.behaviorTracker?.recordRename(
                    pid: pid, processGroupID: processGroupID, processPath: processPath,
                    source: notifySrcPath, destination: notifyDestPath,
                    replacementEvidence: self.behaviorTracker?.consumeRenameIntent(
                        pid: pid, source: notifySrcPath, destination: notifyDestPath
                    )
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
                        responsiblePID: responsiblePid,
                        actorIsPlatformBinary: renameActorIsPlatform,
                        teamID: renameTeamID,
                        signingID: renameSigningID
                    )
                }

                // Browsers and Finder commonly finish a download by renaming a
                // temporary file. Check the final intake path by exact hash so
                // `.txt` and extensionless known samples cannot evade the
                // completed-write scan. Temporary suffixes are excluded by the
                // shared policy to avoid duplicate pre-finalization findings.
                if let scanner = self.fileScanner,
                   let destinationIdentity = FileIdentity(path: notifyDestPath) {
                    let signatureDecision = ScanCandidatePolicy.completedWriteExactSignatureDecision(
                        path: notifyDestPath,
                        fileSize: destinationIdentity.size
                    )
                    if signatureDecision == .skip(.overSizeLimit) {
                        Self.logger.info(
                            "Completed-write exact-signature check skipped over size cap after rename: \(notifyDestPath, privacy: .private)"
                        )
                    }
                    guard signatureDecision == .check,
                          let result = scanner.exactSignatureMatch(
                            path: notifyDestPath,
                            identity: destinationIdentity
                          ) else { return }
                    self.reportDetectedThreat(
                        result,
                        processPath: processPath,
                        pid: pid,
                        parentPid: parentPid,
                        filePath: notifyDestPath,
                        processIdentity: processIdentity,
                        terminateProcess: true
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
            dispatchQueue.async { [weak self] in
                self?.tamperProtection?.handleUnlinkEvent(
                    targetPath: unlinkTarget,
                    actorPath: processPath,
                    actorPid: pid,
                    identity: tamperActorIdentity,
                    blocked: unlinkBlocked
                )
            }
            if !unlinkBlocked {
                fileScanner?.cache.invalidate(path: unlinkTarget)
            }

        // MARK: NOTIFY_UNLINK — invalidate cache for deleted files

        case ES_EVENT_TYPE_NOTIFY_UNLINK:
            let filePath = esString(msg.event.unlink.target.pointee.path)
            fileScanner?.cache.invalidate(path: filePath)
            dispatchQueue.async { [weak self] in
                self?.reportIntegrityViolation(
                    at: filePath, actorPID: pid, responsiblePID: responsiblePid
                )
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
                        processIdentity: processIdentity,
                        responsiblePID: responsiblePid
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
            // Never inspect a just-forked child's descriptors from the ES callback
            // queue. The child may already be suspended in AUTH_EXEC; proc_pidinfo
            // can then wait for that exec while this same queue is responsible for
            // answering it. Exec observation and its bounded retries collect the
            // directional pipe evidence after AUTH_EXEC has been answered.
            interactivePipelinePolicy.recordFork(
                childPID: childPid,
                parentPID: pid,
                standardInputPipeIdentifier: nil,
                standardOutputPipeIdentifier: nil,
                timestamp: Date()
            )
            // Keep lifecycle data inside the extension. Forwarding every fork
            // invalidates the app's observable timeline at system-wide rates.

        case ES_EVENT_TYPE_NOTIFY_EXIT:
            // Clean up timeline to prevent unbounded memory growth
            behaviorTracker?.cleanupExited(pid: pid)
            // Phase 6: mark process exit in tree
            let exitCode: Int32 = 0  // exit code not provided by notify_exit in this binding
            processTree?.recordExit(pid: pid, exitCode: exitCode)
            if tamperActorIdentity.teamID == TamperProtectionPolicy.nickTeamID,
               tamperActorIdentity.isValidIdentitySignature,
               tamperActorIdentity.signingID == "com.ehsanazish.nick",
               xpcServer?.consumeAuthenticatedAppExit(pid: pid) == true {
                let exit = intentionalAppExitRegistry?.consume(pid: pid)
                    ?? (intentional: false, signal: nil)
                if !exit.intentional {
                    let signal = exit.signal
                    dispatchQueue.async { [weak self] in
                        let event = ESEvent(
                            eventType: .notifyExit,
                            processPath: processPath,
                            pid: pid,
                            parentPid: parentPid,
                            filePath: nil,
                            decision: .notApplicable,
                            threat: .init(
                                threatName: "Nick was terminated unexpectedly",
                                threatFamily: "tamper",
                                isCodeSigned: true,
                                teamID: tamperActorIdentity.teamID,
                                signingID: tamperActorIdentity.signingID,
                                metadata: [
                                    "reason": "nick_unexpected_exit",
                                    "killerPID": signal.map { String($0.senderPID) } ?? "unknown",
                                    "killerPath": signal?.senderPath ?? "unknown",
                                    "signal": signal.map { String($0.signal) } ?? "unknown",
                                    "deliveryLevel": "inform"
                                ]
                            )
                        )
                        if let data = try? self?.encoder.encode(event) {
                            self?.xpcServer?.sendThreatToApp(data)
                        }
                    }
                }
            }

        case ES_EVENT_TYPE_NOTIFY_SIGNAL:
            // AUTH_SIGNAL owns enforcement and durable denial evidence. Keep
            // the notify subscription so permitted root/platform signals can
            // be correlated with a subsequent unexpected app exit in field logs.
            let signalEvent = msg.event.signal
            let targetPID = audit_token_to_pid(signalEvent.target.pointee.audit_token)
            let sender = (msg.version >= 9 ? signalEvent.instigator : nil)?.pointee ?? process
            intentionalAppExitRegistry?.recordSignal(
                targetPID: targetPID,
                context: .init(
                    senderPID: audit_token_to_pid(sender.audit_token),
                    senderPath: esString(sender.executable.pointee.path),
                    signal: Int32(signalEvent.sig),
                    observedAt: Date()
                )
            )

        // MARK: Apple-provided security signals

        case ES_EVENT_TYPE_NOTIFY_XP_MALWARE_DETECTED:
            let detected = msg.event.xp_malware_detected.pointee
            let malware = esString(detected.malware_identifier)
            reportAppleSecurityEvent(
                type: .notifyXProtectMalwareDetected,
                actorPath: processPath,
                actorPID: pid,
                parentPID: parentPid,
                responsiblePID: responsiblePid,
                filePath: esString(detected.detected_path),
                title: malware.isEmpty ? "XProtect detected malware" : "XProtect detected \(malware)",
                family: "apple-xprotect",
                ruleTier: "protected",
                metadata: [
                    "appleEvent": "xprotect-malware-detected",
                    "signatureVersion": esString(detected.signature_version),
                    "incidentIdentifier": esString(detected.incident_identifier)
                ]
            )

        case ES_EVENT_TYPE_NOTIFY_XP_MALWARE_REMEDIATED:
            let remediated = msg.event.xp_malware_remediated.pointee
            let malware = esString(remediated.malware_identifier)
            let remediatedPID = remediated.remediated_process_audit_token.map {
                audit_token_to_pid($0.pointee)
            }
            reportAppleSecurityEvent(
                type: .notifyXProtectMalwareRemediated,
                actorPath: processPath,
                actorPID: pid,
                parentPID: parentPid,
                responsiblePID: remediatedPID ?? responsiblePid,
                filePath: esString(remediated.remediated_path),
                title: malware.isEmpty ? "XProtect remediation reported" : "XProtect remediated \(malware)",
                family: "apple-xprotect",
                ruleTier: "review",
                metadata: [
                    "appleEvent": "xprotect-malware-remediated",
                    "signatureVersion": esString(remediated.signature_version),
                    "incidentIdentifier": esString(remediated.incident_identifier),
                    "remediationAction": esString(remediated.action_type),
                    "remediationSucceeded": remediated.success ? "true" : "false",
                    "remediationResult": esString(remediated.result_description)
                ]
            )

        case ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD:
            let event = msg.event.btm_launch_item_add.pointee
            let actor = event.instigator
            let actorPID = actor.map { audit_token_to_pid($0.pointee.audit_token) } ?? pid
            let actorPath = actor.map { esString($0.pointee.executable.pointee.path) } ?? processPath
            let actorParentPID = actor.map { audit_token_to_pid($0.pointee.parent_audit_token) } ?? parentPid
            let appPID = event.app.map { audit_token_to_pid($0.pointee.audit_token) }
            let item = event.item.pointee
            reportAppleSecurityEvent(
                type: .notifyBTMLaunchItemAdd,
                actorPath: actorPath,
                actorPID: actorPID,
                parentPID: actorParentPID,
                responsiblePID: appPID,
                filePath: esString(event.executable_path),
                title: "Background item added",
                family: "apple-background-task-management",
                ruleTier: "review",
                metadata: [
                    "appleEvent": "background-item-added",
                    "itemURL": esString(item.item_url),
                    "appURL": esString(item.app_url),
                    "managed": item.managed ? "true" : "false",
                    "legacy": item.legacy ? "true" : "false"
                ]
            )

        case ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_REMOVE:
            let event = msg.event.btm_launch_item_remove.pointee
            let actor = event.instigator
            let actorPID = actor.map { audit_token_to_pid($0.pointee.audit_token) } ?? pid
            let actorPath = actor.map { esString($0.pointee.executable.pointee.path) } ?? processPath
            let actorParentPID = actor.map { audit_token_to_pid($0.pointee.parent_audit_token) } ?? parentPid
            let appPID = event.app.map { audit_token_to_pid($0.pointee.audit_token) }
            let item = event.item.pointee
            reportAppleSecurityEvent(
                type: .notifyBTMLaunchItemRemove,
                actorPath: actorPath,
                actorPID: actorPID,
                parentPID: actorParentPID,
                responsiblePID: appPID,
                filePath: esString(item.item_url),
                title: "Background item removed",
                family: "apple-background-task-management",
                ruleTier: "review",
                metadata: [
                    "appleEvent": "background-item-removed",
                    "itemURL": esString(item.item_url),
                    "appURL": esString(item.app_url),
                    "managed": item.managed ? "true" : "false",
                    "legacy": item.legacy ? "true" : "false"
                ]
            )

        case ES_EVENT_TYPE_NOTIFY_GATEKEEPER_USER_OVERRIDE:
            let event = msg.event.gatekeeper_user_override.pointee
            let targetPath: String
            if event.file_type == ES_GATEKEEPER_USER_OVERRIDE_FILE_TYPE_PATH {
                targetPath = esString(event.file.file_path)
            } else {
                targetPath = esString(event.file.file.pointee.path)
            }
            reportAppleSecurityEvent(
                type: .notifyGatekeeperUserOverride,
                actorPath: processPath,
                actorPID: pid,
                parentPID: parentPid,
                responsiblePID: responsiblePid,
                filePath: targetPath,
                title: "Gatekeeper override used",
                family: "apple-gatekeeper",
                ruleTier: "review",
                metadata: ["appleEvent": "gatekeeper-user-override"]
            )

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
            let instigatorPID = audit_token_to_pid(tcc.instigator_token)
            let instigatorPath = tcc.instigator.map {
                esString($0.pointee.executable.pointee.path)
            } ?? processPath
            let instigatorParentPID = tcc.instigator.map {
                audit_token_to_pid($0.pointee.parent_audit_token)
            } ?? parentPid
            let tccResponsiblePID = tcc.responsible_token.map {
                audit_token_to_pid($0.pointee)
            } ?? responsiblePid
            reportAppleSecurityEvent(
                type: .notifyTCCModify,
                actorPath: instigatorPath,
                actorPID: instigatorPID,
                parentPID: instigatorParentPID,
                responsiblePID: tccResponsiblePID,
                filePath: appPath.isEmpty ? nil : appPath,
                title: "Privacy permission \(isGranted ? "granted" : "revoked")",
                family: "apple-tcc",
                ruleTier: "review",
                metadata: [
                    "appleEvent": "tcc-permission-modified",
                    "service": service,
                    "appBundleID": appBundleID,
                    "appPath": appPath,
                    "changeType": isGranted ? "granted" : "revoked"
                ]
            )

        default:
            // For any unhandled AUTH event, allow immediately.
            if msg.action_type == ES_ACTION_TYPE_AUTH {
                esClient?.respond(to: message, allow: true)
            }
        }
    }

    /// Converts Apple-authored Endpoint Security notifications into the same
    /// durable finding channel used by Nick's detectors. Attribution is
    /// captured here, while the process ancestry is still available.
    private func reportAppleSecurityEvent(
        type: ESEventType,
        actorPath: String,
        actorPID: Int32,
        parentPID: Int32,
        responsiblePID: Int32?,
        filePath: String?,
        title: String,
        family: String,
        ruleTier: String,
        metadata: [String: String]
    ) {
        dispatchQueue.async { [weak self] in
            self?.reportAppleSecurityEventOffCallbackQueue(
                type: type,
                actorPath: actorPath,
                actorPID: actorPID,
                parentPID: parentPID,
                responsiblePID: responsiblePID,
                filePath: filePath,
                title: title,
                family: family,
                ruleTier: ruleTier,
                metadata: metadata
            )
        }
    }

    private func reportAppleSecurityEventOffCallbackQueue(
        type: ESEventType,
        actorPath: String,
        actorPID: Int32,
        parentPID: Int32,
        responsiblePID: Int32?,
        filePath: String?,
        title: String,
        family: String,
        ruleTier: String,
        metadata: [String: String]
    ) {
        var evidence = metadata
        evidence["reason"] = metadata["appleEvent"] ?? "apple-security-event"
        evidence["rule"] = metadata["appleEvent"] ?? "apple-security-event"
        evidence["ruleTier"] = ruleTier
        evidence["detectionKind"] = "apple-security-event"
        if let attribution = processTree?.responsibleApp(
            actorPID: actorPID,
            responsiblePID: responsiblePID,
            resolver: SecCodeResponsibleProcessIdentityResolver.shared
        ) {
            evidence.merge(attribution.metadata) { current, _ in current }
        }
        reportThreat(ESEvent(
            eventType: type,
            processPath: actorPath,
            pid: actorPID,
            parentPid: parentPID,
            filePath: filePath,
            decision: .notApplicable,
            threat: ESEvent.ThreatContext(
                threatName: title,
                threatFamily: family,
                metadata: evidence
            )
        ))
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
            let blocked = match != nil && scanner.allowsAnyBlocking
            self?.esClient?.respond(to: retained.pointer, allow: !blocked)
            if blocked, let match {
                Self.logger.notice("Blocked first launch of known threat \(match.name, privacy: .public): \(path, privacy: .private)")
            }
            completion(blocked, scanner.cache.lookup(path: path, identity: identity))
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
        arguments: [String],
        responsiblePID: Int32?,
        processIdentity: ProcessInstanceIdentity
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
        processTree?.recordExec(pid: pid, ppid: parentPid, path: targetPath, args: arguments)
        tamperProtection?.handleExecEvent(execPath: targetPath, pid: pid, args: arguments)

        let lolbinFinding = LOLBinExecutionPolicy.finding(
            executablePath: targetPath,
            arguments: arguments
        )
        let pipelineEvidence = processPipeEvidenceProvider(pid)
        let pipelineObservation = InteractiveShellPipelinePolicy.Observation(
            pid: pid,
            parentPID: parentPid,
            executablePath: targetPath,
            arguments: arguments,
            standardInputPipeIdentifier: pipelineEvidence.standardInputPipeIdentifier,
            standardOutputPipeIdentifier: pipelineEvidence.standardOutputPipeIdentifier,
            hasNetworkSocket: pipelineEvidence.hasNetworkSocket,
            codeIdentityValidated: trustedSigner,
            signingIdentifier: signingID,
            timestamp: Date()
        )
        let interactivePipelineFinding = interactivePipelinePolicy.observe(pipelineObservation)
        let attribution = processTree?.responsibleApp(
            actorPID: pid,
            responsiblePID: responsiblePID,
            resolver: SecCodeResponsibleProcessIdentityResolver.shared
        )
        let credentialFinding = CredentialAccessPolicy.findingForExec(
            executablePath: targetPath,
            arguments: arguments,
            responsibleIdentity: attribution?.app.map(Self.credentialIdentity)
        )
        if let credentialFinding,
           CredentialAccessPolicy.armsKeychainCorrelation(reason: credentialFinding.reason) {
            credentialReportLock.withLock {
                let chainKey = self.credentialChainKey(attribution: attribution, actorPID: pid)
                recentKeychainCommands[chainKey] = .init(
                    chainKey: chainKey,
                    armedAt: Date(),
                    processPID: processIdentity.pid,
                    processPIDVersion: processIdentity.pidVersion
                )
            }
        }
        let behaviorTitle = credentialFinding?.title
            ?? lolbinFinding?.title
            ?? interactivePipelineFinding.map { _ in "Download-to-shell command detected" }
        let behaviorFamily = credentialFinding == nil ? "lolbin-behavior" : "credential-access"
        let responsibleChainValidated = attribution?.app.map {
            $0.signing == .signed || $0.signing == .applePlatform
        } ?? false

        pushEvent(ESEvent(
            eventType:   .authExec,
            processPath: processPath,
            pid:         pid,
            parentPid:   parentPid,
            filePath:    targetPath,
            decision:    blocked ? .deny : .allow,
            threat:      ESEvent.ThreatContext(
                sha256:       verdict?.hash,
                threatName:   verdict?.threatName ?? behaviorTitle,
                threatFamily: verdict?.threatFamily ?? (behaviorTitle == nil ? nil : behaviorFamily),
                isCodeSigned: trustedSigner,
                teamID: teamID,
                signingID: signingID,
                metadata: credentialFinding.map { finding in
                    let validatedSecretRead = finding.reason == "keychain_secret_read"
                        && trustedSigner && responsibleChainValidated
                    var metadata = [
                        "reason": finding.reason,
                        "rule": finding.reason,
                        "ruleTier": "review",
                        "detectionKind": "credential-access",
                        "signalSeverity": validatedSecretRead
                            ? "info" : (finding.store == .passwordPrompt ? "high" : "medium"),
                        "credentialStore": finding.store.rawValue,
                        "deliveryLevel": validatedSecretRead ? "inform" : "interrupt"
                    ]
                    if let attribution {
                        metadata.merge(attribution.metadata) { current, _ in current }
                    }
                    return metadata
                } ?? lolbinFinding.map { finding in
                    let validatedSameChain = trustedSigner
                        && (attribution?.app?.signing == .signed
                            || attribution?.app?.signing == .applePlatform)
                    let localTemporaryExecution = finding.reason == "mktemp_execute"
                        && LOLBinExecutionPolicy.mktempTier(
                            actorIdentityValidated: trustedSigner,
                            responsibleChainValidated: validatedSameChain,
                            hasNetworkOrigin: pipelineEvidence.hasNetworkSocket
                                || interactivePipelineFinding != nil,
                            hasQuarantineOrigin: Self.hasQuarantineOrigin(at: targetPath)
                        ) == .review
                    var metadata = [
                        "reason": finding.reason,
                        "rule": finding.reason,
                        "ruleTier": localTemporaryExecution ? "review" : "protected",
                        "detectionKind": "lolbin-behavior",
                        "signalSeverity": localTemporaryExecution ? "medium" : finding.severity,
                        "execTargetPath": targetPath
                    ]
                    if let matchedCommand = finding.matchedCommand {
                        metadata["matchedCommand"] = matchedCommand
                    }
                    if let attribution {
                        metadata.merge(attribution.metadata) { current, _ in current }
                    }
                    return metadata
                } ?? interactivePipelineFinding.map { finding in
                    var metadata = [
                        "reason": finding.reason,
                        "rule": finding.reason,
                        "ruleTier": "protected",
                        "detectionKind": "lolbin-behavior",
                        "signalSeverity": "critical",
                        "signalConfidence": finding.confidence,
                        "matchedCommand": finding.matchedCommand,
                        "execTargetPath": targetPath
                    ]
                    if let attribution {
                        metadata.merge(attribution.metadata) { current, _ in current }
                    }
                    return metadata
                }
            )
        ))
        if interactivePipelineFinding == nil,
           interactivePipelinePolicy.shouldRetry(pipelineObservation) {
            scheduleInteractivePipelineRetries(
                observation: pipelineObservation,
                responsiblePID: responsiblePID
            )
        }
    }

    private func scheduleInteractivePipelineRetries(
        observation: InteractiveShellPipelinePolicy.Observation,
        responsiblePID: Int32?
    ) {
        for delay in [0.02, 0.10, 0.30, 0.75] {
            dispatchQueue.asyncAfter(deadline: .now() + delay) { [weak self] in
                guard let self else { return }
                let evidence = self.processPipeEvidenceProvider(observation.pid)
                let retry = InteractiveShellPipelinePolicy.Observation(
                    pid: observation.pid,
                    parentPID: observation.parentPID,
                    executablePath: observation.executablePath,
                    arguments: observation.arguments,
                    standardInputPipeIdentifier: evidence.standardInputPipeIdentifier,
                    standardOutputPipeIdentifier: evidence.standardOutputPipeIdentifier,
                    hasNetworkSocket: evidence.hasNetworkSocket,
                    codeIdentityValidated: observation.codeIdentityValidated,
                    signingIdentifier: observation.signingIdentifier,
                    timestamp: Date()
                )
                guard let finding = self.interactivePipelinePolicy.observe(retry) else { return }
                var metadata = [
                    "reason": finding.reason,
                    "rule": finding.reason,
                    "ruleTier": "protected",
                    "detectionKind": "lolbin-behavior",
                    "signalSeverity": "critical",
                    "signalConfidence": finding.confidence,
                    "matchedCommand": finding.matchedCommand,
                    "execTargetPath": observation.executablePath
                ]
                if let attribution = self.processTree?.responsibleApp(
                    actorPID: observation.pid,
                    responsiblePID: responsiblePID,
                    resolver: SecCodeResponsibleProcessIdentityResolver.shared
                ) {
                    metadata.merge(attribution.metadata) { current, _ in current }
                }
                self.reportThreat(ESEvent(
                    eventType: .authExec,
                    processPath: observation.executablePath,
                    pid: observation.pid,
                    parentPid: observation.parentPID,
                    filePath: observation.executablePath,
                    decision: .allow,
                    threat: .init(
                        threatName: "Download-to-shell command detected",
                        threatFamily: "lolbin-behavior",
                        metadata: metadata
                    )
                ))
            }
        }
    }

    private func observeCredentialStoreOpen(
        store: CredentialAccessPolicy.Store,
        path: String,
        actorPath: String,
        actorPID: Int32,
        parentPID: Int32,
        responsiblePID: Int32?,
        processIdentity: ProcessInstanceIdentity,
        actorIdentity: TamperActorIdentity
    ) {
        EndpointSecurityClient.healthMetrics.recordCredentialOpenEvaluation()
        let attribution = processTree?.responsibleApp(
            actorPID: actorPID,
            responsiblePID: responsiblePID,
            resolver: SecCodeResponsibleProcessIdentityResolver.shared
        )
        let parentIdentity = parentPID > 1
            ? SecCodeResponsibleProcessIdentityResolver.shared.identity(pid: parentPID, pathHint: nil)
            : nil
        let parentIsValidatedAppleLaunchService = CredentialAccessPolicy.isValidatedAppleLaunchService(
            signingID: parentIdentity?.bundleID,
            isValidatedAppleCode: parentIdentity.map {
                $0.signing == .applePlatform || $0.signing == .appleSigned
            } ?? false
        )
        let chainKey = credentialChainKey(attribution: attribution, actorPID: actorPID)
        let hasRecentKeychainCommand = credentialReportLock.withLock { () -> Bool in
            let now = Date()
            recentKeychainCommands = recentKeychainCommands.filter {
                now.timeIntervalSince($0.value.armedAt) <= 600
            }
            return recentKeychainCommands[chainKey]?.matchesFollowUp(
                chainKey: chainKey,
                processPID: processIdentity.pid,
                processPIDVersion: processIdentity.pidVersion,
                at: now
            ) ?? false
        }
        let finding = CredentialAccessPolicy.findingForOpen(
            path: path,
            responsibleIdentity: attribution?.app.map(Self.credentialIdentity),
            actorIdentityValidated: actorIdentity.isValidIdentitySignature,
            actorIsValidatedApplePlatform: actorIdentity.isPlatformBinary
                && actorIdentity.isValidIdentitySignature,
            actorIsOwnResponsibleProcess: responsiblePID == actorPID,
            actorParentIsLaunchd: parentPID == 1,
            actorParentIsValidatedAppleLaunchService: parentIsValidatedAppleLaunchService,
            actorIsInterpreter: Self.isInterpreter(actorPath),
            hasRecentKeychainCommand: store == .keychain && hasRecentKeychainCommand
        )

        let pendingKeychainRead: KeychainTransferFallbackTracker.PendingRead?
        if store == .keychain, finding?.reason != "keychain_command_correlation" {
            pendingKeychainRead = keychainTransferFallback.recordRead(
                sourcePath: path,
                process: processIdentity,
                at: Date()
            )
        } else {
            pendingKeychainRead = nil
        }
        guard let finding else { return }

        // A plain unvalidated read may be the first half of cp/ditto/manual
        // byte copying. Briefly defer its review item so a following external
        // create/write can replace it with one protected transfer incident.
        if store == .keychain, finding.reason == "credential_store_access" {
            dispatchQueue.asyncAfter(deadline: .now() + 30.1) { [weak self] in
                guard let self,
                      let pendingKeychainRead,
                      self.keychainTransferFallback.hasPendingRead(
                          process: processIdentity,
                          matching: pendingKeychainRead
                      )
                else { return }
                self.keychainTransferFallback.cancel(process: processIdentity)
                self.reportCredentialOpenFinding(
                    finding,
                    path: path,
                    actorPath: actorPath,
                    actorPID: actorPID,
                    parentPID: parentPID,
                    attribution: attribution
                )
            }
            return
        }

        reportCredentialOpenFinding(
            finding,
            path: path,
            actorPath: actorPath,
            actorPID: actorPID,
            parentPID: parentPID,
            attribution: attribution
        )
    }

    private func reportCredentialOpenFinding(
        _ finding: CredentialAccessPolicy.Finding,
        path: String,
        actorPath: String,
        actorPID: Int32,
        parentPID: Int32,
        attribution: ResponsibleAppAttribution?
    ) {

        // High-volume stores may be opened repeatedly. Coalesce at the sensor
        // boundary as well as in Core so a noisy reader cannot flood delivery.
        let key = "\(actorPID)|\(finding.store.rawValue)"
        let now = Date()
        let shouldReport = credentialReportLock.withLock { () -> Bool in
            if let previous = lastCredentialReport[key],
               now.timeIntervalSince(previous) < Self.credentialReportWindow {
                return false
            }
            lastCredentialReport[key] = now
            if lastCredentialReport.count > 1_024 {
                let cutoff = now.addingTimeInterval(-Self.credentialReportWindow)
                lastCredentialReport = lastCredentialReport.filter { $0.value >= cutoff }
            }
            return true
        }
        guard shouldReport else { return }
        EndpointSecurityClient.healthMetrics.recordCredentialOpenFinding()

        var metadata = [
            "reason": finding.reason,
            "rule": finding.reason,
            "ruleTier": finding.tier,
            "detectionKind": "credential-access",
            "signalSeverity": finding.severity,
            "credentialStore": finding.store.rawValue
        ]
        if let attribution {
            metadata.merge(attribution.metadata) { current, _ in current }
        }
        reportThreat(ESEvent(
            eventType: .authOpen,
            processPath: actorPath,
            pid: actorPID,
            parentPid: parentPID,
            filePath: path,
            decision: .allow,
            threat: ESEvent.ThreatContext(
                threatName: finding.title,
                threatFamily: "credential-access",
                metadata: metadata
            )
        ))
    }

    private func verifyPotentialKeychainTransferOnClose(
        destinationPath: String,
        actorPath: String,
        actorPID: Int32,
        parentPID: Int32,
        responsiblePID: Int32?,
        processIdentity: ProcessInstanceIdentity,
        actorIdentity: TamperActorIdentity
    ) {
        guard let pending = keychainTransferFallback.pendingReadForExternalClose(
            destinationPath: destinationPath,
            process: processIdentity,
            at: Date()
        ) else { return }
        guard let sourceSize = fileSize(at: pending.sourcePath),
              let destinationSize = fileSize(at: destinationPath),
              let sourcePrefix = boundedFileSample(at: pending.sourcePath, maximumBytes: 65_536),
              let destinationPrefix = boundedFileSample(at: destinationPath, maximumBytes: 65_536),
              KeychainTransferContentPolicy.isVerifiedTransfer(
                  sourcePrefix: sourcePrefix,
                  sourceSize: sourceSize,
                  destinationPrefix: destinationPrefix,
                  destinationSize: destinationSize
              )
        else { return }
        reportKeychainTransfer(
            sourcePath: pending.sourcePath,
            destinationPath: destinationPath,
            actorPath: actorPath,
            actorPID: actorPID,
            parentPID: parentPID,
            responsiblePID: responsiblePID,
            processIdentity: processIdentity,
            actorIdentity: actorIdentity,
            operation: "verified-close"
        )
    }

    private func reportKeychainTransfer(
        sourcePath: String,
        destinationPath: String,
        actorPath: String,
        actorPID: Int32,
        parentPID: Int32,
        responsiblePID: Int32?,
        processIdentity: ProcessInstanceIdentity,
        actorIdentity: TamperActorIdentity,
        operation: String
    ) {
        keychainTransferFallback.cancel(process: processIdentity)
        guard CredentialAccessPolicy.shouldReportKeychainTransfer(
            sourcePath: sourcePath,
            destinationPath: destinationPath,
            actorIsValidatedApplePlatform: actorIdentity.isPlatformBinary
                && actorIdentity.isValidIdentitySignature,
            actorParentIsLaunchd: parentPID == 1
        ) else { return }
        let attribution = processTree?.responsibleApp(
            actorPID: actorPID,
            responsiblePID: responsiblePID,
            resolver: SecCodeResponsibleProcessIdentityResolver.shared
        )
        let chainKey = credentialChainKey(attribution: attribution, actorPID: actorPID)
        let correlated = credentialReportLock.withLock { () -> Bool in
            let now = Date()
            recentKeychainCommands = recentKeychainCommands.filter {
                now.timeIntervalSince($0.value.armedAt) <= 600
            }
            return recentKeychainCommands[chainKey]?.matchesFollowUp(
                chainKey: chainKey,
                processPID: processIdentity.pid,
                processPIDVersion: processIdentity.pidVersion,
                at: now
            ) ?? false
        }
        let finding = correlated
            ? CredentialAccessPolicy.findingForKeychainCorrelation()
            : CredentialAccessPolicy.findingForKeychainTransfer()
        var metadata = [
            "reason": finding.reason,
            "rule": finding.reason,
            "ruleTier": finding.tier,
            "detectionKind": "credential-access",
            "signalSeverity": finding.severity,
            "credentialStore": finding.store.rawValue,
            "credentialOperation": operation,
            "credentialSource": sourcePath,
            "credentialDestination": destinationPath,
            "deliveryLevel": "interrupt"
        ]
        if let attribution {
            metadata.merge(attribution.metadata) { current, _ in current }
        }
        reportThreat(ESEvent(
            eventType: .authOpen,
            processPath: actorPath,
            pid: actorPID,
            parentPid: parentPID,
            filePath: sourcePath,
            decision: .allow,
            threat: .init(
                threatName: finding.title,
                threatFamily: "credential-access",
                metadata: metadata
            )
        ))
    }

    private func credentialChainKey(
        attribution: ResponsibleAppAttribution?,
        actorPID: Int32
    ) -> String {
        if let app = attribution?.app, let bundleID = app.bundleID {
            // The actor is the final hop (for example osascript, security or
            // codesign). Excluding that leaf lets a prompt and the subsequent
            // keychain read correlate within the same responsible app chain.
            let responsibleChain = attribution?.chain.dropLast().joined(separator: ">") ?? ""
            return "\(app.teamID ?? "")|\(bundleID)|\(responsibleChain)"
        }
        return "pid:\(actorPID)"
    }

    private static func isInterpreter(_ path: String) -> Bool {
        let name = URL(fileURLWithPath: path).lastPathComponent.lowercased()
        return ["sh", "bash", "zsh", "ksh", "fish", "python", "python3", "node", "perl", "ruby", "osascript"].contains(name)
    }

    private static func credentialIdentity(
        _ identity: ResponsibleAppIdentity
    ) -> CredentialAccessPolicy.ValidatedIdentity {
        CredentialAccessPolicy.ValidatedIdentity(
            bundleID: identity.bundleID,
            teamID: identity.signing == .appleSigned ? "APPLE" : identity.teamID,
            signingValidated: identity.signing == .signed
                || identity.signing == .appleSigned
                || identity.signing == .applePlatform,
            isApplePlatform: identity.signing == .applePlatform
        )
    }

    // MARK: - Private Helpers

    private func reportIntegrityViolation(
        at path: String,
        actorPID: Int32? = nil,
        responsiblePID: Int32? = nil
    ) {
        guard let violation = fileIntegrityMonitor?.check(path: path) else { return }
        let attribution = actorPID.flatMap {
            processTree?.responsibleApp(
                actorPID: $0,
                responsiblePID: responsiblePID,
                resolver: SecCodeResponsibleProcessIdentityResolver.shared
            ).metadata
        }
        let attributed = IntegrityViolation(
            id: violation.id,
            path: violation.path,
            violationType: violation.violationType,
            expectedHash: violation.expectedHash,
            actualHash: violation.actualHash,
            timestamp: violation.timestamp,
            metadata: attribution
        )
        guard let data = try? encoder.encode(attributed) else { return }
        xpcServer?.sendIntegrityViolationToApp(data)
    }

    /// Emits detector-confirmed evidence and performs automatic remediation
    /// only for an exact curated signature. Must run on `dispatchQueue`.
    private func reportDetectedThreat(
        _ result: FileScanner.ScanResult,
        processPath: String,
        pid: Int32,
        parentPid: Int32,
        filePath: String,
        processIdentity: ProcessInstanceIdentity?,
        terminateProcess: Bool
    ) {
        let threat = ESEvent(
            eventType: .notifyWrite,
            processPath: processPath,
            pid: pid,
            parentPid: parentPid,
            filePath: filePath,
            decision: .notApplicable,
            threat: ESEvent.ThreatContext(
                sha256: result.hash,
                threatName: result.threatName,
                threatFamily: result.threatFamily
            )
        )
        reportThreat(threat)
        processTree?.markAsThreat(pid: pid)

        // Heuristic/YARA matches are user-review findings. Automated
        // kill/quarantine is reserved for exact curated hash evidence.
        guard result.mayBlock, let engine = remediationEngine else { return }
        let report = engine.remediate(
            threatPath: filePath,
            hash: result.hash,
            threatName: result.threatName ?? "Unknown",
            processPath: processPath,
            pid: pid,
            processIdentity: processIdentity,
            terminateProcess: terminateProcess
        )
        if let data = try? JSONEncoder().encode(report) {
            xpcServer?.sendRemediationToApp(data)
        }
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
        responsiblePID: Int32? = nil,
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
        if let attribution = processTree?.responsibleApp(
            actorPID: pid,
            responsiblePID: responsiblePID,
            resolver: SecCodeResponsibleProcessIdentityResolver.shared
        ) {
            ransomwareMetadata.merge(attribution.metadata) { current, _ in current }
        }
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
        reportThreat(ransomwareEvent)
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

    private static func hasQuarantineOrigin(at path: String) -> Bool {
        path.withCString { filePath in
            "com.apple.quarantine".withCString { attribute in
                getxattr(filePath, attribute, nil, 0, 0, 0) >= 0
            }
        }
    }

    /// Encodes and pushes an `ESEvent` to the container app via XPC.
    /// Called from the ES callback queue; encoding is fast (small struct).
    private func pushEvent(_ event: ESEvent) {
        dispatchQueue.async { [weak self] in
            guard let self, let data = try? self.encoder.encode(event) else { return }
            self.xpcServer?.sendEventToApp(data)
        }
    }

    /// Sends detector-confirmed evidence only through the acknowledged threat
    /// channel. Sending the same event through `reportEvent` first allowed a
    /// notification to race ahead of durable incident persistence and also
    /// made one detection appear twice in the app.
    private func reportThreat(_ event: ESEvent) {
        guard let data = try? encoder.encode(event) else { return }
        xpcServer?.sendThreatToApp(data)
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

    private func fileSize(at path: String) -> UInt64? {
        guard let number = try? FileManager.default.attributesOfItem(atPath: path)[.size]
            as? NSNumber else { return nil }
        return number.uint64Value
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
        // auditToken is retained in the signature for call-site clarity. ES
        // already supplied the identity fields from the kernel; invoking
        // Security.framework here can block an outstanding AUTH response.
        _ = auditToken
        return identity.isValidIdentitySignature
            && identity.teamID == TamperProtectionPolicy.nickTeamID
            && identity.signingID.map(TamperProtectionPolicy.nickMaintenanceSigningIDs.contains) == true
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
            nickUpdateIdentityValidated: identity.isValidIdentitySignature
                && identity.teamID == TamperProtectionPolicy.nickTeamID
                && identity.signingID.map(TamperProtectionPolicy.nickLeasedUpdateSigningIDs.contains) == true
        ) ?? false
    }

    /// Derives the Finder Trash owner only from kernel-authored event values.
    /// Console-user APIs can block and therefore cannot run before an AUTH reply.
    private func callbackSafeConsoleUser(
        destinationPath: String,
        process: es_process_t
    ) -> TamperConsoleUser? {
        let parts = destinationPath.split(separator: "/", omittingEmptySubsequences: true)
        guard parts.count >= 3, parts[0] == "Users", parts[2] == ".Trash" else { return nil }
        return TamperConsoleUser(
            uid: audit_token_to_euid(process.audit_token),
            homeDirectory: "/Users/\(parts[1])"
        )
    }

    private func handleProtectedWriteAuthorization(
        message: UnsafePointer<es_message_t>,
        targetPath: String,
        process: es_process_t,
        processPath: String,
        pid: Int32,
        identity: TamperActorIdentity,
        operation: TamperProtectedOperation
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
        dispatchQueue.async { [weak self] in
            self?.tamperProtection?.handleWriteEvent(
                targetPath: targetPath,
                actorPath: processPath,
                actorPid: pid,
                identity: identity,
                blocked: blocked,
                operation: operation
            )
        }
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
