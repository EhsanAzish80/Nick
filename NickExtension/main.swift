// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import EndpointSecurity
import Foundation
import os

// MARK: - Extension Entry Point

private let logger = Logger(
    subsystem: "com.ehsanazish.nick.NickExtension",
    category: "Main"
)

// MARK: Phase 2 — Scanner stack

let supportDir   = "/Library/Application Support/com.ehsanazish.nick"
let healthPath   = (supportDir as NSString).appendingPathComponent("extension_health.json")
let signatureDB  = SignatureDatabase()
let scanCache    = ScanCache()

/// Publishes a deliberately short-lived proof that the Endpoint Security client
/// is running. The container app treats this as stale after 30 seconds, so a
/// crashed or stopped extension can never leave Smart Scan falsely green.
func writeExtensionHealth() {
    let esMetrics = EndpointSecurityClient.healthMetrics.snapshot()
    let fullDiskAccessReady: Bool = {
        guard let handle = FileHandle(
            forReadingAtPath: "/Library/Application Support/com.apple.TCC/TCC.db"
        ) else {
            return false
        }
        try? handle.close()
        return true
    }()
    var health: [String: Any] = [
        "active": true,
        "xpcListener": xpcServer.listenerConfigurationStatus,
        "updatedAt": Date().timeIntervalSince1970,
        "version": Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? "unknown",
        "emailGuardActive": true,
        // Bundled, compiled YARA rules provide the offline day-one scanner.
        // Hash signatures are an additional layer, not a prerequisite that
        // would leave a fresh installation permanently degraded.
        "emailScannerReady": yaraRulesReady,
        "yaraRulesReady": yaraRulesReady,
        "signatureCount": signatureDB.count,
        "signatureCatalogEntries": signatureDB.bundledCatalogEntryCount,
        "signatureCatalogDate": signatureDB.bundledCatalogRetrievedAt ?? "unavailable",
        "fullDiskAccessReady": fullDiskAccessReady,
        "fimBaselineCount": fileIntegrityMonitor.baselineCount,
        "fimPendingViolationCount": fileIntegrityMonitor.pendingViolationCount,
        "canaryCount": ransomwareDetector.canaryManager.canaryPaths.count,
        "eventsPerSecond": esMetrics.eventsPerSecond,
        "deadlineMissCount": esMetrics.deadlineMisses,
        "credentialOpenEvaluationCount": esMetrics.credentialOpenEvaluations,
        "credentialOpenFindingCount": esMetrics.credentialOpenFindings
    ]
    if let lastDeadlineMissAt = esMetrics.lastDeadlineMissAt {
        health["lastDeadlineMissAt"] = lastDeadlineMissAt.timeIntervalSince1970
    }
    if let p50 = esMetrics.authResponseP50Milliseconds {
        health["authResponseP50Milliseconds"] = p50
    }
    if let p99 = esMetrics.authResponseP99Milliseconds {
        health["authResponseP99Milliseconds"] = p99
    }

    do {
        try FileManager.default.createDirectory(
            atPath: supportDir,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o755]
        )
        let data = try JSONSerialization.data(withJSONObject: health, options: [.sortedKeys])
        try data.write(to: URL(fileURLWithPath: healthPath), options: .atomic)
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o600],
            ofItemAtPath: healthPath
        )
    } catch {
        logger.error("Could not publish extension health: \(error.localizedDescription, privacy: .public)")
    }
}

// Prefer rules copied into the system extension itself. macOS relocates an
// activated system extension, so its original host-app-relative path is not
// reliable after installation.
let appRulesDir: String = {
    let bundledRules = Bundle.main.resourceURL?
        .appendingPathComponent("Rules", isDirectory: true).path
    if let bundledRules,
       FileManager.default.fileExists(atPath: bundledRules) {
        return bundledRules
    }

    // Development fallback while running from the product inside Nick.app.
    let extBundle = Bundle.main.bundleURL
        .deletingLastPathComponent()  // SystemExtensions/
        .deletingLastPathComponent()  // Library/
        .deletingLastPathComponent()  // Contents/
        .appendingPathComponent("Resources/Rules")
        .path
    // Fall back to support dir if the app bundle path isn't accessible.
    return FileManager.default.fileExists(atPath: extBundle) ? extBundle : supportDir + "/Rules"
}()

let yaraSetup: (engine: YARAEngine?, rulesReady: Bool) = {
    do {
        let engine = try YARAEngine(rulesDirectory: appRulesDir)
        // Compile once during extension startup. Merely constructing the
        // engine does not prove the bundled rules are valid.
        try engine.reloadRules()
        logger.info("YARAEngine ready — rules directory: \(appRulesDir, privacy: .public)")
        return (engine, true)
    } catch {
        logger.error("YARAEngine init failed — YARA scanning disabled: \(error.localizedDescription, privacy: .public)")
        return (nil, false)
    }
}()
let yaraEngine = yaraSetup.engine
let yaraRulesReady = yaraSetup.rulesReady

let signedIntelligenceStore = SignedThreatIntelligenceBundleStore(
    directory: ThreatIntelligenceBundleTrustAnchor.productionDirectory,
    publicKey: ThreatIntelligenceBundleTrustAnchor.productionPublicKey,
    updatesEnabled: ThreatIntelligenceBundleTrustAnchor.updatesEnabled
)
let signedRules = signedIntelligenceStore.loadBestAvailable()?.0.rules ?? []
let strictBlockingPolicy = StrictBlockingPolicy(signedRules: signedRules)
let fileScanner = FileScanner(
    signatureDB: signatureDB,
    cache: scanCache,
    yaraEngine: yaraEngine,
    strictBlockingPolicy: strictBlockingPolicy
)

logger.info("Signature database ready — \(signatureDB.count) signature(s) loaded")

// MARK: Phase 3 — Quarantine, Remediation, FIM

let quarantineManager    = QuarantineManager(supportDir: supportDir)
let remediationEngine    = RemediationEngine(quarantineManager: quarantineManager)

let fimBaselinePath      = (supportDir as NSString).appendingPathComponent("fim_baseline.json")
let fimPendingPath       = (supportDir as NSString).appendingPathComponent("fim_pending.json")
let fileIntegrityMonitor = FileIntegrityMonitor(
    baselinePath: fimBaselinePath,
    pendingViolationsPath: fimPendingPath
)

// Build FIM baseline on first run (baseline file absent means first launch)
if !FileManager.default.fileExists(atPath: fimBaselinePath) {
    logger.info("Building FIM baseline for the first time…")
    fileIntegrityMonitor.buildBaseline()
}

// MARK: Phase 4 — Advanced Detection

let behaviorTracker    = BehaviorTracker()
let ransomwareDetector = RansomwareDetector(behaviorTracker: behaviorTracker)

// Plant canary files in common user directories
ransomwareDetector.canaryManager.deployCanaries()

// MARK: Phase 5 — Privacy & USB protection

let privacyGuard = PrivacyGuard()
let usbScanner   = USBScanner(fileScanner: fileScanner)

// MARK: Phase 6 — genealogy and self-protection

let processTree = ProcessTree()
let tamperProtection = TamperProtection()
let updateLeaseManager = NickUpdateLeaseManager()
let protectionContinuityLedger = ProtectionContinuityLedger(
    url: URL(fileURLWithPath: supportDir + "/state/protection-continuity.json")
)
let intentionalAppExitRegistry = IntentionalAppExitRegistry()

// MARK: Phase 6 — Email attachment monitoring

let emailAttachmentMonitor = EmailAttachmentMonitor()

// MARK: Object graph

let eventHandler = ESEventHandler()
let xpcServer    = ESXPCServer()
let esClient     = EndpointSecurityClient(eventHandler: eventHandler)

strictBlockingPolicy.update(settingsRecord: xpcServer.currentSecuritySettingsRecord())
xpcServer.securitySettingsDidChange = { record in
    strictBlockingPolicy.update(settingsRecord: record)
    scanCache.invalidateAll()
}
xpcServer.threatIntelligenceBundleInstaller = { data in
    do {
        _ = try signedIntelligenceStore.stageAndPromote(data) { payload in
            payload.hashes.count <= 100_000
                && payload.domains.count <= 100_000
                && payload.ipAddresses.count <= 100_000
                && payload.rules.count <= 10_000
        }
        signatureDB.reloadSignedThreatBundle()
        if let payload = signedIntelligenceStore.loadBestAvailable()?.0 {
            strictBlockingPolicy.update(signedRules: payload.rules)
        }
        scanCache.invalidateAll()
        return true
    } catch {
        logger.error("Rejected threat-intelligence bundle: \(error.localizedDescription, privacy: .public)")
        return false
    }
}

// Wire cross-references
eventHandler.xpcServer               = xpcServer
eventHandler.esClient                = esClient
eventHandler.fileScanner             = fileScanner
eventHandler.remediationEngine       = remediationEngine
eventHandler.fileIntegrityMonitor    = fileIntegrityMonitor
eventHandler.behaviorTracker         = behaviorTracker
eventHandler.ransomwareDetector      = ransomwareDetector
eventHandler.privacyGuard            = privacyGuard
eventHandler.usbScanner              = usbScanner
eventHandler.processTree             = processTree
eventHandler.emailAttachmentMonitor  = emailAttachmentMonitor
eventHandler.tamperProtection        = tamperProtection
eventHandler.updateLeaseManager      = updateLeaseManager
eventHandler.intentionalAppExitRegistry = intentionalAppExitRegistry
xpcServer.updateLeaseManager         = updateLeaseManager
ESXPCServer.protectionContinuityLedgerRef = protectionContinuityLedger
ESXPCServer.intentionalAppExitRegistryRef = intentionalAppExitRegistry

if let continuityIncident = protectionContinuityLedger.evaluateStart(
    now: Date(),
    bootSessionUUID: ProtectionBootIdentity.sessionUUID(),
    bootTime: ProtectionBootIdentity.bootTime()
) {
    let isGap = continuityIncident.kind == .interrupted
    var metadata: [String: String] = [
        "trust": "root-observed",
        "endedAt": ISO8601DateFormatter().string(from: continuityIncident.endedAt),
        "unobservedWindow": isGap ? "true" : "false",
        "ruleTier": isGap ? "protected" : "review"
    ]
    if let startedAt = continuityIncident.startedAt {
        metadata["startedAt"] = ISO8601DateFormatter().string(from: startedAt)
    }
    if !continuityIncident.appObservations.isEmpty {
        metadata["appObserved"] = "true"
        metadata["appObservationCount"] = String(continuityIncident.appObservations.count)
    }
    let event = ESEvent(
        eventType: .notifyWrite,
        processPath: Bundle.main.executableURL?.path ?? "",
        pid: 0,
        parentPid: 0,
        filePath: nil,
        decision: .notApplicable,
        threat: .init(
            threatName: isGap ? "Protection interrupted" : "Protection resumed after restart",
            threatFamily: "protection-continuity",
            metadata: metadata
        )
    )
    if let data = try? JSONEncoder().encode(event) { xpcServer.sendThreatToApp(data) }
}

updateLeaseManager.onAudit = { audit in
    let event = ESEvent(
        eventType: .notifyWrite,
        processPath: Bundle.main.executableURL?.path ?? "",
        pid: 0,
        parentPid: 0,
        filePath: "/Applications/Nick.app",
        decision: .notApplicable,
        threat: .init(
            threatName: "Nick update authorization \(audit.action.rawValue)",
            threatFamily: "nick-update-lease",
            metadata: [
                "leaseID": audit.leaseID?.uuidString ?? "none",
                "detail": audit.detail
            ]
        )
    )
    if let data = try? JSONEncoder().encode(event) {
        xpcServer.sendThreatToApp(data)
    }
}

tamperProtection.onTamperAttempt = { attempt in
    let event: ESEvent
    switch attempt {
    case .deleteProtectedPath(let path, let pid, let actorPath, let identity, let disposition, let operation):
        let attribution = processTree.responsibleApp(
            actorPID: pid, responsiblePID: nil,
            resolver: SecCodeResponsibleProcessIdentityResolver.shared
        )
        event = ESEvent(
            eventType: .notifyWrite,
            processPath: actorPath,
            pid: pid,
            parentPid: 0,
            filePath: path,
            decision: disposition == .blocked ? .deny : .allow,
            threat: .init(
                threatName: disposition == .blocked
                    ? "Nick protected path change blocked"
                    : "Nick maintenance updated protected files",
                threatFamily: disposition == .blocked ? "tamper" : "nick-maintenance",
                isCodeSigned: identity.isValidIdentitySignature,
                teamID: identity.teamID,
                signingID: identity.signingID,
                metadata: [
                    "tamperOperation": operation.rawValue,
                    "tamperTarget": path
                ].merging(attribution.metadata) { current, _ in current }
            )
        )
    case .renameProtectedPath(let path, let pid, let actorPath, let identity, let disposition, let operation):
        let isDocumentedUninstall = disposition == .documentedUninstall
        let attribution = processTree.responsibleApp(
            actorPID: pid, responsiblePID: nil,
            resolver: SecCodeResponsibleProcessIdentityResolver.shared
        )
        event = ESEvent(
            eventType: .notifyWrite,
            processPath: actorPath,
            pid: pid,
            parentPid: 0,
            filePath: path,
            decision: disposition == .blocked ? .deny : .allow,
            threat: .init(
                threatName: disposition == .blocked
                    ? "Nick protected path change blocked"
                    : (isDocumentedUninstall
                        ? "Nick is being moved to the Trash"
                        : "Nick maintenance updated protected files"),
                threatFamily: disposition == .blocked
                    ? "tamper"
                    : (isDocumentedUninstall ? "nick-documented-uninstall" : "nick-maintenance"),
                isCodeSigned: identity.isValidIdentitySignature,
                teamID: identity.teamID,
                signingID: identity.signingID,
                metadata: [
                    "tamperOperation": operation.rawValue,
                    "tamperTarget": path
                ].merging(attribution.metadata) { current, _ in current }
            )
        )
    case .systemExtensionsCtlExec(let pid, let isSensitive):
        let attribution = processTree.responsibleApp(
            actorPID: pid, responsiblePID: nil,
            resolver: SecCodeResponsibleProcessIdentityResolver.shared
        )
        event = ESEvent(
            eventType: .authExec,
            processPath: "/usr/bin/systemextensionsctl",
            pid: pid,
            parentPid: 0,
            decision: .notApplicable,
            threat: .init(
                threatName: isSensitive
                    ? "System extension removal command observed"
                    : "System extension management observed",
                threatFamily: isSensitive ? "tamper" : "endpoint-management",
                metadata: attribution.metadata
            )
        )
    }
    if let data = try? JSONEncoder().encode(event) {
        xpcServer.sendThreatToApp(data)
    }
}

// Wire USB threat callback through XPC
usbScanner.onThreatFound = { threat in
    if let data = try? JSONEncoder().encode(threat) {
        xpcServer.sendUSBThreatToApp(data)
    }
}

// Expose FIM monitor for on-demand baseline rebuilds (Phase 5)
ESXPCServer.fimMonitorRef = fileIntegrityMonitor
// Expose ransomware detector for on-demand canary deployment from Smart Scan
ESXPCServer.ransomwareDetectorRef = ransomwareDetector
// Expose quarantine operations to the app's Quarantine view.
ESXPCServer.quarantineManagerRef = quarantineManager
ESXPCServer.fileScannerRef = fileScanner
quarantineManager.onReviewedFileSwap = { path in
    let event = ESEvent(
        eventType: .notifyWrite,
        processPath: "",
        pid: 0,
        parentPid: 0,
        filePath: path,
        decision: .notApplicable,
        threat: .init(
            threatName: "Quarantine target changed during review",
            threatFamily: "tamper"
        )
    )
    if let data = try? JSONEncoder().encode(event) {
        xpcServer.sendThreatToApp(data)
    }
}

// Start XPC listener first — container app can connect as soon as the extension launches
xpcServer.start()

// Initialise the ES client
guard esClient.start() else {
    logger.critical("Failed to create ES client — missing entitlement or SIP interference")
    xpcServer.sendStatusChange(isActive: false)
    exit(EXIT_FAILURE)
}

// MARK: Phase 2–4 — Event subscriptions
//
// AUTH events  → block until NickExtension responds (process/operation suspended)
// NOTIFY events → informational; NickExtension observes but cannot block
let phase4Events: [es_event_type_t] = [
    // --- AUTH (blocking) ---
    ES_EVENT_TYPE_AUTH_EXEC,         // block malicious binary execution
    ES_EVENT_TYPE_AUTH_OPEN,         // block opening a previously scanned threat
    ES_EVENT_TYPE_AUTH_MMAP,         // block mapping a previously scanned threat
    ES_EVENT_TYPE_AUTH_COPYFILE,     // block copying a previously scanned threat
    ES_EVENT_TYPE_AUTH_CREATE,       // block suspicious creation chains
    ES_EVENT_TYPE_AUTH_TRUNCATE,     // protect Nick bundle files from truncation
    ES_EVENT_TYPE_AUTH_LINK,         // protect Nick bundle destinations from hard links
    ES_EVENT_TYPE_AUTH_CLONE,        // protect Nick bundle destinations from clones
    ES_EVENT_TYPE_AUTH_RENAME,       // protect Nick files from replacement
    ES_EVENT_TYPE_AUTH_UNLINK,       // protect Nick files from deletion
    ES_EVENT_TYPE_AUTH_SIGNAL,       // protect Nick processes from termination/suspension

    // --- NOTIFY (observational) ---
    ES_EVENT_TYPE_NOTIFY_CLOSE,      // one bounded check after a modified file closes
    ES_EVENT_TYPE_NOTIFY_RENAME,     // invalidate cache on rename
    ES_EVENT_TYPE_NOTIFY_UNLINK,     // invalidate cache on delete
    ES_EVENT_TYPE_NOTIFY_FORK,       // process lifecycle
    ES_EVENT_TYPE_NOTIFY_EXIT,       // process lifecycle
    ES_EVENT_TYPE_NOTIFY_SIGNAL,     // retain allowed killer/sender context

    // --- Apple security signals ---
    ES_EVENT_TYPE_NOTIFY_XP_MALWARE_DETECTED,
    ES_EVENT_TYPE_NOTIFY_XP_MALWARE_REMEDIATED,
    ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD,
    ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_REMOVE,
    ES_EVENT_TYPE_NOTIFY_GATEKEEPER_USER_OVERRIDE,

    // --- Phase 5: Network & Privacy ---
    ES_EVENT_TYPE_NOTIFY_MOUNT,      // external volume mounted → USB scan
    ES_EVENT_TYPE_NOTIFY_UNMOUNT,    // stop scanning media after it is removed
    ES_EVENT_TYPE_NOTIFY_TCC_MODIFY, // TCC permission changed → privacy alert
]

guard esClient.subscribe(to: phase4Events) else {
    logger.critical("Failed to subscribe to ES events")
    xpcServer.sendStatusChange(isActive: false)
    exit(EXIT_FAILURE)
}

// MARK: Mute high-volume trusted paths (reduces noise ~80%)
MuteManager.applyMutes(to: esClient)

writeExtensionHealth()
_ = protectionContinuityLedger.recordHeartbeat(
    now: Date(), bootSessionUUID: ProtectionBootIdentity.sessionUUID()
)
let healthTimer = DispatchSource.makeTimerSource(queue: .global(qos: .utility))
healthTimer.schedule(deadline: .now() + 10, repeating: 10)
healthTimer.setEventHandler(handler: writeExtensionHealth)
healthTimer.resume()

let continuityHeartbeatTimer = DispatchSource.makeTimerSource(queue: .global(qos: .utility))
continuityHeartbeatTimer.schedule(deadline: .now() + 45, repeating: 45)
continuityHeartbeatTimer.setEventHandler {
    _ = protectionContinuityLedger.recordHeartbeat(
        now: Date(), bootSessionUUID: ProtectionBootIdentity.sessionUUID()
    )
}
continuityHeartbeatTimer.resume()

let processTreeTimer = DispatchSource.makeTimerSource(queue: .global(qos: .utility))
processTreeTimer.schedule(deadline: .now() + 3600, repeating: 3600)
processTreeTimer.setEventHandler { processTree.pruneExited() }
processTreeTimer.resume()

logger.info("NickExtension Phase 5 running — privacy monitoring, USB scanning, network filter active")
xpcServer.sendStatusChange(isActive: true)

// Block the main thread indefinitely
dispatchMain()
