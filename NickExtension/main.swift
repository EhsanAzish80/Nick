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
let signatureDB  = SignatureDatabase()
let scanCache    = ScanCache()

// Resolve the Rules directory from the host app bundle (NickExtension is nested
// 3 levels inside Nick.app: .../Nick.app/Contents/Library/SystemExtensions/NickExtension.systemextension/).
let appRulesDir: String = {
    let extBundle = Bundle.main.bundleURL
        .deletingLastPathComponent()  // SystemExtensions/
        .deletingLastPathComponent()  // Library/
        .deletingLastPathComponent()  // Contents/
        .appendingPathComponent("Resources/Rules")
        .path
    // Fall back to support dir if the app bundle path isn't accessible.
    return FileManager.default.fileExists(atPath: extBundle) ? extBundle : supportDir + "/Rules"
}()

let yaraEngine: YARAEngine? = {
    do {
        let engine = try YARAEngine(rulesDirectory: appRulesDir)
        logger.info("YARAEngine ready — rules directory: \(appRulesDir, privacy: .public)")
        return engine
    } catch {
        logger.error("YARAEngine init failed — YARA scanning disabled: \(error.localizedDescription, privacy: .public)")
        return nil
    }
}()

let fileScanner  = FileScanner(signatureDB: signatureDB, cache: scanCache, yaraEngine: yaraEngine)

logger.info("Signature database ready — \(signatureDB.count) signature(s) loaded")

// MARK: Phase 3 — Quarantine, Remediation, FIM

let quarantineManager    = QuarantineManager(supportDir: supportDir)
let remediationEngine    = RemediationEngine(quarantineManager: quarantineManager)

let fimBaselinePath      = (supportDir as NSString).appendingPathComponent("fim_baseline.json")
let fileIntegrityMonitor = FileIntegrityMonitor(baselinePath: fimBaselinePath)

// Build FIM baseline on first run (baseline file absent means first launch)
if !FileManager.default.fileExists(atPath: fimBaselinePath) {
    logger.info("Building FIM baseline for the first time…")
    fileIntegrityMonitor.buildBaseline()
}

// MARK: Phase 4 — Advanced Detection

let behaviorTracker    = BehaviorTracker()
let threatPredictor    = ThreatPredictor()
let ransomwareDetector = RansomwareDetector(behaviorTracker: behaviorTracker)

// Plant canary files in common user directories
ransomwareDetector.canaryManager.deployCanaries()

// MARK: Phase 5 — Privacy & USB protection

let privacyGuard = PrivacyGuard()
let usbScanner   = USBScanner(fileScanner: fileScanner)

// MARK: Phase 6 — Email attachment monitoring

let emailAttachmentMonitor = EmailAttachmentMonitor()

// MARK: Object graph

let eventHandler = ESEventHandler()
let xpcServer    = ESXPCServer()
let esClient     = EndpointSecurityClient(eventHandler: eventHandler)

// Wire cross-references
eventHandler.xpcServer               = xpcServer
eventHandler.esClient                = esClient
eventHandler.fileScanner             = fileScanner
eventHandler.remediationEngine       = remediationEngine
eventHandler.fileIntegrityMonitor    = fileIntegrityMonitor
eventHandler.behaviorTracker         = behaviorTracker
eventHandler.threatPredictor         = threatPredictor
eventHandler.ransomwareDetector      = ransomwareDetector
eventHandler.privacyGuard            = privacyGuard
eventHandler.usbScanner              = usbScanner
eventHandler.emailAttachmentMonitor  = emailAttachmentMonitor

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
    ES_EVENT_TYPE_AUTH_OPEN,         // block access to cached-threat files
    ES_EVENT_TYPE_AUTH_CREATE,       // heuristic block on suspicious creation
    ES_EVENT_TYPE_AUTH_MMAP,         // block mapping of cached-threat binaries
    ES_EVENT_TYPE_AUTH_COPYFILE,     // block copying of cached-threat files

    // --- NOTIFY (observational) ---
    ES_EVENT_TYPE_NOTIFY_CLOSE,      // scan file after write completes
    ES_EVENT_TYPE_NOTIFY_WRITE,      // log file writes
    ES_EVENT_TYPE_NOTIFY_RENAME,     // invalidate cache on rename
    ES_EVENT_TYPE_NOTIFY_UNLINK,     // invalidate cache on delete
    ES_EVENT_TYPE_NOTIFY_FORK,       // process lifecycle
    ES_EVENT_TYPE_NOTIFY_EXIT,       // process lifecycle

    // --- Phase 5: Network & Privacy ---
    ES_EVENT_TYPE_NOTIFY_MOUNT,      // external volume mounted → USB scan
    ES_EVENT_TYPE_NOTIFY_TCC_MODIFY, // TCC permission changed → privacy alert
]

guard esClient.subscribe(to: phase4Events) else {
    logger.critical("Failed to subscribe to ES events")
    xpcServer.sendStatusChange(isActive: false)
    exit(EXIT_FAILURE)
}

// MARK: Mute high-volume trusted paths (reduces noise ~80%)
MuteManager.applyMutes(to: esClient)

logger.info("NickExtension Phase 5 running — privacy monitoring, USB scanning, network filter active")
xpcServer.sendStatusChange(isActive: true)

// Block the main thread indefinitely
dispatchMain()
