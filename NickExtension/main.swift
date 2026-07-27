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
    let fullDiskAccessReady: Bool = {
        guard let handle = FileHandle(
            forReadingAtPath: "/Library/Application Support/com.apple.TCC/TCC.db"
        ) else {
            return false
        }
        try? handle.close()
        return true
    }()
    let health: [String: Any] = [
        "active": true,
        "updatedAt": Date().timeIntervalSince1970,
        "version": Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? "unknown",
        "emailGuardActive": true,
        // Bundled, compiled YARA rules provide the offline day-one scanner.
        // Hash signatures are an additional layer, not a prerequisite that
        // would leave a fresh installation permanently degraded.
        "emailScannerReady": yaraRulesReady,
        "yaraRulesReady": yaraRulesReady,
        "signatureCount": signatureDB.count,
        "fullDiskAccessReady": fullDiskAccessReady,
        "fimBaselineCount": fileIntegrityMonitor.baselineCount,
        "canaryCount": ransomwareDetector.canaryManager.canaryPaths.count
    ]

    do {
        try FileManager.default.createDirectory(
            atPath: supportDir,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o755]
        )
        let data = try JSONSerialization.data(withJSONObject: health, options: [.sortedKeys])
        try data.write(to: URL(fileURLWithPath: healthPath), options: .atomic)
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o644],
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
// Expose quarantine operations to the app's Quarantine view.
ESXPCServer.quarantineManagerRef = quarantineManager
ESXPCServer.fileScannerRef = fileScanner

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
    ES_EVENT_TYPE_AUTH_RENAME,       // protect Nick files from replacement
    ES_EVENT_TYPE_AUTH_UNLINK,       // protect Nick files from deletion

    // --- NOTIFY (observational) ---
    ES_EVENT_TYPE_NOTIFY_CLOSE,      // one bounded check after a modified file closes
    ES_EVENT_TYPE_NOTIFY_RENAME,     // invalidate cache on rename
    ES_EVENT_TYPE_NOTIFY_UNLINK,     // invalidate cache on delete
    ES_EVENT_TYPE_NOTIFY_FORK,       // process lifecycle
    ES_EVENT_TYPE_NOTIFY_EXIT,       // process lifecycle

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
let healthTimer = DispatchSource.makeTimerSource(queue: .global(qos: .utility))
healthTimer.schedule(deadline: .now() + 10, repeating: 10)
healthTimer.setEventHandler(handler: writeExtensionHealth)
healthTimer.resume()

logger.info("NickExtension Phase 5 running — privacy monitoring, USB scanning, network filter active")
xpcServer.sendStatusChange(isActive: true)

// Block the main thread indefinitely
dispatchMain()
