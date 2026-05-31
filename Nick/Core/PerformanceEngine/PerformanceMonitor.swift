// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation

/// MonitorProtocol conformance that bridges the PerformanceEngine into the Nick monitor pipeline.
@MainActor @Observable
final class PerformanceMonitor: MonitorProtocol {

    // MARK: MonitorProtocol
    let monitorType: MonitorType = .performance
    private(set) var isRunning = false

    // MARK: Public state (forwarded from coordinator)
    var foundItems: [JunkItem] { coordinator.foundItems }
    var scanState: PerformanceScanState { coordinator.scanState }
    private(set) var totalReclaimableBytes: Int64 = 0
    private(set) var lastScanDate: Date?

    let coordinator: PerformanceCoordinator
    private var signals: [ThreatSignal] = []

    init() {
        let auditLogger = AuditLogger()
        let executor = CleanupExecutor(auditLogger: auditLogger)
        let planner = CleanupPlanner()
        let browserDetector = BrowserDetector()

        let rules: [any ScanRule] = [
            CacheRule(),
            DerivedDataRule(),
            SimulatorDataRule(),
            SimulatorRuntimesRule(),
            SwiftPMRule(),
            IOSBackupsRule(),
            DeviceSupportRule(),
            WatchOSDeviceSupportRule(),
            XcodeDocumentationRule(),
            ArchivesRule(),
            HomebrewRule(),
            JavaScriptCacheRule(),
            PythonCacheRule(),
            GradleAndroidCacheRule(),
            ChromeCacheRule(),
            AdobeCacheRule(),
            SteamCacheRule(),
            BrowserCacheRule(),
            LogsRule(),
            InstallersRule(),
            DownloadsRule(),
            TrashRule(),
            LargeForgottenFilesRule(),
            LargeVideoFilesRule(),
            MeetingRecordingsRule(),
            LargeImageExportsRule(),
            OldZipArchivesRule(),
            ScreenRecordingExportsRule(),
            LargeDuplicateFilesRule(),
            AppleSoundLibraryRule(),
            MessagesAttachmentsRule(),
            DockerInsightRule(),
            HugeFoldersInsightRule(),
        ]

        coordinator = PerformanceCoordinator(
            rules: rules,
            executor: executor,
            planner: planner,
            browserDetector: browserDetector,
            auditLogger: auditLogger
        )
    }

    // MARK: MonitorProtocol lifecycle

    func start() async throws {
        isRunning = true
    }

    func stop() async {
        coordinator.cancelScan()
        isRunning = false
    }

    // MARK: ThreatSignalSource

    func latestSignals() async -> [ThreatSignal] {
        guard totalReclaimableBytes > 1_000_000_000 else { return [] }
        return signals
    }

    // MARK: Public API

    func runPerformanceScan() async {
        coordinator.startScan()
        // Wait for scan to complete by polling state
        while coordinator.isScanning {
            try? await Task.sleep(nanoseconds: 500_000_000)
        }
        totalReclaimableBytes = coordinator.totalReclaimableSize
        lastScanDate = Date()

        if totalReclaimableBytes > 1_000_000_000 {
            let gbString = String(format: "%.1f", Double(totalReclaimableBytes) / 1_000_000_000)
            signals = [ThreatSignal(
                source: .performance,
                severity: .low,
                title: "Performance: \(gbString) GB reclaimable",
                description: "Nick found \(coordinator.foundItems.count) junk items totalling \(gbString) GB. Run a cleanup to free space.",
                context: ThreatSignalContext()
            )]
        } else {
            signals = []
        }
    }

    func startCleanup(items: [JunkItem]) {
        coordinator.selectedItemIDs = Set(items.map(\.id))
        coordinator.startCleanup()
    }

    func findItemsForProcess(processPath: String) -> [JunkItem] {
        coordinator.foundItems.filter { $0.url.path.contains(processPath) }
    }
}
