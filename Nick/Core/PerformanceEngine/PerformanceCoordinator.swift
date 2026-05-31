// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation

/// Orchestrates parallel rule scanning and cleanup.
@MainActor @Observable
final class PerformanceCoordinator {

    private(set) var scanState: PerformanceScanState = .idle
    private(set) var foundItems: [JunkItem] = []
    private(set) var totalReclaimableSize: Int64 = 0
    var selectedItemIDs: Set<UUID> = []

    var isScanning: Bool {
        if case .scanning = scanState { return true }
        return false
    }

    private let rules: [any ScanRule]
    private let executor: CleanupExecutor
    private let planner: CleanupPlanner
    private let browserDetector: BrowserDetector
    private let auditLogger: AuditLogger
    private var scanTask: Task<Void, Never>?

    init(rules: [any ScanRule],
         executor: CleanupExecutor,
         planner: CleanupPlanner,
         browserDetector: BrowserDetector,
         auditLogger: AuditLogger) {
        self.rules = rules
        self.executor = executor
        self.planner = planner
        self.browserDetector = browserDetector
        self.auditLogger = auditLogger
    }

    func startScan() {
        guard !isScanning else { return }
        scanTask?.cancel()
        foundItems = []
        totalReclaimableSize = 0
        selectedItemIDs = []

        scanTask = Task {
            scanState = .scanning(progress: 0, currentCategory: nil)
            var allItems: [JunkItem] = []
            let ruleCount = rules.count

            await withTaskGroup(of: [JunkItem].self) { group in
                for (index, rule) in rules.enumerated() {
                    group.addTask {
                        return await rule.scan()
                    }
                    _ = index // suppress warning
                }
                var completed = 0
                for await batch in group {
                    guard !Task.isCancelled else { break }
                    allItems.append(contentsOf: batch)
                    completed += 1
                    let progress = Double(completed) / Double(ruleCount)
                    let currentCategory = batch.first?.category
                    scanState = .scanning(progress: progress, currentCategory: currentCategory?.displayName)
                }
            }

            guard !Task.isCancelled else {
                scanState = .idle
                return
            }

            foundItems = allItems.sorted { $0.size > $1.size }
            totalReclaimableSize = foundItems.reduce(0) { $0 + $1.size }
            // Auto-select safe items
            selectedItemIDs = Set(foundItems.filter { $0.riskLevel == .safe }.map(\.id))
            scanState = .readyToClean(totalSize: totalReclaimableSize, itemCount: foundItems.count)
        }
    }

    func cancelScan() {
        scanTask?.cancel()
        scanTask = nil
        scanState = .idle
    }

    func startCleanup() {
        guard case .readyToClean = scanState else { return }
        Task {
            let plan = planner.plan(from: foundItems, selectedIDs: selectedItemIDs)
            guard plan.itemsToClean.isEmpty == false else { return }
            let runningBrowsers = await browserDetector.runningBrowsers()
            scanState = .cleaning(progress: 0, freedSize: 0)
            try? await executor.execute(plan, runningBrowsers: runningBrowsers)
            let freed = executor.freedBytes
            let count = plan.itemsToClean.count
            // Remove cleaned items from foundItems
            let cleanedIDs = Set(plan.itemsToClean.map(\.id))
            foundItems.removeAll { cleanedIDs.contains($0.id) }
            totalReclaimableSize = foundItems.reduce(0) { $0 + $1.size }
            scanState = .completed(freedSize: freed, itemCount: count)
        }
    }
}
