import Foundation
import Darwin
import os

/// All report I/O and process sampling occur off ES callback/worker queues.
/// No verdicts, watchdog scheduling or launch environment are changed here.
final class RuntimeDiagnosticMonitor: @unchecked Sendable {
    private let lock = NSLock()
    private let reportsQueue = DispatchQueue(label: "com.ehsanazish.nick.report-diagnostics", qos: .utility)
    private var warningThread: Thread?
    private var reportsTimer: DispatchSourceTimer?
    private var fields: [String: Any] = ["kernelDeadlineTerminationCount": NSNull(), "kernelDeadlineTerminationStatus": "not-yet-inspected"]
    private var reportCache: [String: (stamp: String, match: EndpointTerminationReport.Match?)] = [:]
    private let previous: [String: Any]?
    private let currentBootSessionUUID = ProtectionBootIdentity.sessionUUID()
    private static let machNanosecondsPerTick: Double = {
        var base = mach_timebase_info_data_t(); mach_timebase_info(&base)
        return Double(base.numer) / Double(base.denom)
    }()
    private static let logger = Logger(subsystem: "com.ehsanazish.nick.NickExtension", category: "RuntimeDiagnostics")
    init(previous: [String: Any]?) { self.previous = previous }
    func start() {
        // A diagnostic observer must not depend on availability of the GCD
        // pool whose starvation is being investigated. Enforcement watchdogs
        // deliberately remain unchanged.
        let warning = Thread { [weak self] in
            while !Thread.current.isCancelled {
                guard self != nil else { return }
                autoreleasepool { self?.sample() }
                Thread.sleep(forTimeInterval: 1)
            }
        }
        warning.name = "Nick pending AUTH diagnostics"
        warning.qualityOfService = .userInitiated
        warningThread = warning; warning.start()
        let reports = DispatchSource.makeTimerSource(queue: reportsQueue)
        reports.schedule(deadline: .now(), repeating: 60, leeway: .seconds(5))
        reports.setEventHandler { [weak self] in autoreleasepool { self?.inspectReports() } }
        reports.resume(); reportsTimer = reports
    }
    deinit { warningThread?.cancel(); reportsTimer?.cancel() }
    private func sample() {
        let now = mach_absolute_time()
        let warnings = EndpointSecurityClient.pendingAuth.warnings(now: now)
        for var record in warnings {
            if let received = record["messageMachTime"] as? UInt64, let deadline = record["deadlineMachTime"] as? UInt64 {
                record["ageMilliseconds"] = Double(now >= received ? now - received : 0) * Self.machNanosecondsPerTick / 1e6
                record["remainingMilliseconds"] = Double(deadline >= now ? deadline - now : 0) * Self.machNanosecondsPerTick / 1e6
            }
            lock.withLock { fields["lastPendingAUTHWarning"] = record }
            if let data = try? JSONSerialization.data(withJSONObject: record, options: [.sortedKeys]),
               let text = String(data: data, encoding: .utf8) {
                Self.logger.fault("AUTH still pending past half deadline window: \(text, privacy: .public)")
            }
        }
        var vm = task_vm_info_data_t()
        var vmCount = mach_msg_type_number_t(MemoryLayout<task_vm_info_data_t>.size / MemoryLayout<integer_t>.size)
        let vmStatus = withUnsafeMutablePointer(to: &vm) { pointer in
            pointer.withMemoryRebound(to: integer_t.self, capacity: Int(vmCount)) {
                task_info(mach_task_self_, task_flavor_t(TASK_VM_INFO), $0, &vmCount)
            }
        }
        if vmStatus == KERN_SUCCESS {
            lock.withLock {
                fields["physicalFootprintBytes"] = vm.phys_footprint
                fields["peakSampledPhysicalFootprintBytes"] = max(fields["peakSampledPhysicalFootprintBytes"] as? UInt64 ?? 0, vm.phys_footprint)
            }
        }
        var task = proc_taskinfo()
        let size = Int32(MemoryLayout<proc_taskinfo>.size)
        if proc_pidinfo(getpid(), PROC_PIDTASKINFO, 0, &task, size) == size {
            lock.withLock {
                fields["residentBytes"] = task.pti_resident_size
                fields["virtualBytes"] = task.pti_virtual_size
                fields["processThreadsSampled"] = task.pti_threadnum
                fields["memorySampledAt"] = Date().timeIntervalSince1970
                let old = fields["peakSampledResidentBytes"] as? UInt64 ?? 0
                fields["peakSampledResidentBytes"] = max(old, task.pti_resident_size)
            }
        }
    }
    func snapshot() -> [String: Any] {
        var result = lock.withLock { fields }
        result["pendingAuthDiagnostics"] = EndpointSecurityClient.pendingAuth.snapshot(now: mach_absolute_time())
        result["scanWorkDiagnostics"] = ScanWorkDiagnostics.shared.snapshot()
        result["allocationLoggingEnvironmentPresent"] = getenv("MallocStackLogging") != nil
        result["allocationLoggingStatus"] = "environment observation only; not proof logging is active; never attaches or changes launch settings"
        result["diagnosticBuildPurpose"] = "trust/create fixes; remaining memory and deadline causes unproven"
        return result
    }
    private func inspectReports() {
        let directory = URL(fileURLWithPath: "/Library/Logs/DiagnosticReports", isDirectory: true)
        var failed = false
        guard let enumerator = FileManager.default.enumerator(at: directory, includingPropertiesForKeys: nil,
            options: [.skipsSubdirectoryDescendants], errorHandler: { _, _ in failed = true; return false }) else {
            lock.withLock { fields["kernelDeadlineTerminationCount"] = NSNull(); fields["kernelDeadlineTerminationStatus"] = "unavailable-directory" }
            return
        }
        var inspected = 0, totalBytes = 0, capped = false
        var matches: [String: EndpointTerminationReport.Match] = [:]
        for case let url as URL in enumerator {
            inspected += 1
            if inspected > 512 { capped = true; break }
            let name = url.lastPathComponent
            guard name.contains("NickExtension"), url.pathExtension == "ips" else { continue }
            let fd = open(url.path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
            guard fd >= 0 else { failed = true; continue }
            defer { close(fd) }
            var st = stat()
            guard fstat(fd, &st) == 0, (st.st_mode & mode_t(S_IFMT)) == mode_t(S_IFREG),
                  st.st_size > 0, st.st_size <= 8 * 1024 * 1024 else { failed = true; continue }
            let stamp = "\(st.st_ino):\(st.st_size):\(st.st_mtimespec.tv_sec):\(st.st_mtimespec.tv_nsec)"
            if let cache = reportCache[name], cache.stamp == stamp {
                if let match = cache.match { matches[match.incidentID] = match }; continue
            }
            if totalBytes + Int(st.st_size) > 16 * 1024 * 1024 { capped = true; break }
            totalBytes += Int(st.st_size)
            var bytes = Data(count: Int(st.st_size))
            let readCount = bytes.withUnsafeMutableBytes { buffer -> Int in
                var offset = 0
                while offset < buffer.count {
                    let n = Darwin.read(fd, buffer.baseAddress!.advanced(by: offset), buffer.count - offset)
                    if n < 0 && errno == EINTR { continue }
                    if n <= 0 { break }
                    offset += n
                }
                return offset
            }
            guard readCount == bytes.count else { failed = true; continue }
            let match = EndpointTerminationReport.parse(bytes)
            if reportCache.count >= 128, reportCache[name] == nil { reportCache.removeAll(keepingCapacity: true) }
            reportCache[name] = (stamp, match)
            if let match { matches[match.incidentID] = match }
        }
        let previousMatch = previous.flatMap { session in matches.values.first { EndpointTerminationReport.matchesPrevious($0, session: session) } }
        lock.withLock {
            fields["kernelDeadlineTerminationCount"] = failed || capped ? NSNull() : matches.count
            fields["kernelDeadlineTerminationReportsObserved"] = matches.count
            fields["kernelDeadlineTerminationStatus"] = failed ? "partial-unreadable-reports" : capped ? "partial-bounded-inspection" : "inspected-available-reports"
            fields["kernelDeadlineTerminationScope"] = "deduplicated matching IPS reports in bounded directory inspection; missing reports cannot prove zero kills"
            fields["terminationReportsInspectedAt"] = Date().timeIntervalSince1970
            fields["terminationReportBytesReadThisPass"] = totalBytes
            if let previousMatch {
                if previous?["bootSessionUUID"] as? String == currentBootSessionUUID {
                    fields["previousSessionTransition"] = "endpointsecurity-deadline-confirmed-by-ips"
                }
                fields["previousKernelDeadlineReportID"] = previousMatch.incidentID
                fields["previousKernelDeadlineCapturedAt"] = previousMatch.captured.timeIntervalSince1970
            }
        }
    }
}
