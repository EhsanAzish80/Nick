import Foundation
import CryptoKit
import Darwin

/// No ES pointers, paths, arguments or credentials retained. The callback only
/// changes bounded scalar state; snapshots and warning selection run elsewhere.
final class PendingAuthDiagnostics: @unchecked Sendable {
    struct Key: Hashable, Sendable { let address: UInt64; let machTime: UInt64 }
    enum Phase: String, Sendable { case callback, credentialValidation, prelaunchHash, workerClaimed, watchdogClaimed, responseAPI, responseFailed }
    struct ResponseContext: Sendable {
        let callbackMachTime: UInt64?
        let phaseBeforeResponse: Phase
    }
    private struct Entry {
        let event: UInt32; let received: UInt64; let deadline: UInt64
        let callbackMachTime: UInt64?
        var phase: Phase = .callback
        var attempts = 0
        var warned = false
    }
    private let lock = NSLock()
    private var entries: [Key: Entry] = [:]
    private var overflow: UInt64 = 0, duplicateAttempts: UInt64 = 0, failedResponses: UInt64 = 0, retryAttempts: UInt64 = 0
    private var peak = 0
    let capacity: Int
    init(capacity: Int = 4096) { precondition(capacity > 0); self.capacity = capacity }
    func received(_ key: Key, event: UInt32, deadline: UInt64, callbackMachTime: UInt64? = nil) {
        lock.withLock {
            guard entries[key] == nil else { return }
            guard entries.count < capacity else { overflow &+= 1; return }
            entries[key] = Entry(event: event, received: key.machTime, deadline: deadline,
                                 callbackMachTime: callbackMachTime)
            peak = max(peak, entries.count)
        }
    }
    func phase(_ key: Key, _ phase: Phase) { lock.withLock { entries[key]?.phase = phase } }
    @discardableResult
    func responseStarted(_ key: Key, isRetry: Bool = false) -> ResponseContext? {
        lock.withLock {
            guard var entry = entries[key] else { return nil }
            let context = ResponseContext(callbackMachTime: entry.callbackMachTime, phaseBeforeResponse: entry.phase)
            if isRetry { retryAttempts &+= 1 }
            else if entry.attempts > 0 { duplicateAttempts &+= 1 }
            entry.attempts += 1; entry.phase = .responseAPI; entries[key] = entry
            return context
        }
    }
    func responseReturned(_ key: Key, accepted: Bool) {
        lock.withLock {
            if accepted { entries.removeValue(forKey: key) }
            else { failedResponses &+= 1; entries[key]?.phase = .responseFailed }
        }
    }
    /// At most eight new fault records per tick. Crossing half the kernel
    /// message-to-deadline window is a warning, never a verdict change.
    func warnings(now: UInt64, limit: Int = 8) -> [[String: Any]] {
        lock.withLock {
            var result: [[String: Any]] = []
            for (key, entry) in entries {
                guard result.count < max(0, limit) else { break }
                let half = entry.received &+ ((entry.deadline >= entry.received ? entry.deadline - entry.received : 0) / 2)
                if !entry.warned && now >= half {
                    entries[key]?.warned = true
                    result.append(["eventType": entry.event, "phase": entry.phase.rawValue,
                                   "messageMachTime": key.machTime, "deadlineMachTime": entry.deadline,
                                   "observedMachTime": now, "responseAttempts": entry.attempts])
                }
            }
            return result
        }
    }
    func snapshot(now: UInt64) -> [String: Any] {
        lock.withLock {
            let oldest = entries.values.map(\.received).min()
            let phases = Dictionary(grouping: entries.values, by: { $0.phase.rawValue }).mapValues(\.count)
            return ["pending": entries.count, "peakPending": peak, "capacity": capacity,
                    "untrackedCapacityOverflows": overflow, "duplicateAttemptsWhilePending": duplicateAttempts,
                    "failedResponseReturns": failedResponses, "retryAttempts": retryAttempts, "phaseCounts": phases,
                    "oldestMessageMachTime": oldest ?? 0, "observedMachTime": now,
                    "scope": "received AUTHs until successful ES response return; excludes messages not yet delivered; never evicts pending records"]
        }
    }
}

/// Rare completed AUTH outliers only. No paths, arguments, signatures or ES
/// messages retained; normal replies do no allocation or extra lock here.
final class SlowAuthResponseDiagnostics: @unchecked Sendable {
    private struct Record {
        let event: UInt32, result: UInt32
        let allowed: Bool
        let message: UInt64, callback: UInt64?, apiStart: UInt64, returned: UInt64, deadline: UInt64
        let phase: PendingAuthDiagnostics.Phase?
        let recordedAt: TimeInterval
    }
    private let lock = NSLock()
    private var records: [Record?]
    private var next = 0, count = 0
    private var overwritten: UInt64 = 0
    private var maximum: Record?
    private let nanosecondsPerTick: Double
    private let thresholdMilliseconds: Double
    let capacity: Int

    init(capacity: Int = 16, nanosecondsPerTick: Double = 1, thresholdMilliseconds: Double = 100) {
        precondition(capacity > 0 && thresholdMilliseconds >= 0)
        records = Array(repeating: nil, count: capacity)
        self.capacity = capacity
        self.nanosecondsPerTick = nanosecondsPerTick
        self.thresholdMilliseconds = thresholdMilliseconds
    }

    func record(event: UInt32, result: UInt32, allowed: Bool, message: UInt64,
                context: PendingAuthDiagnostics.ResponseContext?, apiStart: UInt64,
                returned: UInt64, deadline: UInt64) {
        guard nanosecondsPerTick.isFinite, nanosecondsPerTick > 0, returned >= message else { return }
        let total = milliseconds(message, returned)
        guard total >= thresholdMilliseconds || result != 0 || returned >= deadline else { return }
        let record = Record(event: event, result: result, allowed: allowed, message: message,
                            callback: context?.callbackMachTime, apiStart: apiStart, returned: returned,
                            deadline: deadline, phase: context?.phaseBeforeResponse,
                            recordedAt: Date().timeIntervalSince1970)
        lock.withLock {
            if count == records.count { overwritten &+= 1 }
            records[next] = record; next = (next + 1) % records.count
            count = min(count + 1, records.count)
            if maximum.map({ returned - message > $0.returned - $0.message }) ?? true { maximum = record }
        }
    }

    func snapshot() -> [String: Any] {
        let copy = lock.withLock { () -> ([Record], UInt64, Record?) in
            let ordered = (0..<count).compactMap { records[(next - count + $0 + records.count) % records.count] }
            return (ordered, overwritten, maximum)
        }
        return ["schemaVersion": 1, "capacity": capacity, "retained": copy.0.count,
                "timebaseAvailable": nanosecondsPerTick.isFinite && nanosecondsPerTick > 0,
                "overwritten": copy.1, "thresholdMilliseconds": thresholdMilliseconds,
                "scope": "current-process completed response attempts; excludes unanswered AUTHs",
                "timestampMeaning": "recorded immediately after response return; exact monotonic return tick also retained",
                "records": copy.0.map(fields), "maximumObserved": copy.2.map(fields) as Any? ?? NSNull()]
    }

    private func milliseconds(_ from: UInt64, _ to: UInt64) -> Double {
        (to >= from ? Double(to - from) : -Double(from - to)) * nanosecondsPerTick / 1e6
    }
    private func fields(_ record: Record) -> [String: Any] {
        let callbackValid = record.callback.map { record.message <= $0 && $0 <= record.apiStart } ?? false
        let apiValid = record.message <= record.apiStart && record.apiStart <= record.returned
        return ["eventType": record.event, "responseResult": record.result, "allowed": record.allowed,
                "recordedAt": record.recordedAt, "messageMachTime": record.message,
                "callbackMachTime": record.callback.map { $0 as Any } ?? NSNull(),
                "responseAPIMachTime": record.apiStart, "responseReturnMachTime": record.returned,
                "deadlineMachTime": record.deadline, "totalMilliseconds": milliseconds(record.message, record.returned),
                "eventToCallbackMilliseconds": callbackValid ? milliseconds(record.message, record.callback!) as Any : NSNull(),
                "callbackToAPIMilliseconds": callbackValid && apiValid ? milliseconds(record.callback!, record.apiStart) as Any : NSNull(),
                "responseAPIMilliseconds": apiValid ? milliseconds(record.apiStart, record.returned) as Any : NSNull(),
                "deadlineRemainingAtCallbackMilliseconds": callbackValid ? milliseconds(record.callback!, record.deadline) as Any : NSNull(),
                "deadlineRemainingAtResponseMilliseconds": milliseconds(record.returned, record.deadline),
                "pastDeadline": record.returned >= record.deadline,
                "phaseBeforeResponse": record.phase?.rawValue as Any? ?? NSNull()]
    }
}


/// Mount-only diagnostics: no paths, credentials, file contents, retries or policy decisions.
/// Tokens correlate identical mount paths within one process, never across sessions.
final class USBMountDiagnostics: @unchecked Sendable {
    static let shared = USBMountDiagnostics()
    private let lock = NSLock()
    private let salt = UUID().uuidString
    private var nextID: UInt64 = 0
    private var records: [UInt64: [String: Any]] = [:]
    private var order: [UInt64] = []
    private var receivedCount: UInt64 = 0, overflows: UInt64 = 0
    private var stages: [String: UInt64] = [:]
    let capacity: Int
    init(capacity: Int = 16) { precondition(capacity > 0); self.capacity = capacity }

    func received(path: String, at date: Date = Date()) -> UInt64? {
        let token = SHA256.hash(data: Data((salt + path).utf8)).prefix(16)
            .map { String(format: "%02x", $0) }.joined()
        return lock.withLock {
            receivedCount &+= 1
            if records.count >= capacity {
                guard let old = order.first(where: { records[$0]?["finished"] as? Bool == true })
                else { overflows &+= 1; return nil }
                records.removeValue(forKey: old); order.removeAll { $0 == old }
            }
            nextID &+= 1
            records[nextID] = ["id": nextID, "mountToken": token,
                "pathIsVolumesPrefix": path.hasPrefix("/Volumes/"), "pathByteCount": path.utf8.count,
                "receivedAt": date.timeIntervalSince1970, "updatedAt": date.timeIntervalSince1970,
                "stage": "received", "finished": false, "history": [["stage": "received", "at": date.timeIntervalSince1970]]]
            order.append(nextID)
            stages["received", default: 0] &+= 1
            return nextID
        }
    }

    func update(_ id: UInt64?, stage: String, finished: Bool = false,
                fields: [String: Any] = [:], at date: Date = Date()) {
        lock.withLock {
            stages[stage, default: 0] &+= 1
            guard let id, var record = records[id] else { return }
            record["stage"] = stage; record["updatedAt"] = date.timeIntervalSince1970
            record["finished"] = finished
            for (key, value) in fields { record[key] = value }
            var history = record["history"] as? [[String: Any]] ?? []
            if history.count < 12 { history.append(["stage": stage, "at": date.timeIntervalSince1970]) }
            record["history"] = history
            records[id] = record
        }
    }

    func snapshot() -> [String: Any] {
        lock.withLock {
            ["mountReceivedCount": receivedCount, "mountRecordCapacity": capacity,
             "mountRecordOverflows": overflows, "mountStageCounts": stages,
             "mountRecords": order.compactMap { records[$0] },
             "mountTokenScope": "salted path token; current process only; not a volume UUID",
             "diagnosticScope": "mount startup observations only; scanning policy unchanged"]
        }
    }
}

/// Fixed counters and bounded USB progress records. No per-file history.
final class ScanWorkDiagnostics: @unchecked Sendable {
    static let shared = ScanWorkDiagnostics()
    private struct USBWork { var enumerated = 0; var scanned = 0; let started: Date; var ended: Date? }
    private let lock = NSLock()
    private var nextID: UInt64 = 0
    private var usb: [UInt64: USBWork] = [:]
    private var order: [UInt64] = []
    private var droppedUSBRecords: UInt64 = 0
    private var scansActive = 0, peakScans = 0
    private var scansStarted: UInt64 = 0, scansCompleted: UInt64 = 0, hashBytes: UInt64 = 0
    func scanStarted() { lock.withLock { scansStarted &+= 1; scansActive += 1; peakScans = max(peakScans, scansActive) } }
    func scanEnded() { lock.withLock { scansCompleted &+= 1; scansActive = max(0, scansActive - 1) } }
    func hashed(bytes: Int) { lock.withLock { hashBytes &+= UInt64(max(0, bytes)) } }
    func usbStarted(at date: Date = Date()) -> UInt64? {
        lock.withLock {
            if usb.count >= 32 {
                guard let old = order.first(where: { usb[$0]?.ended != nil }) else { droppedUSBRecords &+= 1; return nil }
                usb.removeValue(forKey: old); order.removeAll { $0 == old }
            }
            nextID &+= 1; usb[nextID] = USBWork(started: date); order.append(nextID); return nextID
        }
    }
    func usbProgress(_ id: UInt64?, enumerated: Int, scanned: Int, finished: Bool = false, at date: Date = Date()) {
        guard let id else { return }
        lock.withLock {
            guard usb[id] != nil else { return }
            usb[id]?.enumerated = enumerated; usb[id]?.scanned = scanned
            if finished { usb[id]?.ended = date }
        }
    }
    func snapshot() -> [String: Any] {
        lock.withLock {
            let records: [[String: Any]] = order.compactMap { id in
                guard let work = usb[id] else { return nil }
                return ["id": id, "enumerated": work.enumerated, "scanned": work.scanned,
                        "startedAt": work.started.timeIntervalSince1970,
                        "endedAt": work.ended?.timeIntervalSince1970 ?? 0, "active": work.ended == nil]
            }
            return ["scansActive": scansActive, "peakScansActive": peakScans,
                    "scansStarted": scansStarted, "scansCompleted": scansCompleted,
                    "streamingHashBytes": hashBytes, "usbRuns": records, "usbRecordCapacity": 32,
                    "usbRecordOverflows": droppedUSBRecords,
                    "usbProgressCadence": "every 256 enumerated entries and scan end; no per-file history"]
        }
    }
}

/// Parses inert, bounded JSON report data only. A stack location is not used
/// as a causal verdict. The caller supplies trusted session identifiers.
enum EndpointTerminationReport {
    struct Match: Equatable {
        let incidentID: String
        let pid: Int32
        let launch: Date
        let captured: Date
        let build: String
    }
    static func date(_ text: String) -> Date? {
        let iso = ISO8601DateFormatter(); iso.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        if let d = iso.date(from: text) { return d }
        iso.formatOptions = [.withInternetDateTime]
        if let d = iso.date(from: text) { return d }
        let f = DateFormatter(); f.locale = Locale(identifier: "en_US_POSIX")
        for format in ["yyyy-MM-dd HH:mm:ss.SSSS Z", "yyyy-MM-dd HH:mm:ss.SSS Z", "yyyy-MM-dd HH:mm:ss Z"] {
            f.dateFormat = format; if let d = f.date(from: text) { return d }
        }
        return nil
    }
    static func parse(_ data: Data) -> Match? {
        guard data.count <= 8 * 1024 * 1024 else { return nil }
        // IPS commonly contains a one-line metadata object followed by a body.
        var bodies: [Data] = [data]
        if let newline = data.firstIndex(of: 10) { bodies.append(Data(data[data.index(after: newline)...])) }
        for body in bodies {
            guard let d = (try? JSONSerialization.jsonObject(with: body)) as? [String: Any],
                  let termination = d["termination"] as? [String: Any],
                  termination["namespace"] as? String == "ENDPOINTSECURITY",
                  (termination["code"] as? NSNumber)?.intValue == 2,
                  let bundle = d["bundleInfo"] as? [String: Any],
                  bundle["CFBundleIdentifier"] as? String == "com.ehsanazish.nick.NickExtension",
                  let build = bundle["CFBundleVersion"] as? String,
                  let pidNumber = d["pid"] as? NSNumber, pidNumber.int64Value > 0, pidNumber.int64Value <= Int64(Int32.max),
                  let launchText = d["procLaunch"] as? String, let launch = date(launchText),
                  let captureText = d["captureTime"] as? String, let capture = date(captureText), capture >= launch,
                  let id = d["incident"] as? String, UUID(uuidString: id) != nil else { continue }
            return Match(incidentID: id, pid: pidNumber.int32Value, launch: launch, captured: capture, build: String(build.prefix(32)))
        }
        return nil
    }
    struct Counts: Equatable {
        let historical: Int
        let currentBuild: Int
        let currentProcess: Int
        let previousSession: Int
    }

    static func counts(_ reports: [Match], current: [String: Any], previous: [String: Any]?) -> Counts {
        let unique = Dictionary(reports.map { ($0.incidentID, $0) }, uniquingKeysWith: { first, _ in first }).values
        return Counts(historical: unique.count,
            currentBuild: unique.filter { $0.build == current["version"] as? String }.count,
            currentProcess: unique.filter { matchesProcess($0, session: current) }.count,
            previousSession: previous.map { prior in unique.filter { matchesPrevious($0, session: prior) }.count } ?? 0)
    }

    static func matchesProcess(_ report: Match, session: [String: Any]) -> Bool {
        guard let pid = session["processID"] as? NSNumber, pid.int32Value == report.pid,
              let start = session["processStartedAt"] as? NSNumber,
              let build = session["version"] as? String, build == report.build else { return false }
        return abs(report.launch.timeIntervalSince1970 - start.doubleValue) <= 120
            && report.captured.timeIntervalSince1970 >= start.doubleValue
    }

    static func matchesPrevious(_ report: Match, session: [String: Any]) -> Bool {
        guard let pid = session["processID"] as? NSNumber, pid.int32Value == report.pid,
              let start = session["processStartedAt"] as? NSNumber,
              let last = session["updatedAt"] as? NSNumber,
              let build = session["version"] as? String, build == report.build else { return false }
        // Health initializes shortly after launch; require both start proximity
        // and capture close to the last heartbeat to reject PID reuse.
        return abs(report.launch.timeIntervalSince1970 - start.doubleValue) <= 120
            && report.captured.timeIntervalSince1970 >= start.doubleValue
            && report.captured.timeIntervalSince1970 >= last.doubleValue - 5
            && report.captured.timeIntervalSince1970 <= last.doubleValue + 180
    }
}

/// Compile-time marker for private packages; ordinary release labels stay intact.
enum PrivateDiagnosticBuild {
    static var enabled: Bool {
#if NICK_PRIVATE_DIAGNOSTICS
        return true
#else
        return false
#endif
    }
    static func version(_ version: String) -> String {
        enabled ? version + " Diagnostic" : version
    }
}
/// Per ES client. Scalar-only bounded history; snapshot serialization never holds
/// the callback lock. Full duration includes post-reply work and pool teardown,
/// but excludes this diagnostic's final bookkeeping and the block-return epilogue.
final class FullCallbackTimingDiagnostics: @unchecked Sendable {
    private struct Timing {
        let event: UInt32, auth: Bool, message: UInt64, entry: UInt64
        var end: UInt64 = 0
        var response: UInt64? = nil
    }
    private struct Record { let current: Timing; let previous: Timing? }
    private let lock = NSLock()
    private let factor: Double
    private var active: Timing?
    private var predecessor: Timing?
    private var previous: Timing?
    private var history: [Record?]
    private var next = 0, count = 0
    private var overwritten: UInt64 = 0, completed: UInt64 = 0, mismatches: UInt64 = 0
    private var maximum: Record?
    private struct CallbackThread { var first: UInt64; var last: UInt64; var callbacks: UInt64 }
    private var threadRecords: [UInt64: CallbackThread] = [:]
    private var threadOrder: [UInt64] = []
    private var threadEvictions: UInt64 = 0, threadLookupFailures: UInt64 = 0
    let capacity: Int
    init(capacity: Int = 16, nanosecondsPerTick: Double) {
        precondition(capacity > 0)
        self.capacity = capacity; factor = nanosecondsPerTick / 1e6
        history = Array(repeating: nil, count: capacity)
    }
    func begin(event: UInt32, auth: Bool, message: UInt64, entry: UInt64, threadID: UInt64? = nil) {
        lock.withLock {
            if let id = threadID {
                if id == 0 { threadLookupFailures &+= 1 }
                else if var record = threadRecords[id] {
                    record.last = entry; record.callbacks &+= 1; threadRecords[id] = record
                } else {
                    if threadOrder.count == 16 { threadRecords.removeValue(forKey: threadOrder.removeFirst()); threadEvictions &+= 1 }
                    threadOrder.append(id); threadRecords[id] = CallbackThread(first: entry, last: entry, callbacks: 1)
                }
            }
            if active != nil { mismatches &+= 1 }
            predecessor = previous
            active = Timing(event: event, auth: auth, message: message, entry: entry)
        }
    }
    /// Deferred replies after callback completion are deliberately not assigned
    /// to a different callback. Existing slow-response diagnostics retain them.
    func responseReturned(callbackEntry: UInt64?, returned: UInt64) {
        guard let callbackEntry else { return }
        lock.withLock {
            guard active?.entry == callbackEntry, returned >= callbackEntry else { return }
            active?.response = returned
        }
    }
    func finish(entry: UInt64, end: UInt64) {
        lock.withLock {
            guard var current = active, current.entry == entry, end >= entry else { mismatches &+= 1; return }
            current.end = end; completed &+= 1
            let record = Record(current: current, previous: predecessor)
            if factor.isFinite && factor > 0 {
                let duration = ms(entry, end)
                let lag = current.auth && current.message <= entry ? ms(current.message, entry) : 0
                if duration >= 10 || lag >= 100 {
                    if count == capacity { overwritten &+= 1 }
                    history[next] = record; next = (next + 1) % capacity; count = min(count + 1, capacity)
                }
                if maximum.map({ end - entry > $0.current.end - $0.current.entry }) ?? true { maximum = record }
            }
            previous = current; active = nil; predecessor = nil
        }
    }
    func snapshot() -> [String: Any] {
        let copy = lock.withLock { () -> ([Record], Record?, UInt64, UInt64, UInt64, [[String: UInt64]], UInt64, UInt64) in
            ((0..<count).compactMap { history[(next - count + $0 + capacity) % capacity] }, maximum, overwritten, completed, mismatches, threadOrder.compactMap { id in
                threadRecords[id].map { ["threadID": id, "firstEntryMachTime": $0.first, "lastEntryMachTime": $0.last, "callbacks": $0.callbacks] }
            }, threadEvictions, threadLookupFailures)
        }
        return ["callbackThreads": copy.5, "callbackThreadCapacity": 16, "callbackThreadEvictions": copy.6, "callbackThreadLookupFailures": copy.7,
                "threadIdentityScope": "kernel thread IDs observed in this client callback; shared-thread CPU is not exclusively callback CPU",
                "schemaVersion": 1, "capacity": capacity, "records": copy.0.map(fields),
                "maximumCallback": copy.1.map(fields) as Any? ?? NSNull(), "overwritten": copy.2,
                "completed": copy.3, "sequenceMismatches": copy.4,
                "timebaseAvailable": factor.isFinite && factor > 0,
                "scope": "per-client callback body including pool teardown; excludes diagnostic finish and return epilogue",
                "thresholdMilliseconds": 10, "authEntryLagThresholdMilliseconds": 100,
                "responseScope": "only responses returned while the matching callback is active; null is not evidence of missing AUTH reply"]
    }
    private func ms(_ a: UInt64, _ b: UInt64) -> Double { (b >= a ? Double(b-a) : -Double(a-b)) * factor }
    private func timing(_ t: Timing) -> [String: Any] {
        ["eventType": t.event, "isAuth": t.auth, "messageMachTime": t.message,
         "entryMachTime": t.entry, "bodyEndMachTime": t.end,
         "bodyMilliseconds": ms(t.entry,t.end),
         "responseReturnMachTime": t.response.map { $0 as Any } ?? NSNull(),
         "postResponseMilliseconds": t.response.flatMap { $0 <= t.end ? ms($0,t.end) : nil } as Any? ?? NSNull()]
    }
    private func fields(_ r: Record) -> [String: Any] {
        let c = r.current
        let p = r.previous
        return ["callback": timing(c), "previousCallback": p.map(timing) as Any? ?? NSNull(),
                "eventToEntryMilliseconds": c.message <= c.entry ? ms(c.message,c.entry) as Any : NSNull(),
                "gapAfterPreviousBodyMilliseconds": p.map { ms($0.end,c.entry) } as Any? ?? NSNull(),
                "previousBodyOverlapWithEventToEntryMilliseconds": p.map {
                    let start = max(c.message,$0.entry), end = min(c.entry,$0.end)
                    return end > start ? ms(start,end) : 0.0
                } as Any? ?? NSNull()]
    }
}

/// Arbitrate only at submission, never while computing policy. The API body is
/// outside the lock; an in-flight ES call cannot safely be preempted.
final class DeferredAuthReply: @unchecked Sendable {
    enum Source { case worker, watchdog }
    enum Result { case accepted, communicationFailure, terminalFailure }
    struct Attempt {
        let allow: Bool, accepted: Bool, final: Bool
        let source: Source
    }
    private enum State { case ready, submitting, retry(Bool), finished }
    private let lock = NSLock()
    private var state = State.ready
    private var attempts = 0
    var isFinished: Bool { lock.withLock { if case .finished = state { return true }; return false } }
    func submit(source: Source, allow proposed: Bool,
                body: (Bool, Int) -> Result) -> Attempt? {
        let reservation: (Bool, Int)? = lock.withLock {
            let allow: Bool
            switch state {
            case .ready: allow = proposed
            case .retry(let original):
                guard source == .watchdog else { return nil }
                allow = original // Never turn a failed deny into an allow.
            case .submitting, .finished: return nil
            }
            attempts += 1; state = .submitting
            return (allow, attempts)
        }
        guard let (allow, number) = reservation else { return nil }
        let result = body(allow, number)
        return lock.withLock {
            let final = result != .communicationFailure || number >= 2
            state = final ? .finished : .retry(allow)
            return Attempt(allow: allow, accepted: result == .accepted, final: final, source: source)
        }
    }
}

/// Monotonic timers on one dedicated thread, independent of GCD worker-pool
/// availability. Timer bodies must only submit replies and enqueue observation.
/// One cancellable entry per deferred request; stale heap slots are compacted.
final class AuthWatchdogScheduler: @unchecked Sendable {
    static let shared = AuthWatchdogScheduler()
    private struct Job { let deadline: UInt64; let body: () -> Void }
    private struct Slot { let deadline: UInt64; let id: UInt64 }
    private let lock = NSLock(), wake = DispatchSemaphore(value: 0)
    private var jobs: [UInt64: Job] = [:], heap: [Slot] = []
    private var nextID: UInt64 = 0
    private var stopped = false
    private var thread: Thread?
    init() {
        let t = Thread { [self] in run() }
        thread = t; t.name = "Nick AUTH watchdog"; t.qualityOfService = .userInteractive; t.start()
    }
    @discardableResult
    func schedule(at deadline: DispatchTime, body: @escaping () -> Void) -> UInt64? {
        let id: UInt64? = lock.withLock {
            guard !stopped else { return nil }
            nextID &+= 1; let id = nextID
            jobs[id] = Job(deadline: deadline.uptimeNanoseconds, body: body)
            heap.append(Slot(deadline: deadline.uptimeNanoseconds, id: id))
            var i = heap.count - 1
            while i > 0 {
                let p = (i-1)/2
                guard heap[i].deadline < heap[p].deadline else { break }
                heap.swapAt(i,p); i = p
            }
            return id
        }
        wake.signal(); return id
    }
    func cancel(_ id: UInt64?) {
        guard let id else { return }
        // Release closure captures outside the scheduler lock.
        let removed = lock.withLock { () -> Job? in
            let removed = jobs.removeValue(forKey: id)
            if heap.count > max(64, jobs.count * 2) {
                heap = jobs.map { Slot(deadline: $0.value.deadline, id: $0.key) }.sorted { $0.deadline < $1.deadline }
            }
            return removed
        }
        withExtendedLifetime(removed) {}; wake.signal()
    }
    func stop() {
        let removed = lock.withLock { () -> [UInt64: Job] in
            stopped = true; let old = jobs; jobs = [:]; heap = []; thread = nil; return old
        }
        withExtendedLifetime(removed) {}; wake.signal()
    }
    var pendingCount: Int { lock.withLock { jobs.count } }
    private func pop() -> Slot {
        let first = heap[0], last = heap.removeLast()
        if !heap.isEmpty {
            heap[0] = last; var i = 0
            while i*2+1 < heap.count {
                var c = i*2+1
                if c+1 < heap.count && heap[c+1].deadline < heap[c].deadline { c += 1 }
                guard heap[c].deadline < heap[i].deadline else { break }
                heap.swapAt(c,i); i = c
            }
        }
        return first
    }
    private func run() {
        while true {
            var due: Job?, deadline = DispatchTime.distantFuture
            lock.lock()
            if stopped { lock.unlock(); return }
            while let first = heap.first, jobs[first.id] == nil { _ = pop() }
            if let first = heap.first {
                if first.deadline <= DispatchTime.now().uptimeNanoseconds {
                    _ = pop(); due = jobs.removeValue(forKey: first.id)
                } else { deadline = DispatchTime(uptimeNanoseconds: first.deadline) }
            }
            lock.unlock()
            if let due { autoreleasepool { due.body() } }
            else { _ = wake.wait(timeout: deadline) }
        }
    }
}

/// Pure, bounded admission policy shared with tests. Production supplies kernel
/// identity and a root-owned config; it never selects an enforcement decision.
final class SyntheticWorkerDelay: @unchecked Sendable {
    enum Scope: String, Codable, Sendable { case credential, prelaunch }
    struct Config: Codable, Sendable {
        let build: String, nonce: String, cdhash: String
        let createdAt: TimeInterval, expiresAt: TimeInterval
        let delayMilliseconds: Int
        let scope: Scope
    }
    struct Candidate: Sendable {
        let build: String, signingID: String?, teamID: String?, cdhash: String
        let identityValid: Bool, helperPath: String, targetPath: String
        let scope: Scope
    }
    static let root = "/Library/Logs/NickPrivateDiagnostics"
    static let helperID = "com.3nsofts.diagnostics.Watchdog5118"
    // XNU cs_blobs.h: CS_SIGNED is distinct from CS_LINKER_SIGNED (0x00020000).
    static func hasValidSignedIdentity(_ flags: UInt32) -> Bool {
        let csValid: UInt32 = 0x00000001
        let csAdhoc: UInt32 = 0x00000002
        let csSigned: UInt32 = 0x20000000
        return flags & csValid != 0 && flags & csSigned != 0 && flags & csAdhoc == 0
    }
    static let credentialSuffix = "/Library/Keychains/synthetic.keychain-db"
    private let lock = NSLock()
    private var consumed: Set<String> = []
    private var active = false
    private var completed: UInt64 = 0
    static func eligible(_ c: Candidate) -> Bool {
        c.build == "5118" && c.identityValid && c.signingID == helperID
            && c.teamID == "UXGW5V3BY6" && c.helperPath.hasPrefix(root + "/Fixtures/")
            && c.helperPath.hasSuffix("/WatchdogReader")
    }
    func claim(_ config: Config, candidate c: Candidate, now: TimeInterval, enabled: Bool) -> Bool {
        guard enabled, Self.eligible(c), config.build == c.build, config.scope == c.scope,
              let uuid = UUID(uuidString: config.nonce), uuid.uuidString == config.nonce,
              config.createdAt.isFinite, config.expiresAt.isFinite, now.isFinite,
              config.createdAt <= now, now < config.expiresAt,
              config.expiresAt > config.createdAt, config.expiresAt - config.createdAt <= 600,
              config.delayMilliseconds == 3000,
              config.cdhash.count == 40, config.cdhash == c.cdhash,
              config.cdhash.allSatisfy({ "0123456789abcdef".contains($0) }) else { return false }
        let base = Self.root + "/Fixtures/" + config.nonce
        guard c.helperPath == base + "/WatchdogReader",
              c.targetPath == base + (c.scope == .credential ? Self.credentialSuffix : "/WatchdogReader") else { return false }
        return lock.withLock {
            guard !active, consumed.count < 16, !consumed.contains(config.nonce) else { return false }
            consumed.insert(config.nonce); active = true; return true
        }
    }
    func finish() { lock.withLock { if active { active = false; completed &+= 1 } } }
    func snapshot() -> [String: Any] {
        lock.withLock { ["injected": consumed.count, "completed": completed, "inFlight": active ? 1 : 0,
                        "maximumInjectionsPerProcess": 16, "fixedDelayMilliseconds": 3000,
                        "enabledInBuild": PrivateDiagnosticBuild.enabled,
                        "scope": "explicit root-configured synthetic workers only; no enforcement decisions"] }
    }
}

/// Configuration I/O and sleeping occur only after a synthetic kernel-identity
/// filter, on the deferred worker. Public builds compile out the entire hook.
final class PrivateWorkerDelay: Sendable {
    static let shared = PrivateWorkerDelay()
    private let admission = SyntheticWorkerDelay()
    func snapshot() -> [String: Any] { admission.snapshot() }
    func pauseIfRequested(_ candidate: SyntheticWorkerDelay.Candidate) {
#if NICK_PRIVATE_DIAGNOSTICS || DEBUG
        guard PrivateDiagnosticBuild.enabled, SyntheticWorkerDelay.eligible(candidate),
              let config = readConfig(),
              Self.safeFixture(config: config, candidate: candidate),
              admission.claim(config, candidate: candidate, now: Date().timeIntervalSince1970, enabled: true) else { return }
        defer { admission.finish() }
        Thread.sleep(forTimeInterval: 3)
#endif
    }
#if NICK_PRIVATE_DIAGNOSTICS || DEBUG
    private static func secure(_ path: String, directory: Bool) -> Bool {
        var value = stat()
        guard lstat(path, &value) == 0, value.st_uid == 0, value.st_mode & 0o022 == 0 else { return false }
        return directory ? value.st_mode & S_IFMT == S_IFDIR
            : value.st_mode & S_IFMT == S_IFREG && value.st_nlink == 1
    }
    private func readConfig() -> SyntheticWorkerDelay.Config? {
        let root = SyntheticWorkerDelay.root
        guard Self.secure(root, directory: true) else { return nil }
        let fd = open(root + "/worker-delay.json", O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard fd >= 0 else { return nil }; defer { close(fd) }
        var metadata = stat()
        guard fstat(fd, &metadata) == 0, metadata.st_uid == 0,
              metadata.st_mode & S_IFMT == S_IFREG, metadata.st_mode & 0o077 == 0,
              metadata.st_nlink == 1, metadata.st_size > 0, metadata.st_size <= 4096 else { return nil }
        var bytes = [UInt8](repeating: 0, count: Int(metadata.st_size))
        let size = bytes.withUnsafeMutableBytes { read(fd, $0.baseAddress, $0.count) }
        guard size == bytes.count else { return nil }
        return try? JSONDecoder().decode(SyntheticWorkerDelay.Config.self, from: Data(bytes))
    }
    private static func safeFixture(config: SyntheticWorkerDelay.Config, candidate: SyntheticWorkerDelay.Candidate) -> Bool {
        // Validate the nonce before using it as a path component.
        guard let uuid = UUID(uuidString: config.nonce), uuid.uuidString == config.nonce else { return false }
        let root = SyntheticWorkerDelay.root
        let base = root + "/Fixtures/" + config.nonce
        if candidate.scope == .credential {
            guard secure(base + "/Library", directory: true), secure(base + "/Library/Keychains", directory: true) else { return false }
        }
        return secure(root + "/Fixtures", directory: true)
            && secure(root + "/Fixtures/" + config.nonce, directory: true)
            && secure(candidate.helperPath, directory: false)
            && secure(candidate.targetPath, directory: false)
    }
#endif
}
