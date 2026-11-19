import Foundation

/// Diagnostic ownership primitive used by the real retained-AUTH paths. Winning
/// a claim is NOT proof that an ES response was submitted or accepted.
final class AuthResponseClaim: @unchecked Sendable {
    private let lock = NSLock()
    private var claimed = false
    func claim() -> Bool { lock.withLock { if claimed { return false }; claimed = true; return true } }
}

/// No ES pointers, paths, arguments or credentials retained. The callback only
/// changes bounded scalar state; snapshots and warning selection run elsewhere.
final class PendingAuthDiagnostics: @unchecked Sendable {
    struct Key: Hashable, Sendable { let address: UInt64; let machTime: UInt64 }
    enum Phase: String, Sendable { case callback, credentialValidation, prelaunchHash, workerClaimed, watchdogClaimed, responseAPI, responseFailed }
    private struct Entry {
        let event: UInt32; let received: UInt64; let deadline: UInt64
        var phase: Phase = .callback
        var attempts = 0
        var warned = false
    }
    private let lock = NSLock()
    private var entries: [Key: Entry] = [:]
    private var overflow: UInt64 = 0, duplicateAttempts: UInt64 = 0, failedResponses: UInt64 = 0
    private var peak = 0
    let capacity: Int
    init(capacity: Int = 4096) { precondition(capacity > 0); self.capacity = capacity }
    func received(_ key: Key, event: UInt32, deadline: UInt64) {
        lock.withLock {
            guard entries[key] == nil else { return }
            guard entries.count < capacity else { overflow &+= 1; return }
            entries[key] = Entry(event: event, received: key.machTime, deadline: deadline)
            peak = max(peak, entries.count)
        }
    }
    func phase(_ key: Key, _ phase: Phase) { lock.withLock { entries[key]?.phase = phase } }
    func responseStarted(_ key: Key) {
        lock.withLock {
            guard var entry = entries[key] else { return }
            if entry.attempts > 0 { duplicateAttempts &+= 1 }
            entry.attempts += 1; entry.phase = .responseAPI; entries[key] = entry
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
                    "failedResponseReturns": failedResponses, "phaseCounts": phases,
                    "oldestMessageMachTime": oldest ?? 0, "observedMachTime": now,
                    "scope": "received AUTHs until successful ES response return; excludes messages not yet delivered; never evicts pending records"]
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
