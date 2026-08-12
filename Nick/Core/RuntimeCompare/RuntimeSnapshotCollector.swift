import Foundation

@MainActor
final class RuntimeSnapshotCollector {
    struct Progress: Sendable {
        let stage: String
        let fraction: Double
    }

    func capture(
        label: String,
        scenario: RuntimeScenario,
        configuration: RuntimeCaptureConfiguration,
        endpointResponding: Bool,
        networkResponding: Bool,
        networkState: String,
        progress: @escaping @MainActor (Progress) -> Void
    ) async throws -> RuntimeSnapshot {
        let startedAt = Date()
        var health: [RuntimeProviderHealth] = []

        progress(.init(stage: "Processes", fraction: 0.08))
        let processResult = Result { try ProcessScanner().scanFast() }
        let rawProcesses = (try? processResult.get()) ?? []
        let processPaths = Dictionary(rawProcesses.map { ($0.pid, $0.path) }, uniquingKeysWith: { current, candidate in
            current.isEmpty ? candidate : current
        })
        let processes = rawProcesses.map(Self.processRecord)
        health.append(Self.health("Processes", result: processResult.map { $0.count }))

        progress(.init(stage: "Persistence", fraction: 0.20))
        let persistenceResult: Result<[PersistenceItem], Error>
        do { persistenceResult = .success(try await PersistenceWatcher().snapshot()) }
        catch { persistenceResult = .failure(error) }
        let persistence = ((try? persistenceResult.get()) ?? []).map(Self.persistenceRecord)
        health.append(Self.health("Persistence", result: persistenceResult.map { $0.count }))

        progress(.init(stage: "System and network extensions", fraction: 0.32))
        let extensionResult = await SystemExtensionInventory.capture()
        let extensions = (try? extensionResult.get()) ?? []
        health.append(Self.health("Extensions", result: extensionResult.map { $0.count }))

        progress(.init(stage: "Listening ports", fraction: 0.42))
        let requested = max(0, configuration.requestedObservationSeconds)
        let interval = max(1, configuration.sampleIntervalSeconds)
        let observation = try await RuntimeConnectionObserver.observe(
            requestedSeconds: requested,
            intervalSeconds: interval,
            sample: Self.connectionSample,
            sleep: { try await Task.sleep(for: .seconds($0)) }
        ) { elapsed in
            progress(.init(
                stage: "Observing connections — \(max(0, requested - elapsed)) seconds remaining",
                fraction: 0.42 + (0.38 * Double(elapsed) / Double(max(1, requested)))
            ))
        }
        let samples = observation.samples
        let elapsed = observation.elapsedSeconds

        let allConnections = samples.flatMap { $0 }
        let listeners = Self.listeners(from: allConnections, processPaths: processPaths)
        let connectionAggregation = Self.aggregateConnections(
            samples: samples,
            processPaths: processPaths,
            startedAt: startedAt,
            interval: interval
        )
        let connections = connectionAggregation.records
        let connectionFailures = samples.isEmpty
        let connectionTruncated = connectionAggregation.droppedDistinctRecords > 0
        let connectionPartiallyFailed = observation.failedSampleCount > 0
        health.append(RuntimeProviderHealth(
            provider: "Connections",
            state: connectionFailures ? .unavailable : ((connectionTruncated || connectionPartiallyFailed) ? .partial : .available),
            message: connectionFailures
                ? "Connection scanner returned no usable sample."
                : (connectionTruncated
                    ? "Connection evidence reached the 25,000-record limit; \(connectionAggregation.droppedDistinctRecords) additional distinct records were omitted."
                    : (connectionPartiallyFailed
                        ? "The connection scanner missed \(observation.failedSampleCount) sample(s); available evidence was preserved."
                        : nil)),
            recordCount: listeners.count + connections.count
        ))

        progress(.init(stage: "Sensor health", fraction: 0.90))
        health.append(.init(
            provider: "Endpoint Security",
            state: endpointResponding ? .available : .partial,
            message: endpointResponding ? nil : "Nick could not verify that Endpoint Security was responding.",
            recordCount: endpointResponding ? 1 : 0
        ))
        health.append(.init(
            provider: "Network Filter",
            state: networkResponding ? .available : .partial,
            message: networkResponding ? nil : "Nick could not verify a current Network Filter heartbeat.",
            recordCount: networkResponding ? 1 : 0
        ))

        progress(.init(stage: "Finishing capture", fraction: 1))
        return RuntimeSnapshot(
            id: UUID(), schemaVersion: RuntimeSnapshot.currentSchemaVersion,
            label: label, scenario: scenario, startedAt: startedAt, completedAt: Date(),
            nickVersion: Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "Unknown",
            macOSVersion: ProcessInfo.processInfo.operatingSystemVersionString,
            architecture: Self.architecture,
            deviceToken: RuntimeDeviceIdentity.token,
            bootSessionIdentifier: String(Int(Date().timeIntervalSince1970 - ProcessInfo.processInfo.systemUptime)),
            configuration: configuration, actualObservationSeconds: elapsed,
            processes: processes, listeners: listeners, connections: connections,
            persistence: persistence, extensions: extensions,
            sensorHealth: .init(
                endpointSecurityResponding: endpointResponding,
                networkFilterResponding: networkResponding,
                networkFilterState: networkState
            ),
            providerHealth: health
        )
    }

    private static func connectionSample() async -> Result<[NetworkConnectionInfo], Error> {
        do { return .success(try await ConnectionScanner().scan()) }
        catch { return .failure(error) }
    }

    private static func processRecord(_ process: NickProcessInfo) -> RuntimeProcessRecord {
        RuntimeProcessRecord(
            id: "process:\(process.pid):\(process.startTime?.timeIntervalSince1970 ?? 0)",
            pid: process.pid, name: process.name, path: process.path,
            parentPID: process.parentPID, parentName: process.parentName,
            user: process.user, startTime: process.startTime,
            signingState: process.signingStatus.displayName,
            teamID: process.signingStatus.runtimeTeamID
        )
    }

    private static func persistenceRecord(_ item: PersistenceItem) -> RuntimePersistenceRecord {
        RuntimePersistenceRecord(
            id: "persistence:\(item.id.uuidString)", type: item.type.rawValue,
            scope: item.scope.rawValue, name: item.name, path: item.path,
            executablePath: item.executablePath, isEnabled: item.isEnabled,
            signingState: item.signingStatus?.displayName,
            teamID: item.signingStatus?.runtimeTeamID, lastModified: item.lastModified
        )
    }

    private static func listeners(
        from connections: [NetworkConnectionInfo],
        processPaths: [Int32: String]
    ) -> [RuntimeListenerRecord] {
        var unique: [String: RuntimeListenerRecord] = [:]
        for item in connections where item.state.isListening {
            let record = RuntimeListenerRecord(
                id: "listener:\(item.id.uuidString)", transport: item.transportProtocol.rawValue,
                localAddress: item.localAddress, localPort: item.localPort,
                ownerName: item.processName, ownerPath: processPaths[item.pid], pid: item.pid
            )
            unique[record.stableKey] = record
        }
        return unique.values.sorted { $0.stableKey < $1.stableKey }
    }

    static func aggregateConnections(
        samples: [[NetworkConnectionInfo]], processPaths: [Int32: String],
        startedAt: Date, interval: Int
    ) -> RuntimeConnectionAggregation {
        var buffer = RuntimeConnectionBuffer()
        for (sampleIndex, sample) in samples.enumerated() {
            let seen = startedAt.addingTimeInterval(Double(sampleIndex * interval))
            for item in sample where item.isOutbound {
                guard let address = item.remoteAddress, let port = item.remotePort else { continue }
                let candidate = RuntimeConnectionRecord(
                    id: "connection:\(item.id.uuidString)", transport: item.transportProtocol.rawValue,
                    remoteAddress: address, remotePort: port, ownerName: item.processName,
                    ownerPath: processPaths[item.pid], firstSeen: seen, lastSeen: seen,
                    observationCount: 1
                )
                buffer.record(candidate, seenAt: seen)
            }
        }
        return .init(records: buffer.sortedRecords, droppedDistinctRecords: buffer.droppedDistinctRecords)
    }

    private static func health(_ provider: String, result: Result<Int, Error>) -> RuntimeProviderHealth {
        switch result {
        case .success(let count): .init(provider: provider, state: .available, message: nil, recordCount: count)
        case .failure(let error): .init(provider: provider, state: .unavailable, message: error.localizedDescription, recordCount: 0)
        }
    }

    private static var architecture: String {
        #if arch(arm64)
        return "arm64"
        #elseif arch(x86_64)
        return "x86_64"
        #else
        return "unknown"
        #endif
    }
}

struct RuntimeConnectionObservation<Sample>: Sendable where Sample: Sendable {
    let samples: [Sample]
    let elapsedSeconds: Int
    let failedSampleCount: Int
}

enum RuntimeConnectionObserver {
    @MainActor
    static func observe<Sample: Sendable>(
        requestedSeconds: Int,
        intervalSeconds: Int,
        sample: () async -> Result<Sample, Error>,
        sleep: (Int) async throws -> Void,
        progress: @MainActor (Int) -> Void
    ) async throws -> RuntimeConnectionObservation<Sample> {
        let requested = max(0, requestedSeconds)
        let interval = max(1, intervalSeconds)
        var samples: [Sample] = []
        var failures = 0
        switch await sample() {
        case .success(let value): samples.append(value)
        case .failure: failures += 1
        }

        var elapsed = 0
        while elapsed < requested {
            try Task.checkCancellation()
            let step = min(interval, requested - elapsed)
            try await sleep(step)
            try Task.checkCancellation()
            elapsed += step
            progress(elapsed)
            switch await sample() {
            case .success(let value): samples.append(value)
            case .failure: failures += 1
            }
        }
        return .init(samples: samples, elapsedSeconds: elapsed, failedSampleCount: failures)
    }
}

struct RuntimeConnectionAggregation: Sendable, Equatable {
    let records: [RuntimeConnectionRecord]
    let droppedDistinctRecords: Int
}

struct RuntimeConnectionBuffer: Sendable {
    static let defaultMaximumCount = 25_000

    private let maximumCount: Int
    private var records: [String: RuntimeConnectionRecord] = [:]
    private(set) var droppedDistinctRecords = 0

    init(maximumCount: Int = defaultMaximumCount) {
        self.maximumCount = max(1, maximumCount)
    }

    mutating func record(_ candidate: RuntimeConnectionRecord, seenAt: Date) {
        if let prior = records[candidate.stableKey] {
            records[candidate.stableKey] = RuntimeConnectionRecord(
                id: prior.id, transport: prior.transport, remoteAddress: prior.remoteAddress,
                remotePort: prior.remotePort, ownerName: prior.ownerName, ownerPath: prior.ownerPath,
                firstSeen: prior.firstSeen, lastSeen: seenAt,
                observationCount: prior.observationCount + 1
            )
        } else if records.count < maximumCount {
            records[candidate.stableKey] = candidate
        } else {
            droppedDistinctRecords += 1
        }
    }

    var sortedRecords: [RuntimeConnectionRecord] {
        records.values.sorted { $0.stableKey < $1.stableKey }
    }
}

enum RuntimeDeviceIdentity {
    private static let key = "runtimeCompareDeviceToken"
    static var token: String {
        if let saved = UserDefaults.standard.string(forKey: key) { return saved }
        let value = UUID().uuidString
        UserDefaults.standard.set(value, forKey: key)
        return value
    }
}

enum SystemExtensionInventory {
    static func capture() async -> Result<[RuntimeExtensionRecord], Error> {
        do {
            let process = Process()
            let pipe = Pipe()
            process.executableURL = URL(fileURLWithPath: "/usr/bin/systemextensionsctl")
            process.arguments = ["list"]
            process.standardOutput = pipe
            process.standardError = pipe
            try process.run()
            process.waitUntilExit()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            guard process.terminationStatus == 0 else {
                throw NSError(domain: "RuntimeCompare", code: Int(process.terminationStatus), userInfo: [NSLocalizedDescriptionKey: String(data: data, encoding: .utf8) ?? "Extension inventory failed."])
            }
            return .success(parse(String(data: data, encoding: .utf8) ?? ""))
        } catch { return .failure(error) }
    }

    static func parse(_ output: String) -> [RuntimeExtensionRecord] {
        var category: RuntimeExtensionCategory = .other
        var records: [RuntimeExtensionRecord] = []
        for rawLine in output.split(separator: "\n", omittingEmptySubsequences: false) {
            let line = String(rawLine).trimmingCharacters(in: .whitespaces)
            if line.contains("endpoint_security_extension") { category = .endpointSecurity; continue }
            if line.contains("network_extension") { category = .network; continue }
            if line.contains("driver_extension") { category = .driver; continue }
            guard line.contains("["), line.contains("]") else { continue }
            let cleaned = line.replacingOccurrences(of: "*", with: " ")
            let tokens = cleaned.split(whereSeparator: { $0.isWhitespace }).map(String.init)
            guard let bundleIndex = tokens.firstIndex(where: { $0.contains(".") && !$0.hasPrefix("(") }), bundleIndex > 0 else { continue }
            let team = tokens[bundleIndex - 1]
            let bundle = tokens[bundleIndex]
            let version = line.firstMatch(between: "(", and: ")")?.split(separator: "/").first.map(String.init)
            let state = line.firstMatch(between: "[", and: "]") ?? "unknown"
            records.append(RuntimeExtensionRecord(
                id: "extension:\(category.rawValue):\(bundle)", category: category,
                bundleIdentifier: bundle, teamIdentifier: team, version: version,
                isActivated: state.contains("activated"), isEnabled: state.contains("enabled"),
                stateDescription: state
            ))
        }
        return records.sorted { $0.stableKey < $1.stableKey }
    }
}

private extension String {
    func firstMatch(between start: Character, and end: Character) -> String? {
        guard let startIndex = firstIndex(of: start),
              let endIndex = self[index(after: startIndex)...].firstIndex(of: end) else { return nil }
        return String(self[index(after: startIndex)..<endIndex])
    }
}
