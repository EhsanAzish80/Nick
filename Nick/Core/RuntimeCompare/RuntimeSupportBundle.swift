import Foundation

struct RuntimeSupportBundleFiles: Sendable {
    let markdown: Data
    let json: Data
}

enum RuntimeSupportBundleBuilder {
    enum ExportError: LocalizedError {
        case tooLarge

        var errorDescription: String? {
            "The support bundle exceeds Nick's 50 MB export limit. Shorten the capture and try again."
        }
    }

    static func files(
        for comparison: RuntimeComparison,
        sanitized: Bool,
        maximumBytes: Int = 50 * 1_024 * 1_024
    ) throws -> RuntimeSupportBundleFiles {
        let value = sanitized ? RuntimeComparisonSanitizer.sanitize(comparison) : comparison
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        let json = try encoder.encode(value)
        let markdown = Data(summary(for: value, sanitized: sanitized).utf8)
        guard json.count + markdown.count <= maximumBytes else { throw ExportError.tooLarge }
        return RuntimeSupportBundleFiles(markdown: markdown, json: json)
    }

    static func summary(for comparison: RuntimeComparison, sanitized: Bool) -> String {
        let important = comparison.findings.filter { $0.attention == .important }.count
        let review = comparison.findings.filter { $0.attention == .review }.count
        var lines = [
            "# Nick Runtime Comparison",
            "",
            "- Label: \(comparison.label)",
            "- Scenario: \(comparison.scenario.title)",
            "- State: \(comparison.state.rawValue)",
            "- Export: \(sanitized ? "Sanitized" : "Original local evidence")",
            "- Important changes: \(important)",
            "- Changes to review: \(review)",
            ""
        ]
        if comparison.findings.isEmpty {
            lines += ["No comparison findings are available.", ""]
        } else {
            for category in RuntimeFindingCategory.allCases {
                let findings = comparison.findings.filter { $0.category == category }
                guard !findings.isEmpty else { continue }
                lines += ["## \(category.rawValue)", ""]
                for finding in findings {
                    lines += [
                        "### \(finding.title)",
                        "",
                        "- Evidence: \(finding.evidence.rawValue)",
                        "- Attention: \(finding.attention.rawValue)",
                        "- Change: \(finding.change.rawValue)",
                        "",
                        finding.explanation,
                        ""
                    ]
                    if let limitation = finding.limitation { lines += ["Limitation: \(limitation)", ""] }
                }
            }
        }
        lines += ["---", "Generated locally by Nick. This report is observational and is not a compliance certification.", ""]
        return lines.joined(separator: "\n")
    }

    static func writeZIP(_ files: RuntimeSupportBundleFiles, to destination: URL) throws {
        let fm = FileManager.default
        let staging = fm.temporaryDirectory.appendingPathComponent("NickRuntimeSupport-\(UUID().uuidString)", isDirectory: true)
        try fm.createDirectory(at: staging, withIntermediateDirectories: true)
        defer { try? fm.removeItem(at: staging) }
        try files.markdown.write(to: staging.appendingPathComponent("Runtime Comparison.md"), options: .atomic)
        try files.json.write(to: staging.appendingPathComponent("Runtime Comparison.json"), options: .atomic)

        let process = Process()
        let errorPipe = Pipe()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/ditto")
        process.arguments = ["-c", "-k", "--sequesterRsrc", staging.path, destination.path]
        process.standardError = errorPipe
        try process.run()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else {
            let message = String(data: errorPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8)
            throw NSError(domain: "RuntimeSupportBundle", code: Int(process.terminationStatus), userInfo: [NSLocalizedDescriptionKey: message ?? "Could not create support bundle."])
        }
    }
}

enum RuntimeComparisonSanitizer {
    static func sanitize(_ comparison: RuntimeComparison) -> RuntimeComparison {
        let values = sensitiveValues(in: comparison)
        let replacements = Dictionary(uniqueKeysWithValues: values.sorted().enumerated().map { index, value in
            (value, "<redacted-\(index + 1)>")
        })
        guard !replacements.isEmpty else { return comparison }
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        guard let data = try? encoder.encode(comparison), var text = String(data: data, encoding: .utf8) else { return comparison }
        for value in replacements.keys.sorted(by: { $0.count > $1.count }) {
            text = text.replacingOccurrences(of: value, with: replacements[value]!)
        }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return (try? decoder.decode(RuntimeComparison.self, from: Data(text.utf8))) ?? comparison
    }

    private static func sensitiveValues(in comparison: RuntimeComparison) -> Set<String> {
        var values = Set<String>()
        for snapshot in [comparison.baseline, comparison.followUp].compactMap({ $0 }) {
            values.insert(snapshot.deviceToken)
            for process in snapshot.processes {
                if let user = process.user, !user.isEmpty { values.insert(user) }
                if process.path.hasPrefix("/Users/") { values.insert(process.path) }
            }
            for item in snapshot.persistence {
                if item.path.hasPrefix("/Users/") { values.insert(item.path) }
                if let path = item.executablePath, path.hasPrefix("/Users/") { values.insert(path) }
            }
            for item in snapshot.connections { values.insert(item.remoteAddress) }
            for item in snapshot.listeners where RuntimeIdentity.addressScope(item.localAddress).hasPrefix("specific:") {
                values.insert(item.localAddress)
            }
        }
        values.remove("")
        return values
    }
}
