import Foundation

struct RuntimeEvidenceItem: Identifiable, Equatable, Sendable {
    enum Capture: String, Sendable {
        case baseline = "Baseline"
        case followUp = "Follow-up"
    }

    let id: String
    let capture: Capture
    let kind: String
    let title: String
    let details: [(label: String, value: String)]

    static func == (lhs: RuntimeEvidenceItem, rhs: RuntimeEvidenceItem) -> Bool {
        lhs.id == rhs.id && lhs.capture == rhs.capture && lhs.kind == rhs.kind &&
        lhs.title == rhs.title && lhs.details.elementsEqual(rhs.details, by: ==)
    }
}

enum RuntimeEvidenceResolver {
    static func resolve(_ finding: RuntimeFinding, in comparison: RuntimeComparison) -> [RuntimeEvidenceItem] {
        let references = Set(finding.sourceReferences)
        guard !references.isEmpty else { return [] }
        return [
            items(in: comparison.baseline, capture: .baseline, references: references),
            items(in: comparison.followUp, capture: .followUp, references: references),
        ].flatMap { $0 }
    }

    private static func items(
        in snapshot: RuntimeSnapshot?, capture: RuntimeEvidenceItem.Capture,
        references: Set<String>
    ) -> [RuntimeEvidenceItem] {
        guard let snapshot else { return [] }
        var result: [RuntimeEvidenceItem] = []
        result += snapshot.processes.filter { references.contains($0.id) }.map {
            item($0.id, capture, "Process", $0.name, [
                ("Path", $0.path), ("PID at capture", String($0.pid)),
                ("Signing", $0.signingState), ("Team ID", $0.teamID ?? "Unavailable"),
            ])
        }
        result += snapshot.listeners.filter { references.contains($0.id) }.map {
            item($0.id, capture, "Listener", $0.ownerName, [
                ("Endpoint", "\($0.localAddress):\($0.localPort)"),
                ("Transport", $0.transport), ("Owner path", $0.ownerPath ?? "Unavailable"),
            ])
        }
        result += snapshot.connections.filter { references.contains($0.id) }.map {
            item($0.id, capture, "Connection", $0.ownerName, [
                ("Destination", "\($0.remoteAddress):\($0.remotePort)"),
                ("Transport", $0.transport), ("Observations", String($0.observationCount)),
                ("Owner path", $0.ownerPath ?? "Unavailable"),
            ])
        }
        result += snapshot.persistence.filter { references.contains($0.id) }.map {
            item($0.id, capture, "Persistence", $0.name, [
                ("Type", $0.type), ("Scope", $0.scope), ("Path", $0.path),
                ("Executable", $0.executablePath ?? "Unavailable"),
                ("Enabled", $0.isEnabled ? "Yes" : "No"),
            ])
        }
        result += snapshot.extensions.filter { references.contains($0.id) }.map {
            item($0.id, capture, "System Extension", $0.bundleIdentifier, [
                ("Category", $0.category.rawValue), ("Team ID", $0.teamIdentifier ?? "Unavailable"),
                ("Version", $0.version ?? "Unavailable"), ("State", $0.stateDescription),
            ])
        }
        return result.sorted { ($0.capture.rawValue, $0.kind, $0.title) < ($1.capture.rawValue, $1.kind, $1.title) }
    }

    private static func item(
        _ id: String, _ capture: RuntimeEvidenceItem.Capture, _ kind: String,
        _ title: String, _ details: [(String, String)]
    ) -> RuntimeEvidenceItem {
        RuntimeEvidenceItem(
            id: "\(capture.rawValue):\(id)", capture: capture, kind: kind,
            title: title, details: details.map { (label: $0.0, value: $0.1) }
        )
    }
}
