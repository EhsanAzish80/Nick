// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import SwiftUI

// MARK: - ProcessTreeView

/// Interactive parent–child process tree built from the live `SecurityEngine.processes` list.
struct ProcessTreeView: View {

    @Environment(SecurityEngine.self) private var engine

    // MARK: - Tree Node

    fileprivate struct TreeNode: Identifiable {
        let id: Int32
        let name: String
        let path: String
        let signingStatus: SigningStatus
        var children: [TreeNode]?
        var isThreat: Bool
    }

    // MARK: - Forest Construction

    private func buildForest(from processes: [NickProcessInfo]) -> [TreeNode] {
        let pidSet = Set(processes.map(\.pid))
        var childrenMap: [Int32: [NickProcessInfo]] = [:]
        for p in processes {
            if pidSet.contains(p.parentPID) {
                childrenMap[p.parentPID, default: []].append(p)
            }
        }
        let roots = processes.filter { !pidSet.contains($0.parentPID) }

        func makeNode(_ p: NickProcessInfo) -> TreeNode {
            let kids = childrenMap[p.pid]?.sorted { $0.name < $1.name } ?? []
            return TreeNode(
                id: p.pid,
                name: p.name.isEmpty ? (p.path as NSString).lastPathComponent : p.name,
                path: p.path,
                signingStatus: p.signingStatus,
                children: kids.isEmpty ? nil : kids.map { makeNode($0) },
                isThreat: p.signingStatus == .unsigned || p.signingStatus == .invalid
            )
        }
        return roots
            .sorted { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }
            .map { makeNode($0) }
    }

    private var forest: [TreeNode] { buildForest(from: engine.processes) }

    // MARK: - Body

    var body: some View {
        Group {
            if forest.isEmpty {
                ContentUnavailableView(
                    "No Process Data",
                    systemImage: "square.stack.3d.up",
                    description: Text("Process data is loading. If this persists, check that the system extension is active.")
                )
            } else {
                List(forest, children: \.children) { node in
                    ProcessNodeRow(node: node)
                }
                .listStyle(.inset)
            }
        }
    }
}

// MARK: - ProcessNodeRow

private struct ProcessNodeRow: View {

    let node: ProcessTreeView.TreeNode

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: node.isThreat ? "exclamationmark.triangle.fill" : "gearshape")
                .foregroundStyle(node.isThreat ? .red : .secondary)
                .frame(width: 18)

            VStack(alignment: .leading, spacing: 2) {
                HStack {
                    Text(node.name)
                        .fontWeight(node.isThreat ? .semibold : .regular)
                        .foregroundStyle(node.isThreat ? Color.red : Color.primary)
                        .lineLimit(1)
                    Spacer()
                    Text("pid \(node.id)")
                        .font(.caption2)
                        .foregroundStyle(.tertiary)
                }
                Text(node.path.isEmpty ? "—" : node.path)
                    .font(.caption2)
                    .foregroundStyle(.tertiary)
                    .lineLimit(1)
                    .truncationMode(.head)
            }
        }
        .padding(.vertical, 2)
    }
}

// MARK: - Preview

#Preview {
    ProcessTreeView()
        .environment(SecurityEngine())
        .frame(width: 700, height: 500)
}
///
/// Shows a nested disclosure tree of process parent-child relationships derived
/// from `ExtensionXPCClient.events`. Events are grouped by PID; for each unique
/// process a tree node is shown. The full ancestor chain is displayed for any
/// process that had a threat event (blocked exec, known threat name, etc.).
///
/// Because the live `ProcessTree` is extension-side only (not serialised over XPC
/// in Phase 6), this view reconstructs parent–child relationships from the
/// `ESEvent` stream already available in `ExtensionXPCClient.events`.
struct ProcessTreeView: View {

    @Environment(ExtensionXPCClient.self) private var xpcClient

    @State private var expandedPIDs: Set<Int32> = []

    // MARK: - Tree Construction

    /// A lightweight node built from `ESEvent` data.
    fileprivate struct TreeNode: Identifiable {
        let id: Int32              // PID
        let processPath: String
        let parentPID: Int32
        var children: [TreeNode]?
        var isThreat: Bool
        var eventCount: Int
        var lastEventTime: Date
    }

    /// Builds a forest of `TreeNode` from the event stream.
    private var forest: [TreeNode] {
        var nodeMap: [Int32: TreeNode] = [:]

        for event in xpcClient.events {
            let pid = event.pid
            let isThreat = (event.threatName != nil || event.decision == .deny)

            if var existing = nodeMap[pid] {
                if isThreat { existing.isThreat = true }
                existing.eventCount += 1
                if event.timestamp > existing.lastEventTime {
                    existing.lastEventTime = event.timestamp
                }
                nodeMap[pid] = existing
            } else {
                nodeMap[pid] = TreeNode(
                    id: pid,
                    processPath: event.processPath,
                    parentPID: event.parentPid,
                    children: nil,
                    isThreat: isThreat,
                    eventCount: 1,
                    lastEventTime: event.timestamp
                )
            }
        }

        // Attach children to parents
        var roots: [TreeNode] = []
        for node in nodeMap.values {
            if nodeMap[node.parentPID] != nil {
                nodeMap[node.parentPID]!.children = (nodeMap[node.parentPID]!.children ?? []) + [node]
            } else {
                roots.append(node)
            }
        }
        return roots.sorted { $0.isThreat && !$1.isThreat }
    }

    // MARK: - Body

    var body: some View {
        VStack(spacing: 0) {
            if forest.isEmpty {
                ContentUnavailableView(
                    "No Process Data",
                    systemImage: "square.stack.3d.up",
                    description: Text("Process lineage will appear here once the extension is active and events arrive.")
                )
            } else {
                List(forest, children: \.children) { node in
                    ProcessNodeRow(node: node)
                }
                .listStyle(.inset)
            }
        }
        .navigationTitle("Process Tree")
        .navigationSubtitle("\(forest.count) root process(es)")
        .toolbar {
            ToolbarItem {
                Button("Expand Threats") {
                    expandThreatNodes()
                }
                .disabled(forest.isEmpty)
            }
        }
    }

    private func expandThreatNodes() {
        for node in forest {
            collectThreatPIDs(node)
        }
    }

    private func collectThreatPIDs(_ node: TreeNode) {
        if node.isThreat { expandedPIDs.insert(node.id) }
        for child in node.children ?? [] { collectThreatPIDs(child) }
    }
}

// MARK: - ProcessNodeRow

private struct ProcessNodeRow: View {

    let node: ProcessTreeView.TreeNode

    private var timeString: String {
        let f = DateFormatter()
        f.dateStyle = .none
        f.timeStyle = .medium
        return f.string(from: node.lastEventTime)
    }

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: node.isThreat ? "exclamationmark.triangle.fill" : "gearshape")
                .foregroundStyle(node.isThreat ? .red : .secondary)
                .frame(width: 18)

            VStack(alignment: .leading, spacing: 2) {
                HStack {
                    Text(node.processPath.lastPathComponent)
                        .fontWeight(node.isThreat ? .bold : .regular)
                        .foregroundStyle(node.isThreat ? .red : .primary)
                        .lineLimit(1)

                    Spacer()

                    Text(timeString)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }

                HStack(spacing: 8) {
                    Text("pid \(node.id)")
                        .font(.caption2)
                        .foregroundStyle(.tertiary)

                    Text("\(node.eventCount) event(s)")
                        .font(.caption2)
                        .foregroundStyle(.secondary)

                    if node.isThreat {
                        Label("Threat", systemImage: "xmark.shield.fill")
                            .font(.caption2)
                            .foregroundStyle(.red)
                    }
                }

                Text(node.processPath)
                    .font(.caption2)
                    .foregroundStyle(.tertiary)
                    .lineLimit(1)
                    .truncationMode(.head)
            }
        }
        .padding(.vertical, 2)
    }
}

// MARK: - String Helper

private extension String {
    var lastPathComponent: String { (self as NSString).lastPathComponent }
}

// MARK: - Preview

#Preview {
    ProcessTreeView()
        .environment(ExtensionXPCClient())
        .frame(width: 700, height: 500)
}
