// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import SwiftUI

// MARK: - ProcessTreeView

/// Phase 6 — Interactive attack-chain visualization.
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
    private struct TreeNode: Identifiable {
        let id: Int32              // PID
        let processPath: String
        let parentPID: Int32
        var children: [TreeNode]
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
                    children: [],
                    isThreat: isThreat,
                    eventCount: 1,
                    lastEventTime: event.timestamp
                )
            }
        }

        // Attach children to parents
        var roots: [TreeNode] = []
        for var node in nodeMap.values {
            if let _ = nodeMap[node.parentPID] {
                nodeMap[node.parentPID]?.children.append(node)
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
                List(forest, children: \.childrenOrNil) { node in
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
        for child in node.children { collectThreatPIDs(child) }
    }
}

// MARK: - TreeNode Children Helper

private extension ProcessTreeView.TreeNode {
    var childrenOrNil: [ProcessTreeView.TreeNode]? {
        children.isEmpty ? nil : children
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
