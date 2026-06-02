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
