// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import SwiftUI

// MARK: - SettingsView

/// Application-level settings panel.
///
/// Covers user-configurable behaviour such as the trusted process list.
/// Access via `Settings` > Nick in the menu bar (`.settings` scene in `NickApp`).
struct SettingsView: View {

    // MARK: - Dependencies

    @Environment(SecurityEngine.self) private var engine

    // MARK: - Private State

    @State private var newProcessName: String = ""
    @State private var showRemoveConfirmation = false
    @State private var nameToRemove: String?

    // MARK: - Body

    var body: some View {
        TabView {
            trustedProcessesTab
                .tabItem {
                    Label("Trusted Processes", systemImage: "hand.raised.slash")
                }
        }
        .frame(minWidth: 540, minHeight: 420)
    }

    // MARK: - Trusted Processes Tab

    private var trustedProcessesTab: some View {
        VStack(alignment: .leading, spacing: NickSpacing.lg) {
            header

            Divider()

            addProcessRow

            Divider()

            userListSection

            Spacer()
        }
        .padding(NickSpacing.xl)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: NickSpacing.xs) {
            Text("Trusted Processes")
                .font(.title2.bold())
            Text("Nick will not generate alerts for processes in this list. "
               + "Only add software you have personally verified. "
               + "Built-in entries cover common developer tools and cannot be removed.")
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    private var addProcessRow: some View {
        HStack(spacing: NickSpacing.sm) {
            TextField("Process name (e.g. MyApp)", text: $newProcessName)
                .textFieldStyle(.roundedBorder)
                .onSubmit { addProcess() }

            Button("Add", action: addProcess)
                .disabled(newProcessName.trimmingCharacters(in: .whitespaces).isEmpty)
                .buttonStyle(NickPrimaryButtonStyle())
        }
    }

    @ViewBuilder
    private var userListSection: some View {
        let userNames = engine.trustedProcessList.userTrustedNames()

        if userNames.isEmpty {
            emptyUserListPlaceholder
        } else {
            VStack(alignment: .leading, spacing: NickSpacing.xs) {
                Text("User-Added Entries")
                    .font(.headline)

                List(userNames, id: \.self) { name in
                    HStack {
                        Image(systemName: "checkmark.seal")
                            .foregroundStyle(.green)
                        Text(name)
                        Spacer()
                        Button {
                            nameToRemove = name
                            showRemoveConfirmation = true
                        } label: {
                            Image(systemName: "trash")
                                .foregroundStyle(.red)
                        }
                        .buttonStyle(.plain)
                    }
                }
                .frame(maxHeight: 200)
                .listStyle(.bordered)
                .confirmationDialog(
                    "Remove \"\(nameToRemove ?? "")\" from trusted processes?",
                    isPresented: $showRemoveConfirmation,
                    titleVisibility: .visible
                ) {
                    Button("Remove", role: .destructive) {
                        if let name = nameToRemove {
                            removeProcess(name)
                        }
                    }
                    Button("Cancel", role: .cancel) {}
                }
            }
        }

        builtInListDisclosure
    }

    private var emptyUserListPlaceholder: some View {
        VStack(alignment: .leading, spacing: NickSpacing.xs) {
            Text("User-Added Entries")
                .font(.headline)
            Text("No user-added entries yet. Use the field above to add process names.")
                .foregroundStyle(.secondary)
        }
    }

    private var builtInListDisclosure: some View {
        DisclosureGroup("Built-in Trusted Processes (\(TrustedProcessList.builtIn.count))") {
            let sorted = TrustedProcessList.builtIn.sorted()
            LazyVStack(alignment: .leading, spacing: NickSpacing.xs) {
                ForEach(sorted, id: \.self) { name in
                    HStack(spacing: NickSpacing.xs) {
                        Image(systemName: "lock.fill")
                            .foregroundStyle(.secondary)
                            .imageScale(.small)
                        Text(name)
                            .foregroundStyle(.secondary)
                    }
                }
            }
            .padding(.top, NickSpacing.xs)
        }
    }

    // MARK: - Actions

    private func addProcess() {
        let trimmed = newProcessName.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty else { return }
        @Bindable var bindableEngine = engine
        bindableEngine.trustedProcessList.addUserTrusted(trimmed)
        newProcessName = ""
    }

    private func removeProcess(_ name: String) {
        @Bindable var bindableEngine = engine
        bindableEngine.trustedProcessList.removeUserTrusted(name)
        nameToRemove = nil
    }
}

// MARK: - Preview

#if DEBUG
#Preview {
    SettingsView()
        .environment(SecurityEngine())
}
#endif
