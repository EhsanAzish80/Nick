import AppKit
import Darwin
import SwiftUI

@MainActor
private final class UninstallModel: ObservableObject {
    enum Phase: Int, CaseIterable {
        case introduction
        case closeNick
        case removeProtection
        case deleteData
        case summary

        var title: String {
            switch self {
            case .introduction: "Introduction"
            case .closeNick: "Close Nick"
            case .removeProtection: "Remove protection"
            case .deleteData: "Delete data"
            case .summary: "Summary"
            }
        }
    }

    @Published var phase: Phase = .introduction
    @Published var status = "Ready to completely remove Nick."
    @Published var progress = 0.0
    @Published var isRunning = false
    @Published var completed = false
    @Published var restartRequired = false
    @Published var failure: String?

    private let fileManager = FileManager.default
    private var traceURL: URL {
        URL(fileURLWithPath: "/private/tmp", isDirectory: true)
            .appendingPathComponent("com.ehsanazish.nick.uninstall-trace-\(getuid()).log")
    }

    func uninstall() {
        guard !isRunning else { return }
        isRunning = true
        failure = nil
        Task { await runUninstall() }
    }

    private func runUninstall() async {
        do {
            try? fileManager.removeItem(at: traceURL)
            trace("Uninstall requested")
            let nickURL = try locateNickApplication()
            trace("Located Nick at \(nickURL.path)")

            phase = .closeNick
            progress = 0.15
            status = "Asking Nick to stop its background monitors…"

            phase = .removeProtection
            progress = 0.35
            status = "Removing the Network Filter and background registrations…"
            try await prepareNickForRemoval(at: nickURL)
            trace("Nick returned a successful protection-removal result")
            try await terminateNick()
            trace("Confirmed Nick is no longer running")

            phase = .deleteData
            progress = 0.62
            status = "Deleting Nick data, quarantine, logs, settings, and the app…"
            resetPrivacyPermissions()
            try await performAuthorizedPurge(nickURL: nickURL)
            trace("Authorized purge completed")

            phase = .summary
            progress = 1
            status = restartRequired
                ? "Nick was removed. Restart your Mac to finish removing its system extensions."
                : "Nick was completely removed. You can now install it as a new app."
            completed = true
            isRunning = false
            trace("Uninstallation complete; closing the uninstaller")
            try? await Task.sleep(for: .seconds(2))
            NSApp.terminate(nil)
        } catch {
            trace("Stopped with error: \(error.localizedDescription)")
            let diagnostic = (try? String(contentsOf: traceURL, encoding: .utf8))?
                .trimmingCharacters(in: .whitespacesAndNewlines)
            failure = diagnostic.map {
                "\(error.localizedDescription)\n\nDebug trace:\n\($0)"
            } ?? error.localizedDescription
            status = "Uninstallation stopped before completion."
            isRunning = false
        }
    }

    private func locateNickApplication() throws -> URL {
        let uninstallerURL = Bundle.main.bundleURL.standardizedFileURL
        let embeddedCandidate = uninstallerURL
            .deletingLastPathComponent() // Applications
            .deletingLastPathComponent() // Contents
            .deletingLastPathComponent() // Nick.app

        if Bundle(url: embeddedCandidate)?.bundleIdentifier == "com.ehsanazish.nick" {
            return embeddedCandidate
        }
        if let installed = NSWorkspace.shared.urlForApplication(
            withBundleIdentifier: "com.ehsanazish.nick"
        ) {
            return installed.standardizedFileURL
        }
        throw UninstallError.nickNotFound
    }

    private func terminateNick() async throws {
        let running = NSRunningApplication.runningApplications(
            withBundleIdentifier: "com.ehsanazish.nick"
        )
        trace("Found \(running.count) running Nick process(es)")
        for application in running {
            trace("Requesting termination of Nick pid \(application.processIdentifier)")
            application.terminate()
        }

        for _ in 0..<30 {
            if NSRunningApplication.runningApplications(
                withBundleIdentifier: "com.ehsanazish.nick"
            ).isEmpty {
                trace("Nick terminated normally")
                return
            }
            try await Task.sleep(for: .milliseconds(100))
        }

        for application in NSRunningApplication.runningApplications(
            withBundleIdentifier: "com.ehsanazish.nick"
        ) {
            trace("Force terminating Nick pid \(application.processIdentifier)")
            application.forceTerminate()
        }
        try await Task.sleep(for: .milliseconds(300))
        trace("Finished Nick termination pass")
    }

    private func prepareNickForRemoval(at nickURL: URL) async throws {
        // Nick must perform NetworkExtension and ServiceManagement cleanup from
        // its own signed bundle. Launch it in maintenance mode, never as the
        // normal user-facing application, and wait for it to quit before purge.
        let marker = URL(
            fileURLWithPath: "/private/tmp",
            isDirectory: true
        ).appendingPathComponent(
            "com.ehsanazish.nick.uninstall-result-\(getuid()).json"
        )
        try? fileManager.removeItem(at: marker)
        defer { try? fileManager.removeItem(at: marker) }
        trace("Using removal receipt \(marker.path)")

        // A normal Nick instance cannot be reused: it may have already passed
        // applicationDidFinishLaunching and can display its main window.
        try await terminateNick()

        let configuration = NSWorkspace.OpenConfiguration()
        configuration.activates = false
        configuration.addsToRecentItems = false
        configuration.createsNewApplicationInstance = true
        configuration.arguments = [
            "--prepare-uninstall",
            "--result",
            marker.path
        ]
        let maintenanceApplication = try await NSWorkspace.shared.openApplication(
            at: nickURL,
            configuration: configuration
        )
        trace("Launched Nick maintenance process pid \(maintenanceApplication.processIdentifier)")

        var receivedResult = false
        for _ in 0..<600 {
            if fileManager.fileExists(atPath: marker.path) {
                receivedResult = true
                trace("Removal receipt appeared")
                break
            }
            if maintenanceApplication.isTerminated {
                trace("Maintenance process terminated before receipt was observed")
                // Give the atomic receipt write one final moment to become visible.
                try await Task.sleep(for: .milliseconds(200))
                receivedResult = fileManager.fileExists(atPath: marker.path)
                break
            }
            try await Task.sleep(for: .milliseconds(100))
        }

        if !maintenanceApplication.isTerminated {
            trace("Maintenance process still running after receipt wait; requesting termination")
            maintenanceApplication.terminate()
            for _ in 0..<30 where !maintenanceApplication.isTerminated {
                try await Task.sleep(for: .milliseconds(100))
            }
        }
        if !maintenanceApplication.isTerminated {
            trace("Force terminating maintenance process")
            maintenanceApplication.forceTerminate()
        }

        guard receivedResult,
              let data = try? Data(contentsOf: marker),
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else {
            throw UninstallError.preparationFailed("Nick did not return a removal result.")
        }

        let failures = object["failures"] as? [String] ?? []
        restartRequired = object["restartRequired"] as? Bool ?? false
        trace("Parsed removal receipt with \(failures.count) failure(s)")
        if !failures.isEmpty {
            throw UninstallError.preparationFailed(failures.joined(separator: "\n"))
        }
    }

    private func trace(_ message: String) {
        let line = "\(ISO8601DateFormatter().string(from: Date())) [Uninstaller] \(message)\n"
        print("[Nick Uninstaller] \(message)")
        let data = Data(line.utf8)
        if !fileManager.fileExists(atPath: traceURL.path) {
            fileManager.createFile(atPath: traceURL.path, contents: data)
            return
        }
        guard let handle = try? FileHandle(forWritingTo: traceURL) else { return }
        defer { try? handle.close() }
        do {
            try handle.seekToEnd()
            try handle.write(contentsOf: data)
        } catch {
            print("[Nick Uninstaller] Could not append trace: \(error.localizedDescription)")
        }
    }

    private func performAuthorizedPurge(nickURL: URL) async throws {
        guard Bundle(url: nickURL)?.bundleIdentifier == "com.ehsanazish.nick" else {
            throw UninstallError.invalidNickApplication
        }

        let home = fileManager.homeDirectoryForCurrentUser.path
        let uninstallerURL = Bundle.main.bundleURL.standardizedFileURL
        var paths = [
            "/Library/Application Support/com.ehsanazish.nick",
            "/Library/LaunchDaemons/com.ehsanazish.nick.helper.plist",
            "/Library/PrivilegedHelperTools/com.ehsanazish.nick.helper",
            "\(home)/Library/Application Support/com.ehsanazish.nick",
            // Pre-4.0 builds used this non-bundle-named directory.
            "\(home)/Library/Application Support/Nick",
            "\(home)/Library/Logs/Nick",
            "\(home)/Library/Caches/com.ehsanazish.nick",
            "\(home)/Library/Caches/com.ehsanazish.nick.findersync",
            "\(home)/Library/Caches/com.ehsanazish.nick.uninstaller",
            "\(home)/Library/WebKit/com.ehsanazish.nick",
            "\(home)/Library/HTTPStorages/com.ehsanazish.nick",
            "\(home)/Library/HTTPStorages/com.ehsanazish.nick.binarycookies",
            "\(home)/Library/Cookies/com.ehsanazish.nick.binarycookies",
            "\(home)/Library/Preferences/com.ehsanazish.nick.plist",
            "\(home)/Library/Preferences/com.ehsanazish.nick.findersync.plist",
            "\(home)/Library/Preferences/com.ehsanazish.nick.uninstaller.plist",
            "\(home)/Library/Saved Application State/com.ehsanazish.nick.savedState",
            "\(home)/Library/Saved Application State/com.ehsanazish.nick.uninstaller.savedState",
            "\(home)/Library/Group Containers/group.com.ehsanazish.nick",
            "\(home)/Library/Containers/com.ehsanazish.nick",
            "\(home)/Library/Containers/com.ehsanazish.nick.findersync",
            "\(home)/Library/Application Scripts/com.ehsanazish.nick",
            "\(home)/Library/Application Scripts/com.ehsanazish.nick.findersync",
            "\(home)/Library/Application Scripts/group.com.ehsanazish.nick",
            "\(home)/Library/LaunchAgents/com.ehsanazish.nick.plist",
            nickURL.path
        ]
        // When the uninstaller is copied out of Nick.app as a standalone tool,
        // remove that bundle too. When it remains embedded, deleting Nick.app
        // already covers it.
        if !uninstallerURL.path.hasPrefix(nickURL.path + "/") {
            paths.append(uninstallerURL.path)
        }
        paths = Array(Set(paths))

        let removeArguments = paths.map(shellQuote).joined(separator: " ")
        let canaryRoots = ["Desktop", "Documents", "Downloads", "Pictures"]
            .map { shellQuote("\(home)/\($0)") }
            .joined(separator: " ")
        let command = """
        /bin/launchctl bootout system/com.ehsanazish.nick.helper 2>/dev/null || true
        /usr/bin/pkill -x NickHelper 2>/dev/null || true
        /usr/bin/pkill -x Nick 2>/dev/null || true
        /System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -u \(shellQuote(nickURL.path)) 2>/dev/null || true
        /bin/rm -rf -- \(removeArguments)
        for root in \(canaryRoots); do
          if [ -d "$root" ]; then
            /usr/bin/find "$root" -maxdepth 1 -type f -name '.~nick_canary_*.tmp' -delete
          fi
        done
        /usr/bin/find /Library/Logs/DiagnosticReports -type f \\( -name 'Nick-*.ips' -o -name 'NickExtension-*.ips' -o -name 'NickNetFilter-*.ips' -o -name 'com.ehsanazish.nick.*.ips' \\) -delete 2>/dev/null || true
        /usr/sbin/pkgutil --forget com.ehsanazish.nick >/dev/null 2>&1 || true
        /usr/sbin/pkgutil --forget com.ehsanazish.nick.uninstaller >/dev/null 2>&1 || true
        """

        let appleScript = "do shell script \(appleScriptString(command)) with administrator privileges"
        let process = Process()
        let errorPipe = Pipe()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        process.arguments = ["-e", appleScript]
        process.standardError = errorPipe
        try process.run()
        process.waitUntilExit()

        guard process.terminationStatus == 0 else {
            let data = errorPipe.fileHandleForReading.readDataToEndOfFile()
            let message = String(data: data, encoding: .utf8)?
                .trimmingCharacters(in: .whitespacesAndNewlines)
            throw UninstallError.authorizedRemovalFailed(
                message?.isEmpty == false ? message! : "Administrator approval was cancelled."
            )
        }
    }

    /// TCC is per-user, so this deliberately runs before the administrator
    /// operation rather than from its root shell.
    private func resetPrivacyPermissions() {
        for bundleID in [
            "com.ehsanazish.nick",
            "com.ehsanazish.nick.NickExtension",
            "com.ehsanazish.nick.NickNetFilter"
        ] {
            // `All` does not consistently remove stale Full Disk Access rows
            // for bundled system extensions. Reset the FDA service explicitly
            // before the general per-bundle reset.
            for service in ["SystemPolicyAllFiles", "All"] {
                let process = Process()
                process.executableURL = URL(fileURLWithPath: "/usr/bin/tccutil")
                process.arguments = ["reset", service, bundleID]
                process.standardOutput = FileHandle.nullDevice
                process.standardError = FileHandle.nullDevice
                try? process.run()
                process.waitUntilExit()
            }
        }
    }

    private func shellQuote(_ value: String) -> String {
        "'" + value.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }

    private func appleScriptString(_ value: String) -> String {
        let escaped = value
            .replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
            .replacingOccurrences(of: "\n", with: "\\n")
        return "\"\(escaped)\""
    }
}

private enum UninstallError: LocalizedError {
    case nickNotFound
    case invalidNickApplication
    case preparationTimedOut
    case preparationFailed(String)
    case authorizedRemovalFailed(String)

    var errorDescription: String? {
        switch self {
        case .nickNotFound:
            "Nick.app could not be found. Run this uninstaller from inside Nick.app."
        case .invalidNickApplication:
            "The selected app is not a valid copy of Nick."
        case .preparationTimedOut:
            "Nick did not finish disabling its protections. Nothing was deleted."
        case let .preparationFailed(message):
            "Nick could not safely prepare for removal:\n\(message)"
        case let .authorizedRemovalFailed(message):
            "The authorized removal failed:\n\(message)"
        }
    }
}

struct UninstallerView: View {
    @StateObject private var model = UninstallModel()
    @State private var confirmed = false

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider()
            HStack(spacing: 0) {
                phaseList
                Divider()
                content
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
        }
        .background(Color(nsColor: .windowBackgroundColor))
        .interactiveDismissDisabled(model.isRunning)
        .confirmationDialog(
            "Permanently remove Nick?",
            isPresented: $confirmed,
            titleVisibility: .visible
        ) {
            Button("Uninstall Nick", role: .destructive) {
                model.uninstall()
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("This permanently deletes Nick’s quarantine, security history, settings, baselines, and all installed protection components.")
        }
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(model.isRunning ? "Uninstalling Nick" : "Nick Uninstaller")
                .font(.title2.bold())
            ProgressView(value: model.progress)
                .progressViewStyle(.linear)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.horizontal, 22)
        .padding(.vertical, 16)
    }

    private var phaseList: some View {
        VStack(alignment: .leading, spacing: 18) {
            ForEach(UninstallModel.Phase.allCases, id: \.rawValue) { phase in
                Label {
                    Text(phase.title)
                } icon: {
                    Image(systemName: phase.rawValue < model.phase.rawValue
                          ? "checkmark.circle.fill"
                          : phase == model.phase ? "circle.fill" : "circle")
                        .foregroundStyle(phase.rawValue <= model.phase.rawValue ? Color.accentColor : .secondary)
                }
            }
            Spacer()
            Label("Nick", systemImage: "shield.fill")
                .font(.headline)
        }
        .padding(22)
        .frame(width: 205, alignment: .leading)
        .background(Color(nsColor: .controlBackgroundColor))
    }

    private var content: some View {
        VStack(spacing: 0) {
            Spacer()
            VStack(spacing: 12) {
                Image(systemName: model.completed ? "checkmark.circle.fill" : "trash")
                    .font(.system(size: 42))
                    .foregroundStyle(model.completed ? .green : model.failure == nil ? Color.accentColor : .red)
                    .accessibilityHidden(true)

                Text(model.completed ? "Uninstallation Complete" : model.isRunning ? model.phase.title : "Uninstall Nick")
                    .font(.title2.bold())

                Text(model.status)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .frame(maxWidth: 390)

                if let failure = model.failure {
                    Text(failure)
                        .font(.callout)
                        .foregroundStyle(.red)
                        .multilineTextAlignment(.center)
                        .textSelection(.enabled)
                        .frame(maxWidth: 430)
                }

                if model.isRunning {
                    ProgressView()
                        .controlSize(.regular)
                        .padding(.top, 4)
                }
            }
            Spacer()
            Divider()
            HStack {
                Text(model.completed
                     ? "Nick and its data were removed."
                     : "Administrator approval is required.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                Spacer()
                if model.completed {
                    Button("Close") { NSApp.terminate(nil) }
                        .keyboardShortcut(.defaultAction)
                } else if !model.isRunning {
                    Button("Cancel") { NSApp.terminate(nil) }
                        .keyboardShortcut(.cancelAction)
                    Button("Uninstall…", role: .destructive) {
                        confirmed = true
                    }
                    .keyboardShortcut(.defaultAction)
                }
            }
            .padding(16)
            .background(.bar)
        }
    }
}
