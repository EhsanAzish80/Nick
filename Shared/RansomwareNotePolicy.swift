import Darwin
import Foundation

struct ProcessInstanceIdentity: Equatable, Hashable, Sendable {
    let pid: Int32
    let startSeconds: UInt64
    let startMicroseconds: UInt64
    /// Kernel pid-version copied from the Endpoint Security audit token.
    /// Zero is retained for legacy callers that capture outside an ES message.
    let pidVersion: Int32
    let processGroupID: Int32
    let sessionID: UInt32

    init(
        pid: Int32,
        startSeconds: UInt64,
        startMicroseconds: UInt64,
        pidVersion: Int32 = 0,
        processGroupID: Int32 = 0,
        sessionID: UInt32 = 0
    ) {
        self.pid = pid
        self.startSeconds = startSeconds
        self.startMicroseconds = startMicroseconds
        self.pidVersion = pidVersion
        self.processGroupID = processGroupID
        self.sessionID = sessionID
    }

    static func capture(pid: Int32) -> Self? {
        guard pid > 1 else { return nil }
        var info = proc_bsdinfo()
        let size = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, Int32(MemoryLayout<proc_bsdinfo>.size))
        guard size == MemoryLayout<proc_bsdinfo>.size else { return nil }
        return Self(
            pid: pid,
            startSeconds: info.pbi_start_tvsec,
            startMicroseconds: info.pbi_start_tvusec,
            pidVersion: 0,
            processGroupID: Int32(bitPattern: info.pbi_pgid),
            sessionID: 0
        )
    }
}

enum RansomwareTerminationPolicy {
    /// Developer-ID validation is performed off the ES authorization path.
    /// A copied Team ID or self-signed certificate never reaches this exemption.
    static func shouldTerminate(
        isBlockRecommendation: Bool,
        developerIDValidated: Bool,
        isApprovedDevelopmentBuild: Bool = false
    ) -> Bool {
        isBlockRecommendation && !developerIDValidated && !isApprovedDevelopmentBuild
    }

    static func maySignalKill(expected: ProcessInstanceIdentity?, current: ProcessInstanceIdentity?) -> Bool {
        guard let expected, let current else { return false }
        guard expected.pid == current.pid,
              expected.startSeconds == current.startSeconds,
              expected.startMicroseconds == current.startMicroseconds
        else { return false }
        // pidversion is authoritative when both identities came from ES. A
        // remediation-time proc snapshot cannot recover it, so zero means
        // unavailable rather than mismatch.
        return expected.pidVersion == 0 || current.pidVersion == 0
            || expected.pidVersion == current.pidVersion
    }
}

enum BrowserDownloadRenamePolicy {
    static func shouldIgnoreDestination(
        destination: String,
        developerIDValidated: Bool,
        teamID: String?,
        signingID: String?
    ) -> Bool {
        guard developerIDValidated,
              let teamID, let signingID,
              ["crdownload", "download", "part", "partial", "opdownload"]
                .contains((destination as NSString).pathExtension.lowercased()) else { return false }
        if teamID == "EQHXZ8M8AV" {
            return signingID == "com.google.Chrome" || signingID.hasPrefix("com.google.Chrome.")
        }
        if teamID == "APPLE_PLATFORM" {
            return signingID == "com.apple.Safari" || signingID.hasPrefix("com.apple.WebKit.")
        }
        return false
    }
}

/// Excludes validated Apple storage-maintenance actors whose normal work is a
/// stream of atomic renames. Identity validation happens before this policy;
/// a copied binary or process using one of these names does not qualify.
enum ScopedUpdaterRenamePolicy {
    static func matchesWhatsAppStagedResourceRename(actorIsAppleDitto: Bool,
                                                   validatedBundleTeam: String?,
                                                   source: String, destination: String) -> Bool {
        guard actorIsAppleDitto, validatedBundleTeam == "57T9237FN3",
              (source as NSString).deletingLastPathComponent == (destination as NSString).deletingLastPathComponent,
              (source as NSString).lastPathComponent.hasPrefix(".BC.T_"),
              (destination as NSString).pathExtension == "mom" else { return false }
        let p = URL(fileURLWithPath: destination).standardizedFileURL.pathComponents
        return p.count > 12 && p[1] == "Users"
            && p[3...7].elementsEqual(["Library", "Caches", "net.whatsapp.WhatsApp", "org.sparkle-project.Sparkle", "Installation"])
            && !p[8].isEmpty && p[9...10].elementsEqual(["WhatsApp.app", "Contents"])
            && p.contains("Resources") && p.contains(where: { $0.hasSuffix(".momd") })
    }
    static func matchesWhatsAppResourceRename(
        actorIsAppleDitto: Bool, updaterValidated: Bool, updaterPath: String,
        updaterTeamID: String?, source: String, destination: String
    ) -> Bool {
        let root = "/Applications/WhatsApp.app/Contents/"
        guard actorIsAppleDitto, updaterValidated, updaterTeamID == "57T9237FN3",
              updaterPath.hasPrefix(root + "Frameworks/Sparkle.framework/Versions/"),
              updaterPath.hasSuffix("/Autoupdate"),
              (destination as NSString).pathExtension.lowercased() == "mom" else { return false }
        return [source, destination].allSatisfy {
            URL(fileURLWithPath: $0).resolvingSymlinksInPath().standardizedFileURL.path.hasPrefix(root)
        }
    }

    static func matchesCodexSessionCompression(
        developerIDValidated: Bool, teamID: String?, signingID: String?,
        source: String, destination: String
    ) -> Bool {
        guard developerIDValidated, teamID == "2DC432GLL2", signingID == "codex" else { return false }
        let src = URL(fileURLWithPath: source).standardizedFileURL
        let dst = URL(fileURLWithPath: destination).standardizedFileURL
        let parent = src.deletingLastPathComponent()
        let parts = parent.pathComponents
        guard parent == dst.deletingLastPathComponent(), parts.count == 8,
              parts[1] == "Users", parts[3] == ".codex", parts[4] == "sessions",
              parts[5].count == 4, parts[6].count == 2, parts[7].count == 2,
              parts[5...7].allSatisfy({ $0.allSatisfy(\.isNumber) }),
              src.lastPathComponent.hasPrefix("rollout-compress-"), src.pathExtension == "tmp",
              dst.lastPathComponent.hasPrefix("rollout-"), dst.lastPathComponent.hasSuffix(".jsonl.zst")
        else { return false }
        return true
    }

    static func matchesOpenAISparkleRename(
        processPath: String, signingID: String?, teamID: String?,
        source: String, destination: String
    ) -> Bool {
        guard teamID == "2DC432GLL2" else { return false }
        let sparkleSuffix: String
        switch signingID {
        case "Autoupdate": sparkleSuffix = "/Autoupdate"
        case "org.sparkle-project.Sparkle.Updater":
            sparkleSuffix = "/Updater.app/Contents/MacOS/Updater"
        default: return false
        }
        return ["/Applications/ChatGPT.app", "/Applications/Codex.app"].contains { app in
            let framework = app + "/Contents/Frameworks/Sparkle.framework/Versions/"
            guard processPath.hasPrefix(framework), processPath.hasSuffix(sparkleSuffix) else { return false }
            let root = app + "/Contents/"
            return [source, destination].allSatisfy { path in
                URL(fileURLWithPath: path).resolvingSymlinksInPath().standardizedFileURL.path
                    .hasPrefix(root)
            }
        }
    }
}

enum AppleSyncRenamePolicy {
    static func isRoutineMaintenanceRename(
        isPlatformBinary: Bool, signingID: String?, source: String, destination: String
    ) -> Bool {
        guard isPlatformBinary else { return false }
        func canonicalPath(_ path: String) -> String {
            let resolved = URL(fileURLWithPath: path).standardizedFileURL.path
            return resolved.hasPrefix("/var/") ? "/private" + resolved : resolved
        }
        let source = canonicalPath(source)
        let destination = canonicalPath(destination)
        let suffix = (destination as NSString).pathExtension.lowercased()
        switch signingID {
        case "com.apple.logd":
            let root = "/private/var/db/diagnostics/"
            return suffix == "tracev3" && source.hasPrefix(root) && destination.hasPrefix(root)
        case "com.apple.system_installd":
            if isSystemIconInstallation(source, destination) { return true }
            let root = "/Applications/Xcode.app/Contents/"
            return suffix == "icns" && source.hasPrefix(root) && destination.hasPrefix(root)
        case "com.apple.mds_stores":
            return ["/.Spotlight-V100/", "/System/Volumes/Data/.Spotlight-V100/"]
                .contains { source.hasPrefix($0) && destination.hasPrefix($0) }
        case "com.apple.bird", "com.apple.cloudd":
            if signingID == "com.apple.bird", isCloudDocsStagingTransfer(source, destination) { return true }
            return ["map", "meta"].contains(suffix) && sameUserMaintenanceDirectory(
                source, destination, directory: "Library/Application Support/CloudDocs"
            )
        case "com.apple.fileproviderd":
            if isCloudBackupHydration(source, destination) { return true }
            if isNextBuildStagingTransfer(source, destination) { return true }
            return suffix == "meta" && sameUserMaintenanceDirectory(
                source, destination, directory: "Library/Application Support/FileProvider"
            )
        case "com.apple.geod":
            let src = URL(fileURLWithPath: source).pathComponents
            guard src.count == 9, src[1] == "Users", src[3...7].elementsEqual(["Library", "Containers", "com.apple.geod", "Data", "tmp"]),
                  UUID(uuidString: src[8]) != nil else { return false }
            let root = "/Users/\(src[2])/Library/Caches/GeoServices/"
            let expected = suffix == "styl" ? "Resources" : (["iconconfigpack", "icondatapack"].contains(suffix) ? "RegionalResources" : "")
            return !expected.isEmpty && (destination as NSString).deletingLastPathComponent == root + expected
        case "com.apple.mobileassetd":
            return isSimulatorMaintenance(source, destination, asset: true)
        case "com.apple.springboard":
            return isSimulatorMaintenance(source, destination, asset: false)
        case "com.apple.parsec-fbf":
            return suffix == "processing" && sameUserMaintenanceDirectory(
                source, destination, directory: "Library/Caches/com.apple.parsec-fbf"
            )
        default:
            return false
        }
    }

    private static func isSystemIconInstallation(_ source: String, _ destination: String) -> Bool {
        let root = "/Library/Apple/System/Library/InstallerSandboxes/.PKInstallSandboxManager-SystemSoftware/"
        guard source.hasPrefix(root), destination.hasPrefix(root),
              (source as NSString).deletingLastPathComponent == (destination as NSString).deletingLastPathComponent,
              (source as NSString).lastPathComponent.hasPrefix(".BC.T_"),
              (destination as NSString).pathExtension == "icns" else { return false }
        let relative = String(destination.dropFirst(root.count)).split(separator: "/").map(String.init)
        guard let sandbox = relative.first, sandbox.hasSuffix(".activeSandbox"),
              UUID(uuidString: String(sandbox.dropLast(".activeSandbox".count))) != nil else { return false }
        return relative.dropFirst().dropLast().elementsEqual([
            "Root", "System", "Library", "CoreServices", "CoreTypes.bundle", "Contents", "Library",
            "MobileDevices.bundle", "Contents", "Resources"
        ])
    }

    private static func fileProviderStagingUser(_ source: String) -> String? {
        let p = URL(fileURLWithPath: source).pathComponents
        guard p.count == 11, p[1] == "Users",
              p[3...5].elementsEqual(["Library", "Application Support", "FileProvider"]),
              UUID(uuidString: p[6]) != nil, p[7...9].elementsEqual(["wharf", "wharf", "propagate"]),
              !p[10].isEmpty, p[10].allSatisfy(\.isNumber) else { return nil }
        return p[2]
    }

    private static func isCloudBackupHydration(_ source: String, _ destination: String) -> Bool {
        guard let user = fileProviderStagingUser(source) else { return false }
        let root = "/Users/\(user)/Library/Mobile Documents/57T9237FN3~net~whatsapp~WhatsApp/Accounts/"
        guard destination.hasPrefix(root) else { return false }
        let p = String(destination.dropFirst(root.count)).split(separator: "/").map(String.init)
        return p.count == 3 && !p[0].isEmpty && p[0].allSatisfy(\.isNumber)
            && p[1] == "backup" && p[2] == "ExtChatDatabase.sqlite.enc"
    }

    private static func isSimulatorMaintenance(_ source: String, _ destination: String, asset: Bool) -> Bool {
        let p = URL(fileURLWithPath: source).pathComponents
        guard p.count > 8, p[1] == "Users",
              p[3...6].elementsEqual(["Library", "Developer", "CoreSimulator", "Devices"]),
              UUID(uuidString: p[7]) != nil, p[8] == "data" else { return false }
        let root = "/" + p[1...8].joined(separator: "/") + "/"
        guard destination.hasPrefix(root) else { return false }
        if !asset {
            let name = (destination as NSString).lastPathComponent
            return (source as NSString).deletingLastPathComponent == root + "tmp"
                && (source as NSString).lastPathComponent.hasPrefix(name + ".")
                && (destination as NSString).pathExtension == "cpbitmap"
                && destination.hasPrefix(root + "Library/Caches/MappedImageCache/com.apple.springboard-")
        }
        let assets = root + "private/var/MobileAsset/AssetsV2/"
        guard source.hasPrefix(assets + "staging/"), destination.hasPrefix(assets),
              (source as NSString).deletingLastPathComponent == assets + "staging" else { return false }
        let relative = String(destination.dropFirst(assets.count)).split(separator: "/").map(String.init)
        guard relative.count == 3, relative[0].hasPrefix("com_apple_MobileAsset_"),
              relative[1] == "purpose_auto", relative[2].hasSuffix(".asset") else { return false }
        let hash = String(relative[2].dropLast(".asset".count))
        let prefix = relative[0] + "." + hash + ".auto."
        let staged = (source as NSString).lastPathComponent
        return hash.count == 40 && hash.allSatisfy(\.isHexDigit)
            && staged.hasPrefix(prefix) && UUID(uuidString: String(staged.dropFirst(prefix.count))) != nil
    }

    private static func isNextBuildStagingTransfer(_ source: String, _ destination: String) -> Bool {
        let parts = URL(fileURLWithPath: source).pathComponents
        guard parts.count == 11, parts[1] == "Users",
              parts[3...5].elementsEqual(["Library", "Application Support", "FileProvider"]),
              UUID(uuidString: parts[6]) != nil,
              parts[7...9].elementsEqual(["wharf", "wharf", "propagate"]),
              !parts[10].isEmpty, parts[10].allSatisfy(\.isNumber) else { return false }
        let root = "/Users/\(parts[2])/Documents/"
        guard destination.hasPrefix(root), (destination as NSString).pathExtension == "rsc" else { return false }
        let relative = String(destination.dropFirst(root.count))
        // File Provider hydrates generated Next.js output through its private
        // numeric staging slots. Do not exempt arbitrary document renames.
        return relative.contains("/.next/server/app/")
    }

    private static func isCloudDocsStagingTransfer(_ source: String, _ destination: String) -> Bool {
        let parts = URL(fileURLWithPath: source).pathComponents
        guard parts.count > 3, parts[1] == "Users" else { return false }
        let library = "/Users/\(parts[2])/Library/"
        let fileProvider = library + "Application Support/FileProvider/"
        let cloud = library + "Application Support/CloudDocs/session/"
        if source.hasPrefix(fileProvider) {
            let relative = String(source.dropFirst(fileProvider.count)).split(separator: "/").map(String.init)
            if relative.count == 5, UUID(uuidString: relative[0]) != nil,
               relative[1...3].elementsEqual(["wharf", "wharf", "propagate"]),
               !relative[4].isEmpty, relative[4].allSatisfy(\.isNumber),
               (destination as NSString).deletingLastPathComponent == cloud + "i",
               ["pcm", "flat", "meta"].contains((destination as NSString).pathExtension) { return true }
        }
        // A downloaded item moves from CloudDocs' private staging slot to
        // the same user's iCloud provider DownloadStage, preserving its name.
        let download = library + "Group Containers/group.com.apple.iCloudDrive/File Provider Storage/DownloadStage/"
        let name = (destination as NSString).lastPathComponent
        return name.hasPrefix("content-") && source == cloud + "d/" + name + "/item"
            && (destination as NSString).deletingLastPathComponent + "/" == download
    }

    private static func sameUserMaintenanceDirectory(
        _ source: String, _ destination: String, directory: String
    ) -> Bool {
        let parts = URL(fileURLWithPath: source).pathComponents
        guard parts.count > 3, parts[1] == "Users" else { return false }
        let root = "/Users/\(parts[2])/\(directory)/"
        return source.hasPrefix(root) && destination.hasPrefix(root)
    }

    static func displayRole(signingID: String?) -> String? {
        switch signingID {
        case "com.apple.bird": return "iCloud Drive (bird)"
        case "com.apple.cloudd": return "iCloud Drive (cloudd)"
        case "com.apple.fileproviderd": return "File Provider (fileproviderd)"
        case "com.apple.mds_stores": return "Spotlight indexing (mds_stores)"
        case "com.apple.geod": return "Apple Maps data (geod)"
        case "com.apple.mobileassetd": return "Simulator asset service"
        case "com.apple.springboard": return "Simulator SpringBoard"
        case "com.apple.parsec-fbf": return "Apple system data (parsec-fbf)"
        default:
            guard let signingID,
                  signingID.hasPrefix("com.apple.FileProvider.")
                    || signingID.hasPrefix("com.apple.fileprovider.") else { return nil }
            return "File Provider extension"
        }
    }
}

enum DevelopmentBuildRansomwarePolicy {
    private static let buildArtifactExtensions: Set<String> = [
        "a", "cmake", "d", "dylib", "make", "ninja_deps", "ninja_log",
        "o", "obj", "pch", "swiftdeps", "swiftmodule", "tmp"
    ]

    static func isAlertOnly(
        processPath: String,
        destination: String,
        repositoryRoot: String?,
        actorValidated: Bool
    ) -> Bool {
        guard let repositoryRoot,
              buildArtifactExtensions.contains((destination as NSString).pathExtension.lowercased()),
              actorValidated || isHomebrewCellarExecutable(processPath) else { return false }
        let root = URL(fileURLWithPath: repositoryRoot).standardizedFileURL.path
        let path = URL(fileURLWithPath: destination).standardizedFileURL.path
        return path == root || path.hasPrefix(root + "/")
    }

    private static func isHomebrewCellarExecutable(_ path: String) -> Bool {
        let normalized = URL(fileURLWithPath: path).standardizedFileURL.path
        return normalized.hasPrefix("/opt/homebrew/Cellar/")
            || normalized.hasPrefix("/usr/local/Cellar/")
    }
}

/// Conservative filename policy for ransomware-note detection.
///
/// Common developer files such as README.md, recovery headers, YARA rules, and
/// Nick's own RansomwareDetector source must never be treated as ransom notes.
/// A filename is suspicious only when it is a document-like file whose stem
/// contains a strong, explicit decryption phrase.
enum RansomwareNotePolicy {
    private static let noteExtensions: Set<String> = [
        "txt", "md", "html", "htm", "hta", "rtf",
    ]

    // Keep detector policy phrases out of shipped Mach-O string tables. The
    // bundled signed YARA rules remain the canonical human-readable source.
    private static let encodedStrongPhrases = [
        "cmVhZG1lX2RlY3J5cHQ=", "cmVhZF9tZV9kZWNyeXB0",
        "ZGVjcnlwdF9pbnN0cnVjdGlvbnM=", "ZGVjcnlwdGlvbl9pbnN0cnVjdGlvbnM=",
        "aG93X3RvX2RlY3J5cHQ=", "aG93dG9fZGVjcnlwdA==", "aGVscF9kZWNyeXB0",
        "cmVzdG9yZV95b3VyX2ZpbGVz", "cmVjb3Zlcl95b3VyX2ZpbGVz",
        "eW91cl9maWxlc19hcmVfZW5jcnlwdGVk", "ZmlsZXNfYXJlX2VuY3J5cHRlZA==",
        "cmFuc29tX25vdGU=",
    ]

    private static let strongPhrases: [String] = encodedStrongPhrases.compactMap {
        Data(base64Encoded: $0).flatMap { String(data: $0, encoding: .utf8) }
    }

    static func matches(filename: String) -> Bool {
        let url = URL(fileURLWithPath: filename)
        guard noteExtensions.contains(url.pathExtension.lowercased()) else {
            return false
        }

        let stem = url.deletingPathExtension().lastPathComponent.lowercased()
        let normalized = stem
            .replacingOccurrences(
                of: #"[^a-z0-9]+"#,
                with: "_",
                options: .regularExpression
            )
            .trimmingCharacters(in: CharacterSet(charactersIn: "_"))

        return strongPhrases.contains { phrase in
            normalized == phrase
                || normalized.hasPrefix(phrase + "_")
                || normalized.hasSuffix("_" + phrase)
        }
    }
}

/// Recognises renames that give a file a new, uncommon extension — the
/// signature of rename-based ransomware — while ignoring atomic saves,
/// download completion, and routine format conversions.
enum RansomwareRenamePolicy {
    /// The extension a rename introduces, or `nil` when the rename is routine.
    static func introducedExtension(source: String, destination: String) -> String? {
        let sourceName = (source as NSString).lastPathComponent
        let destinationName = (destination as NSString).lastPathComponent
        guard !destinationName.hasPrefix(".") else { return nil }

        let sourceExtension = (sourceName as NSString).pathExtension.lowercased()
        let destinationExtension = (destinationName as NSString).pathExtension.lowercased()
        let destinationStemExtension = ((destinationName as NSString)
            .deletingPathExtension as NSString).pathExtension.lowercased()
        // Finalising a temporary path by removing exactly one suffix is an
        // atomic-save shape even when a helper such as `mv` performs the
        // rename for the writer (`archive.tar.zst.tmp` -> `archive.tar.zst`).
        // Content replacement evidence is evaluated separately by
        // BehaviorTracker and still overrides this path-only exemption.
        let sourceWithoutTemporarySuffix = (source as NSString).deletingPathExtension
        if temporaryExtensions.contains(sourceExtension),
           URL(fileURLWithPath: sourceWithoutTemporarySuffix).standardizedFileURL.path
               == URL(fileURLWithPath: destination).standardizedFileURL.path {
            return nil
        }
        // A temporary/hidden file renamed over `document.ext.locked` is the
        // write-then-swap ransomware shape. Preserve the ordinary atomic-save
        // exemption for `.tmp -> final.cmake`, but count an extension appended
        // to an already named destination.
        let appendsToExistingExtension = !destinationStemExtension.isEmpty
        guard !destinationExtension.isEmpty,
              destinationExtension != sourceExtension,
              destinationExtension.count <= 16,
              (!sourceName.hasPrefix(".") || appendsToExistingExtension),
              (!temporaryExtensions.contains(sourceExtension) || appendsToExistingExtension),
              !sourceName.contains(".sb-"), !destinationName.contains(".sb-"),
              !routineDestinationExtensions.contains(destinationExtension)
        else { return nil }
        return destinationExtension
    }

    private static let temporaryExtensions: Set<String> = [
        "tmp", "temp", "download", "crdownload", "part", "partial", "opdownload",
        "swp", "swx", "lock", "new", "writing", "inprogress", "processing",
    ]

    /// Formats applications routinely produce by renaming. Ransomware never
    /// "encrypts" into these.
    private static let routineDestinationExtensions: Set<String> = [
        "json", "plist", "xml", "db", "sqlite", "sqlite3", "wal", "shm", "log", "txt",
        "md", "csv", "html", "css", "js", "ts", "swift", "h", "m", "c", "cpp", "o",
        "make", "map", "tmp", "temp", "processing", "cmake",
        "png", "jpg", "jpeg", "heic", "gif", "webp", "mov", "mp4", "m4a", "mp3", "wav",
        "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "pages", "numbers", "key",
        "zip", "gz", "tar", "dmg", "pkg", "app", "bak", "old", "orig", "backup",
    ]
}
