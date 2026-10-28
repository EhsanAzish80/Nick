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
        "swp", "swx", "lock", "new", "writing", "inprogress",
    ]

    /// Formats applications routinely produce by renaming. Ransomware never
    /// "encrypts" into these.
    private static let routineDestinationExtensions: Set<String> = [
        "json", "plist", "xml", "db", "sqlite", "sqlite3", "wal", "shm", "log", "txt",
        "md", "csv", "html", "css", "js", "ts", "swift", "h", "m", "c", "cpp", "o",
        "make",
        "png", "jpg", "jpeg", "heic", "gif", "webp", "mov", "mp4", "m4a", "mp3", "wav",
        "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "pages", "numbers", "key",
        "zip", "gz", "tar", "dmg", "pkg", "app", "bak", "old", "orig", "backup",
    ]
}
