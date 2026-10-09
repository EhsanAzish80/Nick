import Darwin
import Foundation

struct ProcessInstanceIdentity: Equatable, Sendable {
    let pid: Int32
    let startSeconds: UInt64
    let startMicroseconds: UInt64

    static func capture(pid: Int32) -> Self? {
        guard pid > 1 else { return nil }
        var info = proc_bsdinfo()
        let size = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, Int32(MemoryLayout<proc_bsdinfo>.size))
        guard size == MemoryLayout<proc_bsdinfo>.size else { return nil }
        return Self(
            pid: pid,
            startSeconds: info.pbi_start_tvsec,
            startMicroseconds: info.pbi_start_tvusec
        )
    }
}

enum RansomwareTerminationPolicy {
    /// Developer-ID validation is performed off the ES authorization path.
    /// A copied Team ID or self-signed certificate never reaches this exemption.
    static func shouldTerminate(isBlockRecommendation: Bool, developerIDValidated: Bool) -> Bool {
        isBlockRecommendation && !developerIDValidated
    }

    static func maySignalKill(expected: ProcessInstanceIdentity?, current: ProcessInstanceIdentity?) -> Bool {
        guard let expected, let current else { return false }
        return expected == current
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

    private static let strongPhrases = [
        "readme_decrypt",
        "read_me_decrypt",
        "decrypt_instructions",
        "decryption_instructions",
        "how_to_decrypt",
        "howto_decrypt",
        "help_decrypt",
        "restore_your_files",
        "recover_your_files",
        "your_files_are_encrypted",
        "files_are_encrypted",
        "ransom_note",
    ]

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
        guard !sourceName.hasPrefix("."), !destinationName.hasPrefix(".") else { return nil }

        let sourceExtension = (sourceName as NSString).pathExtension.lowercased()
        let destinationExtension = (destinationName as NSString).pathExtension.lowercased()
        guard !destinationExtension.isEmpty,
              destinationExtension != sourceExtension,
              destinationExtension.count <= 16,
              !temporaryExtensions.contains(sourceExtension),
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
