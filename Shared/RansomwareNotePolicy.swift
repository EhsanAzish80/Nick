import Foundation

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
