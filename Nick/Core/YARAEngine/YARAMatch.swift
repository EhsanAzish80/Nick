// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation

// MARK: - YARAMatch

/// Represents a single YARA rule match against a file.
///
/// Produced by `YARAEngine.scanFile(at:)` when at least one compiled YARA rule
/// triggers on the file's contents. Each match corresponds to exactly one rule;
/// a single file can generate multiple matches if several rules trigger.
///
/// - Note: Used as the payload of a `ThreatSignal` emitted by `YARAEngine`.
struct YARAMatch: Sendable, Equatable {

    // MARK: - Properties

    /// Name of the YARA rule that matched.
    let ruleName: String

    /// Tags attached to the matched rule (e.g. `["malware", "ransomware"]`).
    let tags: [String]

    /// Absolute path of the scanned file.
    let filePath: String

    /// Rule-level metadata key-value pairs from the `.yar` source.
    let metadata: [String: String]
}

// MARK: - YARAError

/// Errors thrown by `YARAEngine` and `YARAScanner`.
enum YARAError: LocalizedError {

    /// The YARA library could not be initialised (`yr_initialize` returned non-zero).
    case initializationFailed(code: Int32)

    /// A compiler could not be created (`yr_compiler_create` returned non-zero).
    case compilerCreationFailed(code: Int32)

    /// A `.yar` source file could not be compiled. Includes the YARA error message.
    case ruleCompilationFailed(path: String, message: String)

    /// No rules were found in the rules directory, so the engine has nothing to scan against.
    case noRulesCompiled

    /// The file at `path` could not be read (does not exist or permission denied).
    case fileNotReadable(path: String)

    /// The scan exceeded the per-file timeout and was aborted.
    case scanTimeout(path: String)

    /// The YARA scan returned an unexpected error code.
    case scanFailed(path: String, code: Int32)

    // MARK: - LocalizedError

    var errorDescription: String? {
        switch self {
        case .initializationFailed(let code):
            return "YARA library initialization failed (code \(code))."
        case .compilerCreationFailed(let code):
            return "YARA compiler creation failed (code \(code))."
        case .ruleCompilationFailed(let path, let message):
            return "YARA rule compilation error in \(path): \(message)."
        case .noRulesCompiled:
            return "No YARA rules were compiled — rules directory is empty or contains no valid .yar files."
        case .fileNotReadable(let path):
            return "Cannot read file for YARA scan: \(path)."
        case .scanTimeout(let path):
            return "YARA scan timed out after 10 seconds on \(path)."
        case .scanFailed(let path, let code):
            return "YARA scan failed on \(path) (code \(code))."
        }
    }
}
