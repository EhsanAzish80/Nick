// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation
import os

// MARK: - YARAEngine

/// Compiles YARA rules from a rules directory and scans files for pattern matches.
///
/// `YARAEngine` wraps the vendored libyara C library (v4.5.2) and bridges it to
/// Swift's async/await concurrency model. Rule compilation is lazy — rules are
/// compiled on the first call to `scanFile(at:)` rather than at init time, keeping
/// app startup fast per the Phase 4 performance budget.
///
/// All libyara API calls are protected by a `NSLock` because `yr_rules_scan_file`
/// is documented as thread-safe after rule compilation, but `YR_COMPILER` is not.
///
/// - Note: Per-file scan timeout is fixed at 10 seconds to prevent a single large
///         or adversarially crafted binary from stalling the scan pipeline.
///
/// - Important: Requires `libyara-universal.a` to be linked and
///              `Nick/Core/YARAEngine/Vendor/include` in Header Search Paths.
final class YARAEngine: @unchecked Sendable {

    // MARK: - Configuration

    /// Maximum seconds libyara will spend scanning a single file before aborting.
    static let perFileScanTimeoutSeconds: Int32 = 10

    // MARK: - Private State

    private var compiledRules: UnsafeMutablePointer<YR_RULES>?
    private let lock = NSLock()
    private let rulesDirectory: String
    private var rulesCompiled = false

    private static let log = Logger(
        subsystem: "com.ehsanazish.nick",
        category: "YARAEngine"
    )

    // MARK: - Init

    /// Creates a `YARAEngine` pointing at the given rules directory.
    ///
    /// Rule compilation is deferred until the first `scanFile(at:)` call.
    /// Throws if the libyara global state cannot be initialised.
    ///
    /// - Parameter rulesDirectory: Absolute path to a directory containing
    ///             `.yar` YARA rule files. Subdirectories are not traversed.
    /// - Throws: `YARAError.initializationFailed` if `yr_initialize` fails.
    init(rulesDirectory: String) throws {
        self.rulesDirectory = rulesDirectory
        let code = yr_initialize()
        guard code == ERROR_SUCCESS else {
            throw YARAError.initializationFailed(code: code)
        }
    }

    deinit {
        if let rules = compiledRules {
            yr_rules_destroy(rules)
        }
        _ = yr_finalize()
    }

    // MARK: - Public API

    /// Scans the file at `path` against all compiled YARA rules.
    ///
    /// Compiles rules on the first call (lazy initialisation). Each subsequent
    /// call reuses the same compiled rule set until `reloadRules()` is called.
    ///
    /// - Parameter path: Absolute path to the file. Must be readable by the
    ///             current process.
    /// - Returns: An array of `YARAMatch` values — one per triggered rule.
    ///            Empty if no rules matched.
    /// - Throws: `YARAError.fileNotReadable` if the path is unreadable,
    ///           `YARAError.scanTimeout` if the 10-second budget is exceeded,
    ///           `YARAError.scanFailed` for any other libyara error.
    func scanFile(at path: String) async throws -> [YARAMatch] {
        // Offload blocking C work to a background thread pool, freeing the
        // Swift cooperative thread pool for other tasks.
        return try await Task.detached(priority: .utility) { [weak self] in
            guard let self else { return [] }
            return try self.scanFileSync(at: path)
        }.value
    }

    /// Scans every regular file in `path`, optionally recursing into subdirectories.
    ///
    /// Files that individually time out are skipped with a warning; the overall
    /// scan continues. Files that are unreadable (e.g. `sbin` restricted binaries)
    /// are also skipped.
    ///
    /// - Parameters:
    ///   - path: Absolute path to a directory.
    ///   - recursive: When `true`, traverses subdirectories.
    /// - Returns: All matches across all files in the directory.
    /// - Throws: `YARAError` if the directory cannot be enumerated.
    func scanDirectory(at path: String, recursive: Bool) async throws -> [YARAMatch] {
        // Collect file paths synchronously on a detached thread to avoid
        // sending a non-Sendable NSDirectoryEnumerator across async boundaries.
        let filePaths: [String] = await Task.detached(priority: .utility) {
            self.collectRegularFiles(under: path, recursive: recursive)
        }.value
        var allMatches: [YARAMatch] = []
        for filePath in filePaths {
            do {
                let matches = try await scanFile(at: filePath)
                allMatches.append(contentsOf: matches)
            } catch YARAError.scanTimeout(let p) {
                Self.log.warning("YARA scan timeout — skipping \(p, privacy: .private)")
            } catch YARAError.fileNotReadable(let p) {
                Self.log.debug("YARA cannot read file (skipped): \(p, privacy: .private)")
            }
        }
        return allMatches
    }

    /// Synchronously enumerates `directory` and returns paths of all regular files.
    private func collectRegularFiles(under directory: String, recursive: Bool) -> [String] {
        let fm = FileManager.default
        let base = URL(fileURLWithPath: directory, isDirectory: true)
        let options: FileManager.DirectoryEnumerationOptions = recursive
            ? []
            : [.skipsSubdirectoryDescendants]
        guard let enumerator = fm.enumerator(
            at: base,
            includingPropertiesForKeys: [.isRegularFileKey],
            options: options
        ) else { return [] }
        var paths: [String] = []
        for case let url as URL in enumerator {
            guard (try? url.resourceValues(forKeys: [.isRegularFileKey]).isRegularFile) == true
            else { continue }
            paths.append(url.path)
        }
        return paths
    }

    /// Destroys and recompiles the rule set from the rules directory.
    ///
    /// Call this when `.yar` files in `rulesDirectory` change at runtime
    /// (e.g., after the user updates community rules from `Rules/community/`).
    ///
    /// - Throws: `YARAError` if recompilation fails.
    func reloadRules() throws {
        lock.lock()
        defer { lock.unlock() }
        if let rules = compiledRules {
            yr_rules_destroy(rules)
            compiledRules = nil
        }
        rulesCompiled = false
        try compileRulesLocked()
    }


    // MARK: - Internal Helpers

    /// Compiles all `.yar` files in `rulesDirectory`. Must be called with `lock` held.
    ///
    /// - Throws: `YARAError.compilerCreationFailed` / `.ruleCompilationFailed` /
    ///           `.noRulesCompiled` on failure.
    private func compileRulesLocked() throws {
        var compilerPtr: UnsafeMutablePointer<YR_COMPILER>?
        let createCode = yr_compiler_create(&compilerPtr)
        guard createCode == ERROR_SUCCESS, let compiler = compilerPtr else {
            throw YARAError.compilerCreationFailed(code: createCode)
        }
        defer { yr_compiler_destroy(compiler) }

        // SECURITY: Set an error callback so compilation errors are logged
        // rather than silently discarded.
        yr_compiler_set_callback(
            compiler,
            { errorLevel, fileName, lineNumber, _, message, _ in
                let msg = message.map { String(cString: $0) } ?? "<nil>"
                let file = fileName.map { String(cString: $0) } ?? "<unknown>"
                let logger = Logger(subsystem: "com.ehsanazish.nick", category: "YARACompiler")
                if errorLevel == YARA_ERROR_LEVEL_ERROR {
                    logger.error("YARA compile error in \(file, privacy: .public):\(lineNumber): \(msg, privacy: .public)")
                } else {
                    logger.warning("YARA compile warning in \(file, privacy: .public):\(lineNumber): \(msg, privacy: .public)")
                }
            },
            nil
        )

        let fm = FileManager.default
        guard let contents = try? fm.contentsOfDirectory(atPath: rulesDirectory) else {
            throw YARAError.noRulesCompiled
        }
        let yarFiles = contents.filter { $0.hasSuffix(".yar") }.sorted()
        guard !yarFiles.isEmpty else {
            throw YARAError.noRulesCompiled
        }

        var compiled = 0
        for filename in yarFiles {
            let fullPath = (rulesDirectory as NSString).appendingPathComponent(filename)
            guard let fp = fopen(fullPath, "r") else {
                Self.log.warning("Cannot open YARA rule file: \(fullPath, privacy: .private)")
                continue
            }
            let errCount = yr_compiler_add_file(compiler, fp, nil, fullPath)
            fclose(fp)
            if errCount == 0 {
                compiled += 1
            } else {
                Self.log.error("YARA rule file had \(errCount) error(s): \(fullPath, privacy: .private)")
            }
        }

        guard compiled > 0 else {
            throw YARAError.noRulesCompiled
        }

        var rulesPtr: UnsafeMutablePointer<YR_RULES>?
        let getCode = yr_compiler_get_rules(compiler, &rulesPtr)
        guard getCode == ERROR_SUCCESS, let rules = rulesPtr else {
            throw YARAError.compilerCreationFailed(code: getCode)
        }
        compiledRules = rules
        rulesCompiled = true
        Self.log.info("YARA: compiled \(compiled) rule file(s) from \(self.rulesDirectory, privacy: .private)")
    }

    // MARK: - Private Implementation

    /// Synchronous scan — runs on a detached task thread.
    private func scanFileSync(at path: String) throws -> [YARAMatch] {
        lock.lock()
        defer { lock.unlock() }

        // Lazy rule compilation on first scan.
        if !rulesCompiled {
            try compileRulesLocked()
        }

        guard let rules = compiledRules else {
            throw YARAError.noRulesCompiled
        }

        // SECURITY: Validate that the file exists and is readable before
        // handing the path to libyara. This prevents misleading errors from
        // the C layer and catches permissions failures early.
        guard FileManager.default.isReadableFile(atPath: path) else {
            throw YARAError.fileNotReadable(path: path)
        }

        // Allocate the results holder on the heap so a stable pointer can be
        // passed through the C callback's user_data parameter.
        let holder = ScanResultsHolder(filePath: path)
        let rawPtr = Unmanaged.passRetained(holder).toOpaque()
        defer { Unmanaged<ScanResultsHolder>.fromOpaque(rawPtr).release() }

        let scanCode = path.withCString { cPath in
            yr_rules_scan_file(
                rules,
                cPath,
                0,                              // flags
                yaraMatchCallback,              // non-capturing C callback
                rawPtr,                         // user_data → holder
                Self.perFileScanTimeoutSeconds  // 10-second timeout
            )
        }

        if scanCode == ERROR_SUCCESS {
            return holder.matches
        } else if scanCode == ERROR_SCAN_TIMEOUT {
            throw YARAError.scanTimeout(path: path)
        } else {
            throw YARAError.scanFailed(path: path, code: scanCode)
        }
    }
}

// MARK: - ScanResultsHolder

/// Reference-type container passed as `user_data` through the libyara C callback.
///
/// Using a class (not a struct) guarantees a stable heap address that can be
/// safely cast to/from `UnsafeMutableRawPointer`.
private final class ScanResultsHolder {
    var matches: [YARAMatch] = []
    let filePath: String

    init(filePath: String) {
        self.filePath = filePath
    }
}

// MARK: - C Callback

/// Non-capturing `@convention(c)` callback passed to `yr_rules_scan_file`.
///
/// `@convention(c)` closures cannot capture Swift values; all state is
/// transmitted through `user_data`, which points to a `ScanResultsHolder`.
///
/// - Note: Called on whatever thread libyara uses internally; the holder is
///         not accessed concurrently so no additional locking is needed here.
private let yaraMatchCallback: YR_CALLBACK_FUNC = { _, message, messageData, userData in
    // Only act on rule-matching messages.
    guard Int(message) == CALLBACK_MSG_RULE_MATCHING else {
        return Int32(CALLBACK_CONTINUE)
    }
    guard let rawUser = userData, let rawRule = messageData else {
        return Int32(CALLBACK_CONTINUE)
    }

    let holder = Unmanaged<ScanResultsHolder>.fromOpaque(rawUser).takeUnretainedValue()
    let rulePtr = rawRule.assumingMemoryBound(to: YR_RULE.self)

    // Rule identifier (name)
    let ruleName: String
    if let identPtr = nick_rule_identifier(rulePtr) {
        ruleName = String(cString: identPtr)
    } else {
        ruleName = "<unknown>"
    }

    // Tags — stored as sequential null-terminated strings, terminated by \0\0.
    var tags: [String] = []
    if var tagPtr = nick_rule_first_tag(rulePtr) {
        while tagPtr.pointee != 0 {
            tags.append(String(cString: tagPtr))
            tagPtr = tagPtr.advanced(by: Int(strlen(tagPtr)) + 1)
        }
    }

    // Metadata — walk the linked list of YR_META entries.
    var metadata: [String: String] = [:]
    if var metaPtr = nick_rule_first_meta(rulePtr) {
        while true {
            if let keyPtr = nick_meta_identifier(metaPtr) {
                let key = String(cString: keyPtr)
                let metaType = nick_meta_type(metaPtr)
                if metaType == META_TYPE_STRING {
                    if let valPtr = nick_meta_string_value(metaPtr) {
                        metadata[key] = String(cString: valPtr)
                    }
                } else if metaType == META_TYPE_INTEGER || metaType == META_TYPE_BOOLEAN {
                    metadata[key] = "\(nick_meta_integer_value(metaPtr))"
                }
            }
            if nick_meta_is_last(metaPtr) != 0 { break }
            metaPtr = metaPtr.advanced(by: 1)
        }
    }

    let match = YARAMatch(
        ruleName: ruleName,
        tags: tags,
        filePath: holder.filePath,
        metadata: metadata
    )
    holder.matches.append(match)

    return Int32(CALLBACK_CONTINUE)
}
