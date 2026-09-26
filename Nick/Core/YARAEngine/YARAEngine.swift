// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation
import os

// MARK: - YARAEngine

/// Compiles YARA rules from a rules directory and scans files for pattern matches.
///
/// `YARAEngine` wraps the vendored libyara C library (v4.5.5) and bridges it to
/// Swift's async/await concurrency model. Rule compilation is lazy — rules are
/// compiled on the first scan rather than at init time, keeping app startup
/// fast per the Phase 4 performance budget.
///
/// **Concurrency.** A compiled `YR_RULES` object may be scanned from several
/// threads at once (up to `YR_MAX_THREADS`); only compilation needs mutual
/// exclusion. The lock therefore guards compilation and the current rule-set
/// reference, never a scan. Each scan holds a strong reference to an immutable
/// `CompiledRules` box, so `reloadRules()` can swap rule sets while scans are
/// in flight without freeing rules under them. A semaphore keeps concurrent
/// scans below libyara's per-rule-set thread limit.
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

    /// Concurrent scans allowed against one rule set. libyara rejects more
    /// than `YR_MAX_THREADS` (32) simultaneous scanners per `YR_RULES`.
    static let maximumConcurrentScans = 16

    /// Nick never reads per-string match offsets, so libyara may stop
    /// searching for a string after its first occurrence.
    private static let scanFlags = Int32(SCAN_FLAGS_FAST_MODE)

    // MARK: - Private State

    /// Owns a compiled rule set; destroyed only when the last scan using it
    /// has released its reference.
    private final class CompiledRules: @unchecked Sendable {
        let pointer: UnsafeMutablePointer<YR_RULES>
        let fileCount: Int

        init(pointer: UnsafeMutablePointer<YR_RULES>, fileCount: Int) {
            self.pointer = pointer
            self.fileCount = fileCount
        }

        deinit { yr_rules_destroy(pointer) }
    }

    private var current: CompiledRules?
    private let lock = NSLock()
    private let scanSlots = DispatchSemaphore(value: YARAEngine.maximumConcurrentScans)
    private let rulesDirectory: String

    private static let log = Logger(
        subsystem: "com.ehsanazish.nick",
        category: "YARAEngine"
    )

    // MARK: - Init

    /// Creates a `YARAEngine` pointing at the given rules directory.
    ///
    /// Rule compilation is deferred until the first scan.
    /// Throws if the libyara global state cannot be initialised.
    ///
    /// - Parameter rulesDirectory: Absolute path to a directory containing
    ///             `.yar`/`.yara` rule files. Subdirectories are traversed.
    /// - Throws: `YARAError.initializationFailed` if `yr_initialize` fails.
    init(rulesDirectory: String) throws {
        self.rulesDirectory = rulesDirectory
        let code = yr_initialize()
        guard code == ERROR_SUCCESS else {
            throw YARAError.initializationFailed(code: code)
        }
    }

    deinit {
        current = nil
        _ = yr_finalize()
    }

    // MARK: - Public API

    /// Synchronous scan — for use on background queues where async/await is unavailable.
    ///
    /// Must NOT be called from the ES callback queue — only from a background
    /// dispatch queue (e.g. `ESEventHandler.dispatchQueue`).
    func scanFileBlocking(at path: String) throws -> [YARAMatch] {
        try scanFileSync(at: path)
    }

    /// Scans bytes already in memory (for example a mapped file that was just
    /// hashed), avoiding a second read of the same file.
    ///
    /// - Parameter path: Reported as the match's file path.
    func scanDataBlocking(_ data: Data, reportingPath path: String) throws -> [YARAMatch] {
        let rules = try compiledRules()
        guard !data.isEmpty else { return [] }

        let holder = ScanResultsHolder(filePath: path)
        let rawPtr = Unmanaged.passRetained(holder).toOpaque()
        defer { Unmanaged<ScanResultsHolder>.fromOpaque(rawPtr).release() }

        scanSlots.wait()
        defer { scanSlots.signal() }
        let scanCode = data.withUnsafeBytes { buffer -> Int32 in
            guard let base = buffer.bindMemory(to: UInt8.self).baseAddress else { return ERROR_SUCCESS }
            return yr_rules_scan_mem(
                rules.pointer,
                base,
                buffer.count,
                Self.scanFlags,
                yaraMatchCallback,
                rawPtr,
                Self.perFileScanTimeoutSeconds
            )
        }
        return try Self.result(for: scanCode, path: path, holder: holder)
    }

    /// Scans the file at `path` against all compiled YARA rules.
    ///
    /// - Parameter path: Absolute path to the file. Must be readable by the
    ///             current process.
    /// - Returns: An array of `YARAMatch` values — one per triggered rule.
    /// - Throws: `YARAError.fileNotReadable` if the path is unreadable,
    ///           `YARAError.scanTimeout` if the 10-second budget is exceeded,
    ///           `YARAError.scanFailed` for any other libyara error.
    func scanFile(at path: String) async throws -> [YARAMatch] {
        // Offload blocking C work so the cooperative pool is not held by I/O.
        return try await Task.detached(priority: .utility) { [weak self] in
            guard let self else { return [] }
            return try self.scanFileSync(at: path)
        }.value
    }

    /// Scans every regular file in `path`, optionally recursing into subdirectories.
    ///
    /// Files that individually time out or are unreadable are skipped; the
    /// overall scan continues.
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

    /// Recompiles the rule set from the rules directory and swaps it in.
    /// In-flight scans finish with the rule set they started with.
    ///
    /// - Throws: `YARAError` if recompilation fails; the previous rule set
    ///   stays active in that case.
    func reloadRules() throws {
        lock.lock()
        defer { lock.unlock() }
        current = try compileRulesLocked()
    }

    // MARK: - Internal Helpers

    private func compiledRules() throws -> CompiledRules {
        lock.lock()
        defer { lock.unlock() }
        if let current { return current }
        let compiled = try compileRulesLocked()
        current = compiled
        return compiled
    }

    /// Compiles all rule files under `rulesDirectory`. Must be called with `lock` held.
    ///
    /// Each file is first validated in a throwaway compiler. libyara leaves a
    /// compiler unusable after any error, so adding an invalid file directly
    /// would silently drop every file that sorts after it.
    private func compileRulesLocked() throws -> CompiledRules {
        let fm = FileManager.default
        guard let enumerator = fm.enumerator(
            at: URL(fileURLWithPath: rulesDirectory),
            includingPropertiesForKeys: nil,
            options: [.skipsHiddenFiles]
        ) else {
            throw YARAError.noRulesCompiled
        }

        var yarFiles: [String] = []
        for case let url as URL in enumerator
            where url.pathExtension == "yar" || url.pathExtension == "yara" {
            yarFiles.append(url.path)
        }
        yarFiles.sort()

        Self.log.info("YARA: found \(yarFiles.count) rule file(s) in \(self.rulesDirectory, privacy: .private)")
        guard !yarFiles.isEmpty else {
            throw YARAError.noRulesCompiled
        }

        let compiler = try Self.makeCompiler()
        defer { yr_compiler_destroy(compiler) }

        var compiled = 0
        for fullPath in yarFiles {
            // A per-file namespace keeps identically named rules from
            // different sources from colliding.
            let namespace = String(fullPath.dropFirst(rulesDirectory.count))
                .trimmingCharacters(in: CharacterSet(charactersIn: "/"))
            guard Self.validate(ruleFile: fullPath, namespace: namespace) else {
                Self.log.error("YARA rule file skipped (does not compile): \(fullPath, privacy: .public)")
                continue
            }
            guard let fp = fopen(fullPath, "r") else {
                Self.log.warning("Cannot open YARA rule file: \(fullPath, privacy: .private)")
                continue
            }
            let errCount = yr_compiler_add_file(compiler, fp, namespace, fullPath)
            fclose(fp)
            guard errCount == 0 else {
                // Validated files should never fail here; if one does, the
                // compiler is now unusable, so keep what compiled so far.
                Self.log.error("YARA rule file failed after validation: \(fullPath, privacy: .public)")
                break
            }
            compiled += 1
        }

        guard compiled > 0 else {
            throw YARAError.noRulesCompiled
        }

        var rulesPtr: UnsafeMutablePointer<YR_RULES>?
        let getCode = yr_compiler_get_rules(compiler, &rulesPtr)
        guard getCode == ERROR_SUCCESS, let rules = rulesPtr else {
            throw YARAError.compilerCreationFailed(code: getCode)
        }
        Self.log.info("YARA: compiled \(compiled) of \(yarFiles.count) rule file(s)")
        return CompiledRules(pointer: rules, fileCount: compiled)
    }

    private static func makeCompiler() throws -> UnsafeMutablePointer<YR_COMPILER> {
        var compilerPtr: UnsafeMutablePointer<YR_COMPILER>?
        let createCode = yr_compiler_create(&compilerPtr)
        guard createCode == ERROR_SUCCESS, let compiler = compilerPtr else {
            throw YARAError.compilerCreationFailed(code: createCode)
        }
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
        return compiler
    }

    /// Compiles one file in isolation. Returns `false` on any error.
    private static func validate(ruleFile path: String, namespace: String) -> Bool {
        guard let compiler = try? makeCompiler() else { return false }
        defer { yr_compiler_destroy(compiler) }
        guard let fp = fopen(path, "r") else { return false }
        defer { fclose(fp) }
        return yr_compiler_add_file(compiler, fp, namespace, path) == 0
    }

    // MARK: - Private Implementation

    /// Synchronous scan — runs on a detached task thread or a dispatch queue.
    private func scanFileSync(at path: String) throws -> [YARAMatch] {
        let rules = try compiledRules()

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

        scanSlots.wait()
        defer { scanSlots.signal() }
        let scanCode = path.withCString { cPath in
            yr_rules_scan_file(
                rules.pointer,
                cPath,
                Self.scanFlags,
                yaraMatchCallback,              // non-capturing C callback
                rawPtr,                         // user_data → holder
                Self.perFileScanTimeoutSeconds  // 10-second timeout
            )
        }
        return try Self.result(for: scanCode, path: path, holder: holder)
    }

    private static func result(for scanCode: Int32, path: String, holder: ScanResultsHolder) throws -> [YARAMatch] {
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
