// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation

// MARK: - PlistParserError

/// Errors thrown by `PlistParser`.
enum PlistParserError: LocalizedError {

    /// The file at the given path could not be read.
    case unreadable(path: String, underlying: Error)

    /// The data was not a valid property list.
    case invalidFormat(path: String)

    /// The property list was valid but did not contain a root dictionary.
    case notADictionary(path: String)

    var errorDescription: String? {
        switch self {
        case .unreadable(let path, let err):
            return "Cannot read plist at \(path): \(err.localizedDescription)"
        case .invalidFormat(let path):
            return "Invalid property list format at \(path)"
        case .notADictionary(let path):
            return "Root of plist is not a dictionary at \(path)"
        }
    }
}

// MARK: - PlistParser

/// Parses LaunchAgent and LaunchDaemon property list files.
///
/// Extracts the subset of keys needed by `PersistenceWatcher` to describe
/// a persistence item. All parsing is defensive — missing or wrong-typed keys
/// return `nil` rather than throwing.
///
/// - Note: Supports both XML and binary plist formats via `PropertyListSerialization`.
struct PlistParser {

    // MARK: - Public API

    /// Parsed representation of a LaunchAgent/Daemon plist.
    struct LaunchPlist {

        /// The `Label` key — unique identifier for the job.
        let label: String

        /// The executable path, from `Program` or the first element of `ProgramArguments`.
        let programPath: String?

        /// All arguments passed to the executable, including `argv[0]`.
        let programArguments: [String]

        /// Whether this job starts when the plist is loaded (`RunAtLoad = true`).
        let runAtLoad: Bool

        /// Whether launchd restarts the job when it exits (`KeepAlive = true`).
        let keepAlive: Bool

        /// Seconds between automatic job invocations, or `nil` if not scheduled.
        let startInterval: Int?

        /// Mach service names this job registers, if any.
        let machServices: [String]
    }

    /// Parses the plist at the given path and returns a structured `LaunchPlist`.
    ///
    /// - Parameter path: Absolute path to the `.plist` file.
    /// - Returns: A `LaunchPlist` populated with all available keys.
    /// - Throws: `PlistParserError` if the file cannot be read or parsed.
    func parse(at path: String) throws -> LaunchPlist {
        let url = URL(fileURLWithPath: path)

        let data: Data
        do {
            data = try Data(contentsOf: url)
        } catch {
            throw PlistParserError.unreadable(path: path, underlying: error)
        }

        let rawObject: Any
        do {
            rawObject = try PropertyListSerialization.propertyList(from: data, format: nil)
        } catch {
            throw PlistParserError.invalidFormat(path: path)
        }

        guard let dict = rawObject as? [String: Any] else {
            throw PlistParserError.notADictionary(path: path)
        }

        return extractLaunchPlist(from: dict)
    }

    // MARK: - Private Helpers

    private func extractLaunchPlist(from dict: [String: Any]) -> LaunchPlist {
        let label = dict["Label"] as? String ?? ""

        // `Program` takes precedence; fall back to first element of `ProgramArguments`
        let programArgs = dict["ProgramArguments"] as? [String] ?? []
        let programPath = (dict["Program"] as? String) ?? programArgs.first

        let runAtLoad = dict["RunAtLoad"] as? Bool ?? false

        // KeepAlive can be a Bool or a dictionary (conditional restart config)
        let keepAlive: Bool
        if let boolVal = dict["KeepAlive"] as? Bool {
            keepAlive = boolVal
        } else if dict["KeepAlive"] as? [String: Any] != nil {
            keepAlive = true // any conditional keepalive counts as active
        } else {
            keepAlive = false
        }

        let startInterval = dict["StartInterval"] as? Int

        // MachServices is a dictionary of service-name → Bool
        let machServicesDict = dict["MachServices"] as? [String: Any] ?? [:]
        let machServices = Array(machServicesDict.keys)

        return LaunchPlist(
            label: label,
            programPath: programPath,
            programArguments: programArgs,
            runAtLoad: runAtLoad,
            keepAlive: keepAlive,
            startInterval: startInterval,
            machServices: machServices
        )
    }
}
