// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation
import Darwin

/// Content-based file typing for scan scheduling.
///
/// File extensions and the executable bit are attacker-controlled and often
/// absent: browser downloads are not `+x`, and droppers write extensionless
/// Mach-O files. Deciding from the first bytes keeps scans focused on content
/// that can execute, while skipping caches, media, and databases.
enum ScanCandidatePolicy {

    enum CompletedWriteSignatureSkipReason: String, Equatable, Sendable {
        case empty
        case overSizeLimit
        case temporaryDownload
        case outsideSupportedIntakeLocation
    }

    enum CompletedWriteSignatureDecision: Equatable, Sendable {
        case check
        case skip(CompletedWriteSignatureSkipReason)
    }

    /// Maximum completed-write size considered for an exact signature lookup.
    /// This path is intentionally hash-only and limited to user intake folders,
    /// so ordinary high-churn text, database and cache writes remain excluded.
    static let completedWriteSignatureSizeLimit: Int64 = 100 * 1_024 * 1_024

    enum Kind: String, Sendable {
        case machO
        case script
        case compiledAppleScript
        case propertyList
        case installerArchive
        case archive
        case windowsExecutable
        case other
    }

    static let headerLength = 16

    static func kind(ofHeader header: Data) -> Kind {
        let bytes = [UInt8](header.prefix(headerLength))
        guard bytes.count >= 2 else { return .other }

        if bytes.count >= 4 {
            let magic = UInt32(bytes[0]) << 24 | UInt32(bytes[1]) << 16 | UInt32(bytes[2]) << 8 | UInt32(bytes[3])
            switch magic {
            case 0xFEED_FACE, 0xFEED_FACF, 0xCEFA_EDFE, 0xCFFA_EDFE:
                return .machO
            case 0xCAFE_BABE, 0xCAFE_BABF:
                // Universal binaries share this magic with Java class files.
                // A fat header's architecture count is small; Java's minor
                // version field is not.
                if bytes.count >= 8 {
                    let count = UInt32(bytes[4]) << 24 | UInt32(bytes[5]) << 16 | UInt32(bytes[6]) << 8 | UInt32(bytes[7])
                    return count > 0 && count < 32 ? .machO : .other
                }
                return .machO
            case 0x7861_7221: // "xar!" — flat installer package
                return .installerArchive
            case 0x504B_0304: // "PK\3\4" — zip, but also every Office document
                return .archive
            default:
                break
            }
        }

        if bytes[0] == 0x23, bytes[1] == 0x21 { return .script } // "#!"
        if bytes[0] == 0x4D, bytes[1] == 0x5A { return .windowsExecutable } // "MZ"
        if header.starts(with: Data("FasdUAS".utf8)) { return .compiledAppleScript }
        if header.starts(with: Data("bplist".utf8)) || header.starts(with: Data("<?xml".utf8)) {
            return .propertyList
        }
        return .other
    }

    /// Reads at most `headerLength` bytes. Returns `.other` for unreadable files.
    static func kind(atPath path: String) -> Kind {
        guard let handle = FileHandle(forReadingAtPath: path) else { return .other }
        defer { try? handle.close() }
        guard let header = try? handle.read(upToCount: headerLength) else { return .other }
        return kind(ofHeader: header)
    }

    /// Content that can run on its own or install code.
    static func isExecutableContent(_ kind: Kind) -> Bool {
        switch kind {
        case .machO, .script, .compiledAppleScript, .installerArchive, .windowsExecutable:
            return true
        case .propertyList, .archive, .other:
            return false
        }
    }

    /// Exact curated hashes must not depend on a filename extension. Browsers,
    /// Finder, Mail and command-line downloaders routinely write known samples
    /// as `.txt`, extensionless files or names chosen by the user.
    static func shouldCheckExactSignatureAfterCompletedWrite(
        path: String,
        fileSize: Int64
    ) -> Bool {
        completedWriteExactSignatureDecision(path: path, fileSize: fileSize) == .check
    }

    static func completedWriteExactSignatureDecision(
        path: String,
        fileSize: Int64
    ) -> CompletedWriteSignatureDecision {
        guard fileSize > 0 else { return .skip(.empty) }
        guard fileSize <= completedWriteSignatureSizeLimit else {
            return .skip(.overSizeLimit)
        }
        let normalized = URL(fileURLWithPath: path).standardizedFileURL.path
        let temporaryExtensions: Set<String> = [
            "crdownload", "download", "opdownload", "part", "partial"
        ]
        guard !temporaryExtensions.contains(
            URL(fileURLWithPath: normalized).pathExtension.lowercased()
        ) else { return .skip(.temporaryDownload) }
        let supportedLocation = normalized.contains("/Downloads/")
            || normalized.contains("/Desktop/")
            || normalized.contains("/Mail Downloads/")
        return supportedLocation ? .check : .skip(.outsideSupportedIntakeLocation)
    }

    static func completedWriteSignatureIdentityKey(
        device: Int64,
        inode: UInt64,
        size: Int64,
        modificationSeconds: Int,
        modificationNanoseconds: Int
    ) -> String {
        "completed-write:\(device):\(inode):\(size):\(modificationSeconds):\(modificationNanoseconds)"
    }
}

/// A bounded prefix read must never wait for a pipe writer or follow a symlink.
/// Validate the opened descriptor, avoiding a path-check/open race.
enum RegularFilePrefixReader {
    static func read(path: String, maximumBytes: Int) -> Data? {
        guard maximumBytes > 0, maximumBytes <= 65_536 else { return nil }
        let descriptor = Darwin.open(path, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else { return nil }
        defer { Darwin.close(descriptor) }
        var info = stat()
        guard fstat(descriptor, &info) == 0,
              (info.st_mode & mode_t(S_IFMT)) == mode_t(S_IFREG) else { return nil }
        var bytes = [UInt8](repeating: 0, count: maximumBytes)
        let count = bytes.withUnsafeMutableBytes { Darwin.read(descriptor, $0.baseAddress, maximumBytes) }
        guard count >= 0 else { return nil }
        return Data(bytes.prefix(count))
    }
}
