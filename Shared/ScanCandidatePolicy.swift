// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation

/// Content-based file typing for scan scheduling.
///
/// File extensions and the executable bit are attacker-controlled and often
/// absent: browser downloads are not `+x`, and droppers write extensionless
/// Mach-O files. Deciding from the first bytes keeps scans focused on content
/// that can execute, while skipping caches, media, and databases.
enum ScanCandidatePolicy {

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
}
