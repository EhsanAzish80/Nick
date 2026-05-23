// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation
import Security
import UniformTypeIdentifiers

// MARK: - FileScanSummary

/// File metadata gathered alongside a manual YARA scan.
///
/// Computed asynchronously on a background thread so it doesn't delay the
/// presentation of the scan sheet or block the main actor.
struct FileScanSummary: Sendable {

    // MARK: Stored Properties

    let fileSize:      Int64
    let fileType:      String
    let entropy:       Double
    let isSigned:      Bool
    let signatureInfo: String

    // MARK: Computed Properties

    /// Human-readable size, e.g. "4.2 MB".
    var formattedSize: String {
        ByteCountFormatter.string(fromByteCount: fileSize, countStyle: .file)
    }

    /// Entropy interpretation label.
    var entropyLabel: String {
        switch entropy {
        case ..<6.0:    return "normal"
        case 6.0..<7.5: return "moderate"
        default:        return "high — possible packing/encryption"
        }
    }

    // MARK: Factory

    /// Gathers file metadata on a background thread.
    static func analyze(url: URL) async -> FileScanSummary {
        await Task.detached(priority: .utility) { _analyze(url: url) }.value
    }

    // MARK: - Private Helpers

    private static func _analyze(url: URL) -> FileScanSummary {
        let attrs     = try? FileManager.default.attributesOfItem(atPath: url.path)
        let size      = (attrs?[.size] as? Int64) ?? 0
        let typeName  = detectFileType(url: url)
        let entropy   = computeEntropy(url: url)
        let (signed, sigInfo) = checkSigning(url: url)
        return FileScanSummary(
            fileSize:      size,
            fileType:      typeName,
            entropy:       entropy,
            isSigned:      signed,
            signatureInfo: sigInfo
        )
    }

    /// Resolves the UTType description for the file.
    private static func detectFileType(url: URL) -> String {
        if let typeID = try? url.resourceValues(forKeys: [.typeIdentifierKey]).typeIdentifier,
           let utType = UTType(typeID) {
            return utType.localizedDescription ?? utType.preferredFilenameExtension?.uppercased() ?? utType.identifier
        }
        let ext = url.pathExtension
        return ext.isEmpty ? "Unknown" : "\(ext.uppercased()) file"
    }

    /// Shannon entropy computed on the first 1 MiB of the file.
    private static func computeEntropy(url: URL) -> Double {
        guard let data = try? Data(contentsOf: url, options: .mappedIfSafe),
              !data.isEmpty else { return 0 }
        let sampleSize = min(data.count, 1_048_576)
        var freq = [Int](repeating: 0, count: 256)
        data.prefix(sampleSize).forEach { freq[Int($0)] += 1 }
        let total = Double(sampleSize)
        return freq.filter { $0 > 0 }.reduce(0.0) { acc, count in
            let p = Double(count) / total
            return acc - p * log2(p)
        }
    }

    /// Checks whether the file has a valid code signature and returns signer info.
    private static func checkSigning(url: URL) -> (Bool, String) {
        var staticCode: SecStaticCode?
        guard SecStaticCodeCreateWithPath(url as CFURL, [], &staticCode) == errSecSuccess,
              let code = staticCode else {
            return (false, "No")
        }
        guard SecStaticCodeCheckValidity(code, [], nil) == errSecSuccess else {
            return (false, "No")
        }
        var cfInfo: CFDictionary?
        let infoFlags = SecCSFlags(rawValue: UInt32(kSecCSSigningInformation))
        guard SecCodeCopySigningInformation(code, infoFlags, &cfInfo) == errSecSuccess,
              let info = cfInfo as? [String: Any] else {
            return (true, "Yes (Ad-Hoc)")
        }
        if let certs = info[kSecCodeInfoCertificates as String] as? [SecCertificate],
           let first = certs.first {
            var cn: CFString?
            SecCertificateCopyCommonName(first, &cn)
            if let name = cn as String?, !name.isEmpty {
                return (true, "Yes — \(name)")
            }
        }
        return (true, "Yes (Ad-Hoc)")
    }
}

// MARK: - Utilities

extension FileScanSummary {
    /// Counts compiled YARA rules in the given flat directory.
    ///
    /// Parses each `.yar` file and counts `rule ` keyword occurrences.
    /// Returns 0 if the directory is unreadable.
    static func countRules(inDirectory dir: String) -> Int {
        guard let contents = try? FileManager.default.contentsOfDirectory(atPath: dir) else { return 0 }
        return contents
            .filter { $0.hasSuffix(".yar") }
            .reduce(0) { total, file in
                let path = (dir as NSString).appendingPathComponent(file)
                guard let text = try? String(contentsOfFile: path, encoding: .utf8) else { return total }
                // Count occurrences of `\nrule ` (plus leading `rule ` at file start)
                let newlineCount = text.components(separatedBy: "\nrule ").count - 1
                let startCount   = text.hasPrefix("rule ") ? 1 : 0
                return total + newlineCount + startCount
            }
    }
}
