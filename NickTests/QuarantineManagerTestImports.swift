// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

@testable import Nick

// QuarantineManager and QuarantineDatabase are compiled directly into the
// unit-test bundle so their actual file-operation paths can be exercised. The
// shipping extension sources remain independent of the app module; these
// aliases supply the shared wire types only inside NickTests.
typealias QuarantineFailure = Nick.QuarantineFailure
typealias QuarantineFailureReason = Nick.QuarantineFailureReason
typealias QuarantineRecord = Nick.QuarantineRecord

struct FileIdentity: Hashable, Sendable {
    fileprivate let shared: Nick.FileIdentity
    var device: Int64 { shared.device }
    var inode: UInt64 { shared.inode }

    init(stat info: stat) {
        shared = Nick.FileIdentity(stat: info)
    }

    init?(path: String) {
        guard let shared = Nick.FileIdentity(path: path) else { return nil }
        self.shared = shared
    }
}

enum QuarantineMovePolicy {
    static func matchesReviewedFile(
        reviewedIdentity: FileIdentity,
        reviewedHash: String,
        currentIdentity: FileIdentity,
        currentHash: String
    ) -> Bool {
        Nick.QuarantineMovePolicy.matchesReviewedFile(
            reviewedIdentity: reviewedIdentity.shared,
            reviewedHash: reviewedHash,
            currentIdentity: currentIdentity.shared,
            currentHash: currentHash
        )
    }
}

enum QuarantineRestorePolicy {
    static func canonicalPathForLegacyRecord(_ path: String) -> String {
        Nick.QuarantineRestorePolicy.canonicalPathForLegacyRecord(path)
    }

    static func restoredPermissions(_ storedPermissions: UInt16?) -> UInt16 {
        Nick.QuarantineRestorePolicy.restoredPermissions(storedPermissions)
    }
}
