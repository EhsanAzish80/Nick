import XCTest
@testable import Nick

final class RansomwareNotePolicyTests: XCTestCase {
    func test_commonDeveloperFilesDoNotMatch() {
        let safeNames = [
            "README.md",
            "API_README.markdown",
            "DiskSpaceRecovery.h",
            "RansomwareDetector.swift",
            "macos_ransomware.yar",
        ]

        for filename in safeNames {
            XCTAssertFalse(
                RansomwareNotePolicy.matches(filename: filename),
                "\(filename) must not be treated as a ransom note"
            )
        }
    }

    func test_explicitDecryptionNoteMatches() {
        XCTAssertTrue(
            RansomwareNotePolicy.matches(filename: "README_DECRYPT_FILES.txt")
        )
        XCTAssertTrue(
            RansomwareNotePolicy.matches(filename: "HOW_TO_DECRYPT.html")
        )
    }
}
