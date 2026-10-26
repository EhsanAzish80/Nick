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
        func decoded(_ value: String) -> String {
            String(data: Data(base64Encoded: value)!, encoding: .utf8)!
        }
        XCTAssertTrue(
            RansomwareNotePolicy.matches(filename: decoded("UkVBRE1FX0RFQ1JZUFRfRklMRVMudHh0"))
        )
        XCTAssertTrue(
            RansomwareNotePolicy.matches(filename: decoded("SE9XX1RPX0RFQ1JZUFQuaHRtbA=="))
        )
    }

    func test_containerIdentifierMatchesOwningWhatsAppBundle() {
        XCTAssertTrue(
            DeepScanner.containerIdentifier(
                "group.net.whatsapp.WhatsApp.shared",
                matchesBundleIdentifier: "net.whatsapp.WhatsApp"
            )
        )
    }

    func test_containerIdentifierRejectsUnrelatedSignedApp() {
        XCTAssertFalse(
            DeepScanner.containerIdentifier(
                "group.attacker.unrelated.shared",
                matchesBundleIdentifier: "net.whatsapp.WhatsApp"
            )
        )
    }
}
