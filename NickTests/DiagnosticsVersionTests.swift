import XCTest
@testable import Nick

final class DiagnosticsVersionTests: XCTestCase {
    func test_matchingBuildsAreHealthy() {
        XCTAssertEqual(ExtensionBuildVersionStatus(appBuild: "5015", extensionBuild: "5015"), .matching)
    }

    func test_differentBuildsRaiseMismatch() {
        XCTAssertEqual(ExtensionBuildVersionStatus(appBuild: "5015", extensionBuild: "5014"), .mismatch)
    }

    func test_missingExtensionBuildIsUnavailable() {
        XCTAssertEqual(ExtensionBuildVersionStatus(appBuild: "5015", extensionBuild: "Unavailable"), .unavailable)
    }
}
