import AppKit
import XCTest
@testable import Nick

@MainActor
final class AppDelegateTerminationPolicyTests: XCTestCase {
    func test_hiddenMenuBarAppNormallyStaysRunning() {
        XCTAssertEqual(
            AppDelegate.terminationReply(
                isRunningTests: false,
                forceQuit: false,
                sparkleInstallationInProgress: false,
                windowVisible: false
            ),
            .terminateCancel
        )
    }

    func test_hiddenMenuBarAppTerminatesForSparkleInstallation() {
        XCTAssertEqual(
            AppDelegate.terminationReply(
                isRunningTests: false,
                forceQuit: false,
                sparkleInstallationInProgress: true,
                windowVisible: false
            ),
            .terminateNow
        )
    }
}
