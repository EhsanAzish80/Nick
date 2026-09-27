// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import XCTest
@testable import Nick

final class OverviewCopyTests: XCTestCase {
    func test_issuesHeadlineAgreesWithCount() {
        XCTAssertEqual(OverviewDetailView.issuesHeadline(1), "1 issue needs attention")
        XCTAssertEqual(OverviewDetailView.issuesHeadline(2), "2 issues need attention")
        XCTAssertEqual(OverviewDetailView.issuesHeadline(12), "12 issues need attention")
    }
}
