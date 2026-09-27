// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import XCTest
@testable import Nick

final class QuickCheckProgressTests: XCTestCase {
    private let start = Date(timeIntervalSince1970: 1_790_000_000)

    private func event(_ title: String, secondsAfterStart: Double) -> ActivityEvent {
        ActivityEvent(timestamp: start.addingTimeInterval(secondsAfterStart),
                      icon: "checkmark", iconColor: "green", title: title, subtitle: "")
    }

    func test_startsLowAndGrowsPerStep() {
        XCTAssertEqual(QuickCheckProgress.fraction(events: [], since: start), 0.08, accuracy: 0.001)
        let events = [
            event("System audit complete", secondsAfterStart: 1),
            event("Persistence check passed", secondsAfterStart: 2),
        ]
        XCTAssertEqual(QuickCheckProgress.fraction(events: events, since: start), 0.58, accuracy: 0.001)
    }

    func test_ignoresStepsFromEarlierChecksAndOtherEvents() {
        let events = [
            event("System audit complete", secondsAfterStart: -60),
            event("LOLBin execution detected", secondsAfterStart: 5),
        ]
        XCTAssertEqual(QuickCheckProgress.fraction(events: events, since: start), 0.08, accuracy: 0.001)
    }

    func test_neverReachesOneWhileRunning() {
        let events = QuickCheckProgress.stepTitles.map { event($0, secondsAfterStart: 1) }
        XCTAssertLessThan(QuickCheckProgress.fraction(events: events, since: start), 1)
    }
}

final class HomeMotionTests: XCTestCase {
    func test_breathPhaseEasesBetweenRestAndFull() {
        let period = HomeMotion.breathPeriod
        let rest = Date(timeIntervalSinceReferenceDate: period * 1_000)
        XCTAssertEqual(HomeMotion.breathPhase(at: rest), 0, accuracy: 0.0001)
        XCTAssertEqual(HomeMotion.breathPhase(at: rest.addingTimeInterval(period / 2)), 1, accuracy: 0.0001)
        XCTAssertEqual(HomeMotion.breathPhase(at: rest.addingTimeInterval(period / 4)), 0.5, accuracy: 0.0001)
    }

    func test_reduceMotionDropsAnimations() {
        XCTAssertNil(HomeMotion.animation(HomeMotion.stateChange, reduceMotion: true))
        XCTAssertNotNil(HomeMotion.animation(HomeMotion.stateChange, reduceMotion: false))
    }

    func test_metaSaysCheckedJustNowRightAfterACheck() {
        let now = Date(timeIntervalSince1970: 1_790_000_000)
        XCTAssertEqual(HomeHero.lastCheckText(now.addingTimeInterval(-5), now: now), "Checked just now")
        XCTAssertTrue(HomeHero.lastCheckText(now.addingTimeInterval(-7_200), now: now).hasPrefix("Last check"))
    }
}
