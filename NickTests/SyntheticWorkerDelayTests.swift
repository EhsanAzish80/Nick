import XCTest
@testable import Nick

final class SyntheticWorkerDelayTests: XCTestCase {
    private let nonce = "D641EA58-DA69-40DF-A57C-E0C526711D89"
    private let expectedHash = String(repeating: "a", count: 40)
    private func config(nonce: String? = nil, build: String = "5117", scope: SyntheticWorkerDelay.Scope = .credential,
                        created: Double = 990, expires: Double = 1100, delay: Int = 3000, hash: String? = nil) -> SyntheticWorkerDelay.Config {
        .init(build: build, nonce: nonce ?? self.nonce, cdhash: hash ?? self.expectedHash, createdAt: created, expiresAt: expires, delayMilliseconds: delay, scope: scope)
    }
    private func candidate(nonce: String? = nil, build: String = "5117", scope: SyntheticWorkerDelay.Scope = .credential,
                           id: String? = SyntheticWorkerDelay.helperID, team: String? = "UXGW5V3BY6", valid: Bool = true,
                           target: String? = nil, helper: String? = nil, hash: String? = nil) -> SyntheticWorkerDelay.Candidate {
        let base = SyntheticWorkerDelay.root + "/Fixtures/" + (nonce ?? self.nonce)
        return .init(build: build, signingID: id, teamID: team, cdhash: hash ?? self.expectedHash, identityValid: valid,
                     helperPath: helper ?? base + "/WatchdogReader", targetPath: target ?? base + (scope == .credential ? SyntheticWorkerDelay.credentialSuffix : "/WatchdogReader"), scope: scope)
    }
    func testOffByDefaultAndBothSyntheticScopesAdmitOnlyOnce() {
        for scope in [SyntheticWorkerDelay.Scope.credential, .prelaunch] {
            let gate = SyntheticWorkerDelay(), c = candidate(scope: scope), cfg = config(scope: scope)
            if scope == .credential { XCTAssertEqual(CredentialAccessPolicy.sensitiveStore(at: c.targetPath), .keychain) }
            XCTAssertFalse(gate.claim(cfg, candidate: c, now: 1000, enabled: false))
            XCTAssertTrue(gate.claim(cfg, candidate: c, now: 1000, enabled: true))
            gate.finish()
            XCTAssertFalse(gate.claim(cfg, candidate: c, now: 1000, enabled: true))
            XCTAssertEqual(gate.snapshot()["completed"] as? UInt64, 1)
        }
    }
    func testRealPathsAndUnvalidatedOrWrongActorsNeverAdmit() {
        let bad = [candidate(id: nil), candidate(id: "com.other.app"), candidate(team: nil),
                   candidate(team: "OTHER"), candidate(valid: false), candidate(build: "5116"),
                   candidate(target: "/Users/example/Library/Keychains/login.keychain-db"),
                   candidate(helper: "/Applications/WatchdogReader"), candidate(hash: String(repeating: "b", count: 40)),
                   candidate(scope: .prelaunch)]
        for c in bad { XCTAssertFalse(SyntheticWorkerDelay().claim(config(), candidate: c, now: 1000, enabled: true)) }
    }
    func testExpiredFutureMalformedAndUnboundedConfigurationsNeverAdmit() {
        let bad = [config(expires: 1000), config(created: 1001), config(created: 0, expires: 1001),
                   config(created: .nan), config(expires: .infinity), config(delay: 3001), config(delay: 0),
                   config(nonce: "../real"), config(build: "5118"), config(hash: String(repeating: "x", count: 40))]
        for cfg in bad { XCTAssertFalse(SyntheticWorkerDelay().claim(cfg, candidate: candidate(), now: 1000, enabled: true)) }
        XCTAssertFalse(SyntheticWorkerDelay().claim(config(), candidate: candidate(), now: .nan, enabled: true))
    }
    func testOnlyOneActiveDelayAndLifetimeAdmissionIsBounded() {
        let gate = SyntheticWorkerDelay()
        for i in 0..<16 {
            let id = UUID().uuidString, cfg = config(nonce: id), c = candidate(nonce: id)
            XCTAssertTrue(gate.claim(cfg, candidate: c, now: 1000, enabled: true))
            let other = UUID().uuidString
            XCTAssertFalse(gate.claim(config(nonce: other), candidate: candidate(nonce: other), now: 1000, enabled: true))
            XCTAssertEqual(gate.snapshot()["inFlight"] as? Int, 1)
            gate.finish(); XCTAssertEqual(gate.snapshot()["injected"] as? Int, i + 1)
        }
        let id = UUID().uuidString
        XCTAssertFalse(gate.claim(config(nonce: id), candidate: candidate(nonce: id), now: 1000, enabled: true))
    }
    func testRacingSyntheticRequestsHaveOneWinner() {
        final class Counter: @unchecked Sendable {
            private let lock = NSLock()
            private var count = 0
            func increment() { lock.withLock { count += 1 } }
            var value: Int { lock.withLock { count } }
        }
        let gate = SyntheticWorkerDelay(), cfg = config(), c = candidate(), wins = Counter()
        DispatchQueue.concurrentPerform(iterations: 100) { _ in
            if gate.claim(cfg, candidate: c, now: 1000, enabled: true) { wins.increment() }
        }
        XCTAssertEqual(wins.value, 1); gate.finish()
    }
    func testCallbackThreadRecordsAreBoundedAndCountEvictionsAndFailures() throws {
        let d = FullCallbackTimingDiagnostics(nanosecondsPerTick: 1)
        for id in 1...32 {
            d.begin(event: 1, auth: true, message: UInt64(id), entry: UInt64(id), threadID: UInt64(id))
            d.finish(entry: UInt64(id), end: UInt64(id + 1))
        }
        d.begin(event: 1, auth: true, message: 40, entry: 40, threadID: 32); d.finish(entry: 40, end: 41)
        d.begin(event: 1, auth: true, message: 42, entry: 42, threadID: 0); d.finish(entry: 42, end: 43)
        let s = d.snapshot(), rows = try XCTUnwrap(s["callbackThreads"] as? [[String: UInt64]])
        XCTAssertEqual(rows.count, 16); XCTAssertEqual(rows.first?["threadID"], 17)
        XCTAssertEqual(rows.last?["callbacks"], 2); XCTAssertEqual(rows.last?["lastEntryMachTime"], 40)
        XCTAssertEqual(s["callbackThreadEvictions"] as? UInt64, 16)
        XCTAssertEqual(s["callbackThreadLookupFailures"] as? UInt64, 1)
        XCTAssertTrue(JSONSerialization.isValidJSONObject(s))
    }
}
