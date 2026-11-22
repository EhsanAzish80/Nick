# Deferred AUTH audit — installed private 5115

Scope: source at `48c5989fc39e47e3cafa635288eb0200373f673a`, matching the
preserved private 5115 archive. Audit and characterization tests only; no
production implementation or trust/fallback changes. No merge or publication.

## Inventory and response contract

`EventHandler.swift` has two retained-message construction sites: credential
AUTH_OPEN (`deferCredentialAuthorization`) and first-launch AUTH_EXEC
(`respondAfterPreLaunchHash`). Both share `RetainedMessage`, which retains once,
releases in deinit, and uses `AuthResponseClaim` to admit one claimant. Worker
and timer closures retain the wrapper. A losing timer can retain an already
answered message until its dispatch time; a blocked losing worker can keep it
longer. This is distinct from an unanswered request and is not a measured leak.

| Path | Before claim | After claim | Existing timeout fallback |
|---|---|---|---|
| Credential OPEN | Developer ID distribution validation; owning-app preparation | Cached-result check, then recursively `handle` OPEN, including policy/cache/registry locks before reply | Allow, if watchdog gets to run and wins |
| First-launch EXEC | File open/stream SHA-256, signature DB lookup/cache store | Blocking-policy read, ES response; cache lookup and observation completion follow reply | Allow, if watchdog gets to run and wins |
| EXEC with budget <=50 ms | No hash dispatched | Claim, allow, observation completion | Immediate allow attempt |

These are existing allow/deny policies, not endorsements or proposed changes.
Credential validation has no matching <=50 ms synchronous branch: it always
schedules worker and timer, including zero remaining budget. No branch scan
established a missing reply in ordinary live-owner success paths. This is not
an exhaustive synthetic ES-message integration proof.

## Concrete ownership limitation

The claim guarantees at most one winner, not exactly one accepted ES response.
A credential worker claims **before** recursive handling; a prelaunch worker
claims before policy lookup and reply. Once claimed, even a blocked worker or
rejected response API return prevents the watchdog from winning. Pending
metrics retain the unaccepted request but do not reopen ownership or recover
it. `EndpointSecurityClient.respond` returns false for a missing client and
records rejected ES returns; it does not retry. Blind retry would itself need
ES-result semantics review, not an automatic fix.

Closures capture `self` weakly. Credential worker evaluates the claim before
`let self`; timers can claim and then find no self/client. Prelaunch has the
same optional response dependency. This matters to teardown/lifecycle reasoning;
it is not evidence that self disappears during normal production use. Client
shutdown unsubscribes/deletes the client, but the deferred paths have no explicit
work-drain/cancellation contract. Do not turn a teardown-only observation into
a claim of a spontaneous live-client failure.

## Watchdog scheduling and admission

Both `asyncAfter` watchdogs run on the same `.concurrent`, user-interactive
`preLaunchQueue` as synchronous hashing/Security work. The budget is half the
remaining kernel deadline, capped at two seconds; expired deadlines return
zero. A dispatch deadline means eligibility, not guaranteed execution.
There is no dedicated timer thread, concurrency admission cap, per-cdhash
single-flight, or cancellation of losing closures. Shared queue placement is
verified; GCD starvation on this Mac is **not reproduced**. An artificial
barrier/serial-queue test would not prove concurrent production starvation, so
none is presented as such.

The timer counts/records dispatch lateness before attempting the claim. A zero
late-response counter cannot count an attempt that never occurred. Pending
warnings and kernel termination evidence remain independent observations.

## Shared locks reachable from deferred processing

- DeveloperIDTrustValidator dictionaries: shared NSLock, short dictionary
  sections; inspected Security validation/owning-app filesystem calls are
  outside that lock. `prepareOwningApp` marks preparation before completing
  app validation; concurrent callers are not coordinated by single-flight.
  Potential early observation of incomplete preparation is a separate issue,
  not an established timeout cause. Revocation/expiration flags unchanged.
- ScanCache: AUTH lookup/allowance and scanner mutations share NSLock. Store
  compaction filters the insertion log while holding it. Invalidation and clear
  share it too. No file hashing under the cache lock was found in these paths.
- SignatureDatabase: SQLite lookup and bulk transaction share NSLock; worker
  hashing can wait on DB activity **before** claiming, while the timer could win
  if scheduled. This is not a lock-free decision path.
- StrictBlockingPolicy: configuration/rule-set reads and updates share NSLock;
  decoding/new-rule construction is outside the lock. Prelaunch reads this
  after claiming, so the ownership limitation applies even to a policy wait.
- PendingAuthDiagnostics / AuthResponseClaim / full-callback and response
  diagnostics: independent bounded locks; response-start and response-return
  bookkeeping do not hold the pending lock across the ES response API. No
  nested lock cycle was found in the inspected chain. This does not prove
  hard real-time bounds or absence of other lock interactions.
- Credential re-entry also reaches storage-operation registry and update-lease
  manager locks. Registry kernel-resolved paths use lexical normalization;
  non-kernel-resolved mode can do filesystem resolution while holding its lock.
  Update-lease off-callback audit persistence and onAudit callback run under its
  lock; callback-origin persistence is dispatched asynchronously. Thus moving
  work off the reader does not mean it cannot contend with a lock the reader
  needs. No observed multi-second hold is attributed to these locks.
- BehaviorTracker and ProcessTree share locks across reader lifecycle/create
  paths and observation work. These may delay delivery of a later AUTH; they
  are not the retained-message ownership mechanism itself. Existing full
  callback measurements do not identify a single long predecessor explaining
  the captured multi-second event-to-entry intervals.

## Focused Xcode characterization tests

`DeferredAuthOwnershipAuditTests` exercises the **actual production**
AuthResponseClaim and PendingAuthDiagnostics types with synthetic keys:

1. Watchdog wins before worker claim: accepted return clears pending, worker loses.
2. Worker claims but is held before submitting: watchdog cannot take over;
   pending warning reports workerClaimed and zero response attempts.
3. Rejected response: request stays pending/responseFailed, but one-shot claim
   remains unavailable to watchdog.

The bounded semaphore in test 2 models a post-claim stall; it is not a real ES
message, real Security stall or GCD exhaustion test. No installed extension is
attached, suspended, fed malformed messages or run with fault injection. Tests
characterize current limits rather than pretending a missing recovery exists.
Existing race test already covers one winner under 1,000 contenders. No duplicate
implementation of an AUTH handler or source-string assertion is used.

Xcode execution result is recorded separately after running the suite. A green
suite validates these contracts, not proof that #122 is fixed. A subsequent
production design would need an explicit lifecycle/accepted-reply state machine,
independent watchdog execution and per-event fallback semantics reviewed before
implementation; no such change is authorized or made by this audit.

## Execution result

Xcode UI Product/Test on Mac Studio: **1,078 passed, zero failures, zero skipped**,
including all three new characterization tests. Result bundle:
`Test-Nick-2026.11.22_17-18-13-+0300.xcresult`. Existing runtime main-thread
warnings remain in the result; they were not diagnosed or changed by this audit.
Ten audited production files were hash-checked against commit `48c5989`; all
were unchanged. The installed build remains 5115; no new installer was built.
