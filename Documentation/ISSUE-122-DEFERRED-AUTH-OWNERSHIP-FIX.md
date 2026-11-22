# Deferred AUTH response ownership and independent watchdogs

Scope: follow-up to the 5115 audit, on `fix/deferred-auth-response-ownership`. This is a local source change, not an installed build or release. It does not establish the cause of issue #122's historical kernel terminations.

## Confirmed gap and change

The old retained-message claim occurred before credential policy evaluation or prelaunch response preparation. A stalled claimant could exclude its watchdog without submitting a response. A failed response also consumed the one-shot claim. Both watchdogs were scheduled on the worker queue performing validation and hashing.

The shared `DeferredAuthReply` coordinator now reserves ownership only at the response boundary. Policy computation does not reserve a reply. Its short state lock is released before the response body; concurrent API submissions are prohibited. A worker finishing after an accepted watchdog reply cannot submit again. Retained messages hold the responder strongly through the race.

Watchdogs use a dedicated monotonic timer thread, independent of GCD worker availability. Cancelled entries release their retained captures outside the scheduler lock, and stale heap slots are compacted. The watchdog submits the reply and enqueues post-response observation; cache lookup and completion run on the worker queue.

## Decisions and errors

Credential policy, curated hash decisions, Strict Mode, tamper rules, trust-policy flags, timeout budgets, and the existing timeout-allow fallback remain unchanged. OPEN still uses the flags response API; ES caching remains disabled.

A successful response ends ownership. Invalid arguments, missing messages, duplicate responses, wrong event interfaces, and unavailable clients are terminal. An internal communication failure permits one watchdog retry, preserving the exact original verdict, including deny. A second failure is terminal. Recovery attempts have a separate diagnostic counter rather than being counted as accidental duplicate submissions. This bounded recovery is a design choice, not a promise that the kernel will accept a retry.

An API call already in flight is not preempted or duplicated. The timer can still be delayed by OS scheduling, diagnostic locks, or the response API itself. This change makes no hard-deadline guarantee and does not cancel worker I/O already in progress.

## Validation

Focused tests exercise the production coordinator and scheduler with synthetic response bodies: stalled policy work, blocked workers, competing submissions, allow/deny outcomes, failed-deny preservation, bounded communication recovery, terminal errors, deadline order, cancellation, and captured-state release. They do not suspend or send synthetic messages to the installed extension. Full Xcode test results are recorded after the run completes.

On November 22, 2026, Cmd-U in Xcode on the Mac Studio passed all **1,084 tests**, with zero failures, expected failures or skips. The three focused test classes passed; the ES extension binary was rebuilt by the scheme. Xcode reported 13 main-thread runtime warnings elsewhere in the full suite; this is not a warning-free result. Result bundle: `Test-Nick-2026.11.22_17-32-48-+0300.xcresult`. Installed runtime remains 5115; no installed-load validation of this source change has occurred.
