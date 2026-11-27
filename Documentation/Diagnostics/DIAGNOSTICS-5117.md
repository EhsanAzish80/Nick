# Private diagnostic 5117

Purpose: safely test an installed watchdog win and correlate each ES client's callbacks with passive per-thread CPU accounting. This does not change protection rules, certificate validation, subscriptions, response cache flags, deadlines or timeout fallback decisions. No merge, public release, website or appcast update is part of this build.

## Worker-delay safeguards

The hook is compiled into private diagnostics; ordinary public Release builds exclude it. Debug builds compile its loader for build verification but the hook remains gated by `PrivateDiagnosticBuild.enabled`. No configuration is installed or enabled automatically.

Only build 5117 can admit the designated kernel-reported identity `com.3nsofts.diagnostics.Watchdog5117`, team UXGW5V3BY6, with identity-bearing valid code-signing flags. A root-owned control file pins its exact 20-byte cdhash. These are diagnostic admission checks, not changes to certificate trust or normal authorization policy.

The operator must explicitly create `/Library/Logs/NickPrivateDiagnostics/worker-delay.json`: a non-symlink regular root-owned file with mode 0600, one link and at most 4096 bytes. Its parent must be a root-owned directory without group/world write. The root-owned Fixtures directory and UUID subdirectory must also reject unprivileged writes, including the synthetic Library/Keychains ancestors. Helper and target must be regular root-owned single-link files, with no group/world write.

The JSON schema is `build`, canonical uppercase UUID `nonce`, lowercase 40-hex `cdhash`, finite `createdAt` and `expiresAt` epoch seconds, `delayMilliseconds` exactly 3000, and `scope` either `credential` or `prelaunch`. The validity window is at most ten minutes, with future, expired and malformed configurations rejected. The paths are derived rather than configurable: `Fixtures/<nonce>/WatchdogReader` and, for credential reads, `Fixtures/<nonce>/Library/Keychains/synthetic.keychain-db`, under the private diagnostic root. Real credential-store paths cannot pass admission.

A nonce is consumed once per extension process. There is at most one active delay and sixteen lifetime admissions; used nonces are never evicted or rearmed. The three-second sleep is on the deferred worker, outside admission and response locks, after its existing watchdog is armed. The worker checks whether the watchdog already finished before doing policy work after the delay. The watchdog and response coordinator retain their existing decisions and ownership behavior. Removing the control file disables new requests, but does not interrupt an already admitted three-second sleep.

The health snapshot exposes only bounded injection/completion/in-flight counters and fixed limits; no control-file contents, hashes, target paths or credential data. This build's packaging never creates the control file or fixtures.

## Callback-thread diagnostics

Private callbacks obtain the current kernel thread ID with `pthread_threadid_np`, then record it under the existing per-client timing lock. Sixteen distinct thread IDs are retained per client with first/last monotonic callback entry and callback count; evictions and lookup failures are counted. No thread names, paths, stack traces or task ports are needed. The bookkeeping is bounded, but adds private diagnostic overhead and must be measured after installation.

A matching thread's CPU can include other work if GCD shares that thread; observed IDs do not by themselves prove exclusive reader-queue ownership. Whole-extension CPU must not be reported as reader-thread CPU.

## Validation and installed gates

Focused Xcode tests cover off/default gating, both scopes, actor/hash/path/build mismatches, expiry and malformed/unbounded requests, replay protection, concurrent admission, fixed capacity and bounded thread history. Existing ownership/watchdog/ransomware tests remain in the full suite. Xcode result and signed archive provenance are retained locally after the run.

After installation: verify app and both active extensions; run a non-armed synthetic control; explicitly arm one synthetic worker request; verify one injection, watchdog response, zero API errors/duplicate submissions, pending AUTH recovery, delayed-worker completion and unchanged settings. Then correlate passive thread counters under the established footprint/disk/swap limits. This has not yet run on the installed build and does not prove the historical #122 kill cause.

Xcode Cmd-U validation on November 22 passed **1,090 tests**, zero failures/skips, on the Mac Studio. Result bundle: `Test-Nick-2026.11.22_19-27-18-+0300.xcresult`. Thirteen main-thread runtime warnings are present; this is not a warning-free run. The pure admission tests and bounded thread-history test passed. Debug compiled the loader for verification while its runtime hook stayed disabled; the private archive separately compiles the private ES entry points. Installed fault-injection and overhead validation remain pending.
