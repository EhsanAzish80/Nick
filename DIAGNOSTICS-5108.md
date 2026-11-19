# Private credential AUTH diagnostic candidate — build 5108

Local candidate only; not a release or a claimed fix. Marketing version remains 5.1.5. No flags, verdicts, cache ordering, watchdog budgets, fallback decisions or queue placements were changed. Timing/counter instrumentation necessarily adds some overhead.

## Verified code and SDK

`DeveloperIDTrustValidator.isValidated` and `.isValidatedDistribution` call static-code creation and `SecCodeCopySigningInformation(kSecCSSigningInformation)` before their cdhash cache check. The installed SDK's `Security.framework/Headers/SecCode.h` says that signing-information flag returns certificate-chain and CMS information. This does not establish that every call triggers an online evaluation.

`CSCommon.h` defines `kSecCSEnforceRevocationChecks = 1 << 30` (force revocation checks regardless of preferences), `kSecCSConsiderExpiration = 1U << 31` (request rejection of expired certificates), and `kSecCSNoNetworkAccess` (not currently set). Both existing flags remain unchanged. Per-call network traffic and any particular TemporalValidity failure still need measurement; the flag text alone does not establish causation or all timestamp-policy details.

Negative validation results are cached when the code reaches the final cache write. Earlier failures, before obtaining a hash or requirement, may return without caching. AUTH_OPEN already checks the kernel cdhash cache before deferring: one repeatedly reading actor can become a warm-cache case rather than repeatedly exercise trust validation. Credential work, prelaunch hashing and their watchdogs share `preLaunchQueue`; thread-pool starvation is a hypothesis, not a verified cause.

## Diagnostics

The existing `extension_health.json` gains `credentialAuthDiagnostics` and `processThreadCount`. Fixed enum slots track function starts/completions, current/peak work, queue-wait timings, retained-message lifetimes, watchdog dispatch delay, winning/losing response claims, cache outcomes, Security API durations/counts and last completed OSStatus. No paths, hashes or credential contents are stored. Thread count is a self-process kernel query, not a task-attaching profiler.

Counts/timings are process-lifetime. Existing health persistence cadence is unchanged (about 30 seconds), so a kill may lose the final interval. Retained-message in-flight counts include closures that outlive a winning watchdog; they are not unanswered-message counts. Work counts are executing blocks, not live queue depth. A won response claim is not proof of an accepted ES API response; correlate existing response errors and OS termination evidence. Last OSStatus can be overwritten by a later call; failure counts remain cumulative.

## Test A readiness

1. Install the private candidate and verify app plus BOTH active extensions at 5108. Preserve history.
2. Confirm Strict Mode OFF. The runner requires `--strict-mode-confirmed-off`; it does not change policy.
3. Start passive kernel memory/CPU and health collection. Do not attach heap, sample, vmmap or Instruments during the clean run.
4. Run the normal-network case first, initially bounded to 60 seconds, 8 threads and 1,000 opens/s.
5. Verify deferred AUTH and validation counters actually rise. A warm cache with no deferrals is a negative control, not a reproduction of starvation.
6. Record claim outcomes, queue waits, validation duration, watchdog delay, active work, thread count, health freshness and launchd termination evidence before making a causal claim.

The separate reader is Developer ID signed by UXGW5V3BY6 with identifier `com.3nsofts.diagnostics.CredentialReader`, not a Nick identifier or Apple platform binary. It is not embedded in the installer. The runner creates only synthetic `Cookies`, `Library/Keychains/synthetic.keychain-db`, and `.ssh/id_synthetic` beneath a private nonce-marked scratch root. The reader opens/closes fixed paths only, without reading their contents or opening the network.

Local test artifacts: `/private/tmp/NickCredentialTestA-5108/credential-reader` and `run-test-a.py`. After installation and passive collection are ready:

```
/usr/bin/python3 /private/tmp/NickCredentialTestA-5108/run-test-a.py --strict-mode-confirmed-off --seconds 60 --threads 8 --rate 1000
```

Do not run yet on 5107 and mistake it for candidate evidence. The first unknown reader hash is the cold case; later accesses may hit the cache. Distinct-hash cold bursts would require separately signed variants and must be labelled separately.

Network impairment and expired-certificate execution are NOT prepared or enabled. No system-wide DNS, hosts, firewall, trust-settings or clock changes. No large-file workload or MallocStackLogging configuration in this step. Stop a later test on process replacement, excessive physical footprint, stale health or unexpected errors; never auto-disable protection.

## Local build boundary

Xcode UI: the two focused diagnostic regression tests passed. Build 5108 is Developer ID signed, Apple-notarized and stapled following explicit authorization. Gatekeeper accepts the installer. Submission: bffe8f01-ec1d-41ee-aa33-ee14f9962a30. Final package SHA-256: 752f263dd15adbd2855dbb2685a8895dc021a1e1448ccb75e4d9209cf02c2120. No PR, push, release, website/appcast update, installation or reporter message is performed by this work.
