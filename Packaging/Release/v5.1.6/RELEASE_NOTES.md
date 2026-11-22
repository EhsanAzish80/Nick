# Nick 5.1.6 — backup scan memory and AUTH reliability

Release: **5.1.6 (5119)** for macOS 26 and later.

## Fixed

- Coalesce credential observations before resolving identity, removing repeated trust-validation work under frequent credential-store opens.
- Replace repeated creation-history pruning and sorting with bounded heap/path-index tracking, preserving create-before-rename ordering and atomic-save behavior.
- Release Foundation read allocations per streaming-hash chunk instead of retaining them for the full scan.
- Reserve deferred AUTH response ownership only at submission, so an independent watchdog can still respond while a worker is delayed.
- Recover once, with the same verdict, from an internal response communication failure; prohibit concurrent submissions and do not retry terminal errors.

## Validation

The local Xcode suite passed **1,091 tests**, with zero failures/skips and 13 recorded main-thread runtime warnings. Current-head PR CI, both Sonar checks and Codecov patch passed before merge.

Installed private 5118 completed the retained synthetic SMB image: **737 entries / 552 files in 277 seconds**, with sampled peak **100.8 MiB** and final **94.0 MiB** footprint. No new termination reports, response errors, late attempts or pending AUTHs appeared. The same settings/process survived, and test resources were cleaned up. Memory did not return to its starting footprint during the bounded observation.

Separate synthetic credential and prelaunch worker delays each produced one successful watchdog response while the worker slept. These hooks are private-build-only and are disabled in this public release. No blanket backup-app exclusion, scan-policy reduction, certificate-trust change or timeout fallback change is included.

## Remaining limits

The historical kernel-termination cause and full remote Time Machine/Backblaze workload are not established as resolved. Reader-thread CPU attribution and long-duration write-budget compliance remain follow-ups. **Issue #122 stays open.** These are measured fixes to identified costs and response ownership, not a claim that every reported symptom is solved.
