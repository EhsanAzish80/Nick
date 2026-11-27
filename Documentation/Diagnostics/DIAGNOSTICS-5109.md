# Private diagnostic candidate 5109

Marketing version remains 5.1.5. This candidate is for a matched installed Test A comparison with 5108, not publication.

## Scope

Credential-store observations are admitted before dispatching attribution work. Exact keys include actor audit/image identity, executable path, responsible and parent audit tokens, target path, file identity, owner and store type. Repeated matching observations coalesce for 60 seconds. Different targets and process instances remain distinct.

Admission permits at most 128 pending observations (including delayed reviews) and retains at most 2,048 keys. A fixed-size FIFO avoids dictionary filtering on admission. Pressure drops observation enrichment only, increments health counters and emits a throttled degradation finding. Existing AUTH enforcement responds before this gate. Lightweight keychain read/copy correlation also precedes admission and remains independently bounded at 4,096 process records, with eviction counts exposed. Delayed review uses one timer chain per admitted target and checks the latest matching read before cancellation/reporting.

Responsible identity attribution uses a bounded 1,024-entry, five-second positive/negative cache with at most 32 concurrent reservations and single-flight work per key. Keys require captured ES image metadata plus live process-instance, executable and bundle-info file stamps. Cached hits recheck those guards. Fresh validation checks the Security result against ES cdhash, signing ID and team ID and discards a result if the image changed. Missing ES evidence uses the original uncached validation. Busy/changed attribution returns unknown rather than fabricating trusted identity. Security work runs outside cache locks.

No revocation, expiration or certificate trust-policy flags were changed. The 5108 validator diagnostic wrappers remain present. No enforcement rule was intentionally changed. This does not bound every other event-handler branch and does not establish the cause of the reporter's deadline kills or 15 GB footprint.

## Diagnostics

Health includes credential observation admissions, pre-queue coalescing, pressure drops, queued/active/delayed counts, oldest queued/pending age and bounded queue-wait p99/max. Attribution exposes identity and Security call counts/durations, identity p99 duration, cache hits/misses/busy/evictions and capacity. Keychain correlation exposes pending/capacity/eviction counts. These measurements distinguish queued work from delayed review timers.

## Validation and next gate

Xcode UI tests cover 60,000 duplicate reads, distinct evidence, pressure recovery, queue metrics, keychain correlation preservation, stale timers, cache expiry, single-flight and capacity. Final frozen-source Xcode UI run: 1,042 tests passed across two test targets (2026-11-19). This is source-level validation; installed 5109 Test A remains pending.

After manual installation, verify Nick.app and both active system extensions are 5109 before reusing the unchanged signed Test A reader and synthetic fixtures. Compare the same load and recovery windows with preserved 5108 evidence: trust-anchor rate, attribution call counts, queue wait/depth, CPU tail, footprint and session continuity. No scorecard or soak is required for this comparison. No real credentials are needed. No release, PR, push or website publication is part of this candidate.
