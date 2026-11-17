# Issue #122: write churn and deadline diagnostics follow-up

Emergency 5.1.4 follow-up on `fix/incident-write-churn-deadline-diagnostics`.
The user authorized release after the reporter supplied the matching 5105 .ips reports.

## Write amplification

The 5105 paths could still force full incident snapshots for unchanged protected
observations through their tier, severity or `quarantine_executable` reason.
Additionally, notification retry eligibility was being promoted to an urgent
persistence outcome. Undelivered notifications therefore kept repeated,
already-recorded incidents urgent.

The incident store now tracks unconfirmed urgent incident mutations separately
from notification eligibility. New incidents, severity increases, reopenings and
unconfirmed first findings remain urgent. A notification retry or unchanged
observation alone can use the existing fifteen-minute snapshot batch, including
an unchanged protected observation. Actual AUTH-deny, blocking and remediation
evidence, plus authenticated user actions, still force prompt persistence.
Detection, enforcement eligibility and root-journal capture are unchanged.
Events are acknowledged only after a successful root-owned snapshot covers their
generation. A later urgent write can also durably cover queued routine updates.

The transport regression uses a real temporary PrivilegedIncidentFileStore:
one initial observation is persisted immediately; 120 recurrences without a
delivered notification produce no additional full-file writes until one batch
flush; acknowledgements wait for that flush. Two subsequent AUTH denials force
persistence without a routine flush. Another regression confirms that an older
snapshot confirmation does not clear a newer unconfirmed urgent mutation.

This reduces avoidable recurrence writes. It does not promise the daily write
budget under arbitrary new incidents, enforcement or user actions. It also does
not eliminate snapshot encoding on every in-memory mutation.

## Deadline diagnostics

The old deadline counter mixed locally observed late response attempts with
all response API errors. It also reset at process restart and could not count a
kernel kill that happened before the process returned or persisted its metrics.

Health schema 2 separates late response observations from response errors, with
last error code/event and timestamps. The legacy `deadlineMissCount` is retained
as an explicitly documented alias for local late attempts only. Kernel deadline
termination count is null/unknown and requires an OS diagnostic; it is never
inferred as zero from local counters or an ordinary process restart.

Response latency now runs from the ES message's mach timestamp through response
API return. Recent percentiles retain the existing fixed-capacity window. A
process-lifetime maximum preserves a rare completed outlier after that window
rotates. Unreturned attempts remain unobservable through these latency samples.

Each health record includes process ID, process-instance UUID, startup time,
process/system uptime and boot-session identity. A bounded allowlist preserves
one previous process's summary across startup. Same-boot restarts have unknown
cause; reboots and legacy records are identified separately. No file paths,
arguments, nested history or arbitrary prior fields are carried forward.
Diagnostics UI explicitly explains the counter and sampling limits.

The remaining kernel deadline termination is not claimed fixed. The reporter's
5105 UUID matches retained debug symbols; raw .ips evidence is still needed to
isolate the unresolved stall. No additional soak or installed scorecard is run.

## Matching crash evidence and reader-path fix

Both 5105 crash reports match arm64 UUID DF78C0B7-543F-308E-BD14-9A3C6058E125.
Offsets 209320, 645056, 609924 and 610140 symbolicate to
FileIntegrityMonitor.isExactShellProfile, ESEventHandler.handleWithinPool and
the EndpointSecurityClient reader callback. isExactShellProfile canonicalized
every write-open path with realpath, even after answering that individual open;
this still blocks the serial reader from handling subsequent messages.

The reader now matches only an immutable index of exact canonical targets, built
before ES starts. Startup/configuration canonicalization remains intact. It does
not trust a filename alone or broaden monitored paths. A 50,000-query regression
checks exact configured-file matches and rejects unconfigured paths/directories.

The worker offsets 91280 and 779428 map to ScanCandidatePolicy.kind(atPath:) and
shouldDeepScanModifiedFile. Header classification now uses the existing
O_NONBLOCK/O_NOFOLLOW descriptor reader with fstat regular-file validation and
a fixed prefix size. FIFO/symlink regressions cover classification itself. This
prevents special-file header reads from indefinitely waiting for input; it does
not guarantee a time bound for regular files on a stalled filesystem.

The reporter also observed multi-GB peak footprint later on 5105. These local
changes and tests do not establish resolution of that full workload or memory
peak; reporter confirmation and further profiling remain necessary.
