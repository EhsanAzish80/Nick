# Nick 5.1.4 — reader-path and persistence reliability update

Release: **5.1.4 (5106)** for macOS 26 and later.

## Fixed

- Remove the remaining shell-profile realpath lookup from the Endpoint Security reader thread. Exact canonical targets are indexed at setup; per-event checks use immutable membership only.
- Reject FIFO, symlink and non-regular files before worker header reads, using a bounded prefix reader.
- Batch unchanged incident observations and notification retries, including protected observations, without bypasses based only on tier, severity or the quarantine-execution reason. New incidents, escalations, reopenings, unconfirmed first findings, actual enforcement and authenticated user actions remain urgent. Events remain unacknowledged until their state is durably stored.
- Separate local late-response observations from response API errors. Diagnostics explicitly mark kernel deadline termination counts as unknown, retain a bounded previous-session summary and show the slowest completed response alongside recent percentiles.

No backup-app exclusion or protection-rule relaxation was added.

## Evidence and limits

The reporter's two 5105 crash reports match our retained arm64 symbols. Their reader-thread offsets identify the remaining realpath lookup; worker frames identify the header read. Regression tests cover exact path matching, FIFO/symlink rejection, repeated-observation write batching, urgent enforcement, persistence acknowledgements and counter/restart semantics.

Local validation: 1,016 Swift tests, 52 Python tests and repository validation passed. The signed payload passed YARA checks across 11 executables. Installer and disk image are signed, Apple-notarized, stapled and Gatekeeper accepted. No installed scorecard was rerun.

The full Backblaze workload has not been reproduced locally. The reporter's later multi-GB peak footprint is not claimed resolved. Local tests and these fixes do not establish absence of further deadline stalls; issue #122 stays open for confirmation. No additional soak or installed scorecard is run.

Thanks to **prismatic7** for the crash reports and detailed follow-up measurements.
