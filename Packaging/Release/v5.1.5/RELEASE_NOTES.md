# Nick 5.1.5 — bounded persistence and write-churn fixes

Release: **5.1.5 (5107)** for macOS 26 and later.

## Fixed

- Stop rewriting the full endpoint-event snapshot for unknown or repeated acknowledgements. Matching acknowledgements now append small, synchronized journal records; replay preserves their removal after restart.
- Use the writer's actual file offset for the endpoint journal limit, avoiding cached file-size values that could prevent checkpoints.
- Journal network observations instead of rewriting the retained array for every flow. Retain the newest 500 events, recover completed records after partial writes, and read both existing snapshots and the new journal.
- Batch unchanged network-incident recurrences while keeping new incidents and enforcement urgent. Delivery cursors still advance only after durable persistence succeeds.
- Bound the network observation throttle to 1,024 entries even during unique-host churn. Connection inspection and verdicts are unchanged.

No backup-app exclusion or protection-rule relaxation was added. The native backup workload executable is test-only and is absent from the installer.

## Validation

- Xcode reported **1,029 tests passed**, including persistence, checkpoint/restart, retention, failed-write, urgent-enforcement and memory-bound regressions.
- A native four-worker synthetic workload performed 98,304 file reads, 3,072 writes and 1,024 renames while exercising 5,000 endpoint evidence/acknowledgement cycles and 5,000 network records. Recorded endpoint compaction writes were about 5.7 KB, rather than a full snapshot per acknowledgement.
- After installing 5107 locally, two focused Xcode runs completed **196,608 file reads** in total. The app and both active extensions were verified at 5107; sampled extension process identities stayed unchanged, locally observed late attempts and response errors remained zero, and no matching launchd/kernel termination entries were returned for the checked interval. No new actionable alerts appeared.
- The preliminary live write projection was **25.6 MB/day against a 52.4 MB/day target** over a four-and-a-half-minute measurement window. It includes ordinary background activity and is not a sustained Backblaze measurement.
- The installer and disk image are Developer ID signed, Apple-notarized and stapled; Gatekeeper accepts both. Both packaged extensions match build 5107.

## Still awaiting confirmation

The reporter's full Backblaze workload has not been reproduced locally. Their latest 5106 report described no deadline terminations over a three-hour window spanning a transmit pass, with a flat memory peak, but persistent excessive writes. This release targets the remaining write amplification identified in that report. Short synthetic tests do not establish that the original multi-hour termination or peak-footprint problem is eliminated. Issue #122 remains open for workload confirmation.

AUTH percentiles cover the recent retained sample window; the maximum covers completed calls in the current process. A local late-attempt count is not an early-warning threshold or a census of kernel deadline terminations. macOS termination logs remain necessary.

Thanks to **prismatic7** for the diagnostics and follow-up measurements.
