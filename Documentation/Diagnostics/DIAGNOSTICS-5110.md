# Private candidate 5110 — creation-history maintenance

Marketing version remains 5.1.5. This private candidate includes the tested 5109 trust-storm work plus the focused creation-history cost change. No release or publication is part of this work.

`BehaviorTracker.recentCreations` now uses a timestamp min-heap with a path-to-slot index. A path has exactly one heap slot; refreshing it changes its value/time in place and repairs the heap in either direction. Rename consumption and exit cleanup remove indexed slots directly. There are no stale queued generations or tombstones.

Create and rename still use the same synchronous BehaviorTracker lock and order. Creation evidence retains the 60-second window, strict older-than expiry boundary, 4,096-record cap, timestamp-oldest eviction, PID/process-group checks and the existing ten-second atomic-swap predicate (including its existing behavior for future timestamps). No reader-thread dispatch or trust/enforcement policy changes. Equal-timestamp eviction now has a deterministic path tie-break; the prior dictionary sort did not define a stable order among tied timestamps. Exact equivalence is claimed for distinct timestamps, not an arbitrary old tie order.

Per update/removal maintenance is O(log n), with O(n) bounded storage. Pruning removes only expired/excess heap roots; a large expiration batch can cost O(k log n) on that call. Exit cleanup still walks the bounded index. The create/rename hot path no longer rebuilds a dictionary or sorts all records.

Xcode tests include randomized reference comparison against the old filter/sort algorithm over create, rename consumption, cleanup and out-of-order timestamp sequences, comparing stored evidence and atomic predicates. Targeted tests cover expiry boundaries, the cap, same-path refresh, heap rebalancing/removal, deterministic ties and loss of the atomic exemption after eviction. Existing ransomware and routine Apple rename tests remain required in the full suite.

Installed 5110 creation validation passed on 2026-11-19:

- The bounded creation burst completed 75,000 files in 30 seconds at every requested rate, with CPU reduced from 97% on the earlier implementation to 21% on 5110.
- The installed T1486 replay produced durable `PREVENTED` evidence for the protected `mass_file_rename` rule in no more than 0.80 seconds.
- A same-process atomic-save fixture created and immediately renamed 20 extensionless temporary files to `.styl` destinations without a notification or new Rapid file-renaming incident.
- The Xcode equivalence suite remained green. Together these results close the 5110 creation-history performance and same-process atomic-save gate.

An initial shell fixture did alert because interactive `zsh` created each file and a separate `mv` process renamed it. The same cross-process pattern also alerts on 5109, so it is not a 5110 regression, but it is a real deferred false-positive class for build tools and package managers that repeatedly use `cmd > tmp && mv tmp final` in one folder. Kernel birth-time evidence planned during the earlier 5074 work was never implemented; no extension or shared code currently reads `es_file_t.stat.st_birthtimespec`.

Deferred backlog, explicitly outside 5110: treat a rename as an atomic save when the source file's kernel birth time is no more than 60 seconds before the rename, independent of the creating process. Preserve the existing overrides: appending an extension to a named file still counts, encrypted-replacement evidence still counts, and the exemption is void when the same lineage deletes pre-existing originals in that folder. Do not use path or filename allowlists. The exact `zsh` to `mv` loop must stay silent while T1486 remains PREVENTED.

The remaining gates are unchanged: USB linearity with allocation attribution, then kill diagnostics. A later reporter build may carry the proven trust-storm and creation-hotspot fixes, the USB fix only if confirmed, and the instrumentation. The USB memory and Backblaze deadline mechanisms remain unattributed. No USB change is included in 5110.

Final Xcode UI validation on 2026-11-19: 1,049 tests passed across two test targets, including seven new creation-index tests. No CLI test runner was used. Installed 5110 creation checks subsequently passed as recorded above.
