# Private 5114 — completed AUTH outlier attribution

Retains the 5113 scoped streaming-read memory fix. Adds observation only around
existing callback and response boundaries. No AUTH subscriptions, trust rules,
verdicts, response flags/cache setting, watchdog scheduling or fallbacks change.

`slowAuthResponseDiagnostics` records completed attempts at least 100 ms,
response errors, or returns at/past deadline. A preallocated 16-record ring
reports overwrites; a separate maximum record survives ring rotation. Fields:
raw event type/result, allow/deny decision, monotonic event/callback/API/return
and deadline ticks, event-to-callback time, callback-to-API time, API duration,
signed deadline margin, pre-response diagnostic phase, and wall recording time
immediately after return. Missing/invalid callback timing is null, not zero.
Unanswered AUTHs remain the pending-AUTH diagnostics' responsibility.

No pointers, executable/file paths, arguments, credentials, hashes or signing
identities enter outlier records. Normal successful replies below threshold do
no allocation or additional outlier-ring locking. Existing pending bookkeeping
provides callback time and phase without a second per-event registry. Timestamp
reads are monotonic; timebase is cached. Serialization is done in health code,
not the ES reader callback. Diagnostic recording follows the existing response
API; it never selects or owns a response and cannot submit a second reply.

Xcode tests cover decomposition/byte-free payload serialization, unavailable
callback timing, ring overwrite/maximum retention, fast-path filtering,
error/late recording and pending phase preservation. Installed timing overhead
and actual slow-event attribution remain validation gates, not claimed results.

Use short passive capture first, then the retained fixture if needed. Keep the
same footprint/disk/swap limits. No task-attaching profiler on live ES. Exact
binaries, source/test evidence, dSYMs and notarized installer are preserved
locally. No merge, release, appcast, website or public distribution authorized.
