# Private 5115: full ES callback timing

Observation only. Preserves 5114 and its streaming-memory fix. No enforcement,
trust, cache, subscriptions, watchdogs, settings or reply ownership changes.

Each ES client has independent bounded scalar diagnostics (primary and shell
profile write client). Entry is sampled before instrumentation; body end after
EventHandler and autoreleasepool cleanup, before diagnostic finish and the
block-return epilogue. This is an approximation of full callback wall duration,
not CPU time or kernel delivery latency. Two short per-callback lock sections
and a matching response annotation add overhead; installed overhead is unproven.
Snapshot serializes outside the lock; the reader never waits on bulk analysis.

Retains 16 records for bodies >=10 ms or AUTH event-to-entry >=100 ms, counts
overwrites, and preserves the maximum callback separately. Each record includes
its immediate predecessor's event, body entry/end, and synchronous response
return if observed; also previous body overlap with the current event-to-entry
interval and gap since previous body end. Missing predecessor/response is null,
not a zero duration or proof of missing reply. A response deferred until after
callback completion is left to existing response/pending diagnostics. No ES
pointers, paths, arguments, PIDs, credentials or unbounded history are retained.
No per-event asynchronous work or logging. Sequence mismatch counter makes a
broken serial-callback assumption visible. Different clients never share a
predecessor. Maximum may predate the test window; timestamps must be filtered.

Tests cover post-response work, predecessor overlap versus idle gaps, NOTIFY,
deferred response isolation, bounded history/max retention, fast callbacks,
independent clients, missing timebase and mismatches. No claim of fixing delays.
Private local installation, passive overhead baseline and matched bounded SMB
fixture are separate gates after Xcode, packaging and notarization. No publish.
