# Issue #122: Scoped termination-report diagnostics

Related: #122. The original full Backblaze workload and historical spontaneous deadline terminations remain unresolved. This PR does not claim a new enforcement fix or full-workload resolution.

## Confirmed reporting gap

The legacy `kernelDeadlineTerminationCount` counts available historical reports, including old builds. Diagnostics displayed an unscoped unknown label. Preserve the legacy field for existing collectors, explicitly describe its historical meaning, and add deduplicated counts for history, current build across sessions, current process (PID/build/start) and previous-session correlation. Expose those distinct labels and inspection status in the app.

Current-process matching requires PID, build, launch proximity and capture after startup. Previous-session cause still uses the existing additional heartbeat/boot checks. Missing, unreadable or capped reports cannot establish zero kills. Report I/O remains on the existing utility queue; no authorization decision, watchdog, scan, exclusion or launch policy changes. Remove the obsolete 5112-purpose label.

## Validation

- [x] Xcode UI: 12 RuntimeDiagnosticsTests passed, zero failures/skips/warnings (2026-11-27 15:02 local).
- [x] Historical 5110 report does not count against a newer build/process; duplicate incident IDs deduplicate; same-build other PID remains separate; PID reuse/start mismatch rejected; previous-session correlation preserved.
- [x] Existing pending-AUTH ownership, bounded diagnostics and IPS rejection tests passed.
- [ ] Fresh CI passes, including shipping extension compilation.
- [ ] Combined private-build diagnostic labels and bounded workload checks.

No new broad soak or reporter request. No profiler attachment, main merge or public release. Evidence: ignored `build/IssueValidation/122/` contains full result and hashes. Preserve the earlier #122 validation closeout and dSYMs; historical stack locations alone do not prove cause.
