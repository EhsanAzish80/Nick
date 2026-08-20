# Nick Enterprise Pilot Resource Budgets

These are release acceptance limits, not aspirational measurements. Tests must
record hardware, macOS version, Nick build, enabled providers, observation
window, and measurement method.

## Idle state

Measured after five minutes of stabilization with no UI interaction:

- Main app average CPU: **at most 1%** over 15 minutes.
- Endpoint extension average CPU: **at most 1%** over 15 minutes.
- Network extension average CPU: **at most 1%** over 15 minutes.
- Combined resident memory: **at most 250 MB** in the standard pilot setup.
- Main-thread hangs longer than 100 ms caused by Nick background work: **zero**.
- Continuous polling faster than 5 seconds without an active user-requested
  capture: **zero**.

## Active diagnostics

- Default runtime observation: 30 seconds.
- Managed observation range: 5–300 seconds.
- UI remains responsive during capture and cancellation completes promptly.
- A capture never launches overlapping full scans for the same request.
- Provider event queues and saved snapshots remain bounded by their documented
  limits; dropped events are counted and reported.

## Disk and logs

- Default retention: 14 days; managed maximum: 90 days.
- Enterprise operational logs: maximum 25 MB per file, maximum four rotated
  files per component.
- A diagnostic bundle must calculate its projected size and refuse output over
  100 MB unless a future reviewed contract defines a larger bound.
- Temporary output is removed after failure or cancellation.
- No unbounded JSON array, event history, cache, or support bundle is accepted.

## Network

- No periodic cloud upload in the pilot.
- No packet or page-content inspection.
- Health reporting writes locally and does not create network traffic.
- The Network Filter remains fail-open and must not interrupt ordinary traffic,
  AirDrop, Continuity, Git, developer tooling, or software updates.

## Energy and regression gates

- Run an eight-hour workday observation on at least one Apple silicon Mac.
- Compare Energy Impact, CPU time, wakeups, disk writes, and memory against the
  same Mac with Nick stopped.
- A regression exceeding 20% of Nick's prior accepted idle measurement blocks
  release even when the absolute ceiling is not exceeded.
- Any reproduced connectivity disruption, prompt loop, UI hang, or repeated
  extension-install request blocks the pilot build.
