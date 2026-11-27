# Issue #51: Investigate Performance Diagnostics main-thread work

Related issue: [#51](https://github.com/EhsanAzish80/Nick/issues/51)

## Current status

Draft work plan only. No runtime implementation, reproduction, fix or test pass is claimed by this commit. The original issue remains open. Base checkpoint: `171d1a8b3aea0c59628cae5817bc95d98c4b3951`.

## Problem and scope

Move Performance Diagnostics work off the main thread

Identify the exact API and caller producing the recorded main-thread runtime warning; move proven blocking work off-main with UI publication on MainActor.

## Initial code review targets

These are investigation entry points, not established causes:

- `Nick/Core/PerformanceEngine/PerformanceMonitor.swift`
- `Nick/Core/PerformanceEngine/PerformanceCoordinator.swift`
- `Nick/App/Dashboard/PerformanceView.swift`

## Scope boundaries

Do not assume this explains #139. Keep diagnostics value/refresh semantics intact; no speculative changes based only on the warning text.

This PR owns only issue #51. Keep implementation, tests and validation evidence in this branch. If shared code needs an earlier sibling change, document that dependency and rebase explicitly rather than bundling other issues into this PR.

## Acceptance and validation

The issue remains the source of the full report and acceptance criteria. Initial checklist:

- [ ] Identify the API call and call path responsible for the fault.
- [ ] Move the work off the main thread while keeping UI state updates on `MainActor` where required.
- [ ] Add a regression test where practical.
- [ ] Verify the warning is absent in focused bounded Diagnostics refresh/reopen validation; the original issue’s 30-minute window is historical and no new soak is scheduled by this draft.
- [ ] Confirm Diagnostics values and refresh behavior remain correct after the change.

- [ ] Record the confirmed cause and resulting implementation in this document.
- [ ] Run relevant Xcode tests when implementation exists; do not label the planning commit as a tested fix.
- [ ] Review protection and detection impact, including negative cases where applicable.
- [ ] Keep this PR draft until the issue-specific evidence is complete.

No merge, release or additional live workload is requested by this planning checkpoint. Existing evidence and dSYMs remain preserved. Use synthetic fixtures, bounded diagnostics and redacted public evidence; do not post credentials, personal paths or raw private reports.
