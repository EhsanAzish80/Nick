# Issue #139: Investigate minutes-long UI activation stalls

Related issue: [#139](https://github.com/EhsanAzish80/Nick/issues/139)

## Current status

Draft work plan only. No runtime implementation, reproduction, fix or test pass is claimed by this commit. The original issue remains open. Base checkpoint: `171d1a8b3aea0c59628cae5817bc95d98c4b3951`.

## Problem and scope

[Bug]: Recurrent minutes-long UI stalls on notification, menu-bar and Dock activation

Trace notification, menu-bar and Dock activation through main-actor responsiveness, window/scene lifecycle, first render and data readiness. Establish a concrete blocking path or lifecycle race before changing behavior.

## Initial code review targets

These are investigation entry points, not established causes:

- `Nick/App/AppDelegate.swift`
- `Nick/App/MainWindowView.swift`
- `Nick/Core/ThreatCorrelator/IncidentStore.swift`

## Scope boundaries

Do not assume alert-only findings caused the stall, or suppress findings as a workaround. Keep #51 separate unless measurements establish a shared cause.

This PR owns only issue #139. Keep implementation, tests and validation evidence in this branch. If shared code needs an earlier sibling change, document that dependency and rebase explicitly rather than bundling other issues into this PR.

## Acceptance and validation

The issue remains the source of the full report and acceptance criteria. Initial checklist:

- [ ] Reproduce menu-bar and Dock activation from hidden, closed and existing-window states, including before scene-action registration.
- [ ] Check under bounded synthetic incident ingestion without real private evidence or protection changes.
- [ ] Distinguish click delivery, activation, window creation/ordering, first render and data readiness with bounded diagnostics.
- [ ] Identify concrete blocking work or a lifecycle race before implementing a fix.
- [ ] Show responsive initial content/loading state and consistent activation from both routes.
- [ ] Add focused Xcode regressions for the proven cause and verify installed behavior.
- [ ] Do not suppress findings or weaken protection as a UI workaround.

- [ ] Record the confirmed cause and resulting implementation in this document.
- [ ] Run relevant Xcode tests when implementation exists; do not label the planning commit as a tested fix.
- [ ] Review protection and detection impact, including negative cases where applicable.
- [ ] Keep this PR draft until the issue-specific evidence is complete.

No merge, release or additional live workload is requested by this planning checkpoint. Existing evidence and dSYMs remain preserved. Use synthetic fixtures, bounded diagnostics and redacted public evidence; do not post credentials, personal paths or raw private reports.
