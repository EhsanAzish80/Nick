# Issue #139: Investigate minutes-long UI activation stalls

Related issue: [#139](https://github.com/EhsanAzish80/Nick/issues/139)

## Current status

Focused implementation in progress: remove repeated Home activity presentation work from SwiftUI rendering. This addresses a measured main-thread CPU hotspot; it does not yet establish the cause of every reported minutes-long activation stall. The original issue remains open. Base checkpoint: `171d1a8b3aea0c59628cae5817bc95d98c4b3951`.

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

## Measured main-thread hotspot (2026-11-27)

Two existing macOS `Nick` CPU resource reports, dated November 22 and 23, identify heavy SwiftUI Home-body work. The November 23 report covers build 5118, records 90 CPU seconds over 162 seconds, and has 17 of 20 samples in Home-body evaluation. Its arm64 image UUID `D91BE8E6-BE31-3327-8320-BE74DAA50952` matches the retained 5118 app dSYM.

Symbolication maps app offsets 1526184, 1530556, 1533096, 1538372, 1539180, 1539644, 1558076 and 1523900 to `SimpleHomeView.body`, its layout closures, `activityFeed` and `activity`. This is the GUI application, not the Endpoint Security extension. Reading these existing reports did not attach a profiler to either process.

The activity feed recomputed `HomeActivityLine.recent` for its empty state, rows and animation identity. Each computation rebuilt all alert presentations through `UserFacingAlertBuilder`, including its pattern matching, although `SecurityEngine.userFacingAlerts` already held the current presentation snapshot.

### Implementation

- Home activity consumes the existing engine presentation snapshot, avoiding alert pattern matching during feed rendering.
- Empty state, rows and animation identity share one feed calculation per render.
- The technical-input model entry point remains available for existing callers; both paths retain the same daily summaries, ordering and display limit.
- Reset clears the prepared snapshot together with technical alerts, preventing stale feed content.
- Detection, enforcement, incident persistence, review state and notification policy are unchanged.

### Validation status

The Xcode UI full run `Test-Nick-2026.11.27_12-04-34-+0300.xcresult` completed with 1,093 passed, zero failed and zero skipped. This includes the two new prepared-presentation tests. It reports 13 main-thread runtime warnings; these are not treated as resolved (#51 remains separate). The final focused Xcode run `Test-Nick-2026.11.27_12-12-13-+0300.xcresult` passed all 17 Home model tests, zero failed/skipped and zero runtime warnings, including populated-state reset. The preceding focused attempt caught an invalid empty-evidence test fixture; the corrected fixture uses a synthetic evidence-backed finding. No real command or credential access was executed by that fixture.

No installed build comparison has been performed. The current installed 5119 UI was accessible when inspected, which does not reproduce the historical stall. The full activation/loading acceptance checklist remains open, and this PR must not close #139 on the strength of model tests alone.
