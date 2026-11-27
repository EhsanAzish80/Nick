# Issue #49: Refresh delivered notification counts after persistence

Related issue: [#49](https://github.com/EhsanAzish80/Nick/issues/49)

## Current status

Draft work plan only. No runtime implementation, reproduction, fix or test pass is claimed by this commit. The original issue remains open. Base checkpoint: `171d1a8b3aea0c59628cae5817bc95d98c4b3951`.

## Problem and scope

Notification Center count stays stale during protected-incident throttle window

Update existing Notification Center content after durable coalesced occurrence persistence while retaining the canonical incident identifier and silent throttle behavior.

## Initial code review targets

These are investigation entry points, not established causes:

- `Nick/Core/Notifications/NotificationManager.swift`
- `Nick/Core/ThreatCorrelator/IncidentStore.swift`

## Scope boundaries

Preserve the banner/sound throttle, urgent enforcement and durable-write ordering. No additional banner or duplicate canonical incident.

This PR owns only issue #49. Keep implementation, tests and validation evidence in this branch. If shared code needs an earlier sibling change, document that dependency and rebase explicitly rather than bundling other issues into this PR.

## Acceptance and validation

The issue remains the source of the full report and acceptance criteria. Initial checklist:

- [ ] Confirm the current-build behavior with sanitized, issue-specific evidence.
- [ ] Add focused regression coverage for the demonstrated cause.
- [ ] Record positive and negative validation before marking this PR ready.

- [ ] Record the confirmed cause and resulting implementation in this document.
- [ ] Run relevant Xcode tests when implementation exists; do not label the planning commit as a tested fix.
- [ ] Review protection and detection impact, including negative cases where applicable.
- [ ] Keep this PR draft until the issue-specific evidence is complete.

No merge, release or additional live workload is requested by this planning checkpoint. Existing evidence and dSYMs remain preserved. Use synthetic fixtures, bounded diagnostics and redacted public evidence; do not post credentials, personal paths or raw private reports.
