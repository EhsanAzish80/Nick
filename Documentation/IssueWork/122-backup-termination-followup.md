# Issue #122: Investigate remaining backup-load termination uncertainty

Related issue: [#122](https://github.com/EhsanAzish80/Nick/issues/122)

## Current status

Draft work plan only. No runtime implementation, reproduction, fix or test pass is claimed by this commit. The original issue remains open. Base checkpoint: `171d1a8b3aea0c59628cae5817bc95d98c4b3951`.

## Problem and scope

NickExtension SIGKILLed on ES deadline under bursty file-open load; per-event lstat appears to run on the callback path

Audit remaining evidence after the shipped 5.1.6 fixes. Establish current-build termination attribution and representative workload evidence before proposing further runtime changes.

## Initial code review targets

These are investigation entry points, not established causes:

- `NickExtension/EndpointSecurityClient.swift`
- `NickExtension/EventHandler.swift`
- `Nick/Core/Metrics/RuntimeDiagnostics.swift`
- `Documentation/ISSUE-122-VALIDATION-CLOSEOUT-5118.md`

## Scope boundaries

Historical stack locations are not proof of root cause. Do not reframe the shipped fixes as full-workload resolution, add backup-app exclusions, attach profilers to live ES, or start another broad test cycle automatically.

This PR owns only issue #122. Keep implementation, tests and validation evidence in this branch. If shared code needs an earlier sibling change, document that dependency and rebase explicitly rather than bundling other issues into this PR.

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
