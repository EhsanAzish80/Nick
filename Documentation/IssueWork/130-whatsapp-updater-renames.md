# Issue #130: Scope WhatsApp updater resource renames

Related issue: [#130](https://github.com/EhsanAzish80/Nick/issues/130)

## Current status

Draft work plan only. No runtime implementation, reproduction, fix or test pass is claimed by this commit. The original issue remains open. Base checkpoint: `171d1a8b3aea0c59628cae5817bc95d98c4b3951`.

## Problem and scope

[False positive]: WhatsApp Sparkle update resource renames trigger ransomware alerts

Reproduce benign Sparkle staging resource finalization and determine the narrow validated actor/source/destination conditions.

## Initial code review targets

These are investigation entry points, not established causes:

- `Shared/RansomwareNotePolicy.swift`
- `NickExtension/Behavioral/BehaviorTracker.swift`
- `NickTests/RansomwareAtomicRenameTests.swift`

## Scope boundaries

Do not broadly exempt ditto, Sparkle, WhatsApp or the .mom extension. Keep #129 and #131 distinct.

This PR owns only issue #130. Keep implementation, tests and validation evidence in this branch. If shared code needs an earlier sibling change, document that dependency and rebase explicitly rather than bundling other issues into this PR.

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
