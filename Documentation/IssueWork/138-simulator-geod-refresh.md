# Issue #138: Scope simulator GeoServices resource refresh

Related issue: [#138](https://github.com/EhsanAzish80/Nick/issues/138)

## Current status

Draft work plan only. No runtime implementation, reproduction, fix or test pass is claimed by this commit. The original issue remains open. Base checkpoint: `171d1a8b3aea0c59628cae5817bc95d98c4b3951`.

## Problem and scope

[False positive]: iOS Simulator geod resource refresh triggers ransomware rename alert

Cover the reported same-device simulator temp-to-GeoServices resource finalization beyond the existing host-only geod shape.

## Initial code review targets

These are investigation entry points, not established causes:

- `Shared/RansomwareNotePolicy.swift`
- `NickTests/RansomwareAtomicRenameTests.swift`

## Scope boundaries

Require narrow validated actor and same-user/device boundaries. No CoreSimulator, geod or resource-extension blanket exemption.

This PR owns only issue #138. Keep implementation, tests and validation evidence in this branch. If shared code needs an earlier sibling change, document that dependency and rebase explicitly rather than bundling other issues into this PR.

## Acceptance and validation

The issue remains the source of the full report and acceptance criteria. Initial checklist:

- [ ] Reproduce with harmless synthetic source/destination paths and a rename burst; no real simulator data is changed.
- [ ] Recognize narrowly validated simulator GeoServices finalization within the same user and exact device data root.
- [ ] Preserve host GeoServices behavior and reject cross-user/cross-device moves, non-UUID staging, unrelated destinations, spoofed actors and unvalidated runtime identity.
- [ ] No broad `geod`, Apple-platform, CoreSimulator-directory or `.icondatapack` exemption.
- [ ] Independent canary and strong ransomware evidence remain evaluated; unrelated malicious write/rename activity remains protected.
- [ ] Positive/negative regression coverage passes in Xcode, followed by focused installed validation of the eventual fix.

- [ ] Record the confirmed cause and resulting implementation in this document.
- [ ] Run relevant Xcode tests when implementation exists; do not label the planning commit as a tested fix.
- [ ] Review protection and detection impact, including negative cases where applicable.
- [ ] Keep this PR draft until the issue-specific evidence is complete.

No merge, release or additional live workload is requested by this planning checkpoint. Existing evidence and dSYMs remain preserved. Use synthetic fixtures, bounded diagnostics and redacted public evidence; do not post credentials, personal paths or raw private reports.
