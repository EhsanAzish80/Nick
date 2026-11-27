# Issue #140: Scope XCTest SpringBoard cache finalization

Related issue: [#140](https://github.com/EhsanAzish80/Nick/issues/140)

## Current status

Draft work plan only. No runtime implementation, reproduction, fix or test pass is claimed by this commit. The original issue remains open. Base checkpoint: `171d1a8b3aea0c59628cae5817bc95d98c4b3951`.

## Problem and scope

[False positive]: XCTestDevices SpringBoard cpbitmap cache finalization triggers ransomware alert

Cover the reported XCTestDevices temp-to-MappedImageCache operation while preserving the existing CoreSimulator SpringBoard constraints.

## Initial code review targets

These are investigation entry points, not established causes:

- `Shared/RansomwareNotePolicy.swift`
- `NickTests/RansomwareAtomicRenameTests.swift`

## Scope boundaries

Reject cross-user/device and unrelated paths. Repeated identical exports do not establish two distinct incidents. Keep UI causality in #139.

This PR owns only issue #140. Keep implementation, tests and validation evidence in this branch. If shared code needs an earlier sibling change, document that dependency and rebase explicitly rather than bundling other issues into this PR.

## Acceptance and validation

The issue remains the source of the full report and acceptance criteria. Initial checklist:

- [ ] Add harmless synthetic XCTestDevices fixtures matching the reported operation shape.
- [ ] Cover validated platform SpringBoard, exact same-user/same-device root, temp-to-cache basename relationship and destination scope.
- [ ] Preserve existing CoreSimulator behavior and reject cross-user/device paths, malformed UUIDs, unrelated destinations, spoofed/unvalidated actors and unsupported operations.
- [ ] No blanket SpringBoard, XCTestDevices, simulator or .cpbitmap exemption.
- [ ] Preserve independent canary/strong ransomware evidence and unrelated malicious rename/write detection.
- [ ] Positive/negative Xcode regressions and targeted installed validation demonstrate the eventual fix.
- [ ] Investigate duplicate presentation only with distinct row/evidence records; do not infer it from the repeated pasted JSON.

- [ ] Record the confirmed cause and resulting implementation in this document.
- [ ] Run relevant Xcode tests when implementation exists; do not label the planning commit as a tested fix.
- [ ] Review protection and detection impact, including negative cases where applicable.
- [ ] Keep this PR draft until the issue-specific evidence is complete.

No merge, release or additional live workload is requested by this planning checkpoint. Existing evidence and dSYMs remain preserved. Use synthetic fixtures, bounded diagnostics and redacted public evidence; do not post credentials, personal paths or raw private reports.
