# Issue #132: Scope MobileAsset staging finalization

Related issue: [#132](https://github.com/EhsanAzish80/Nick/issues/132)

## Current status

Draft work plan only. No runtime implementation, reproduction, fix or test pass is claimed by this commit. The original issue remains open. Base checkpoint: `171d1a8b3aea0c59628cae5817bc95d98c4b3951`.

## Problem and scope

[False positive]: MobileAsset staging finalization triggers ransomware rename alert

Reproduce the reported host AssetsV2 staging-to-resource shape, including file/directory type and validated actor evidence.

## Initial code review targets

These are investigation entry points, not established causes:

- `Shared/RansomwareNotePolicy.swift`
- `NickTests/RansomwareAtomicRenameTests.swift`

## Scope boundaries

No broad MobileAsset, Apple-platform or AssetsV2 exemption. Unrelated user-file mutations remain protected.

This PR owns only issue #132. Keep implementation, tests and validation evidence in this branch. If shared code needs an earlier sibling change, document that dependency and rebase explicitly rather than bundling other issues into this PR.

## Acceptance and validation

The issue remains the source of the full report and acceptance criteria. Initial checklist:

- [ ] Reproduce the exact staging-to-destination shape with harmless synthetic fixtures.
- [ ] Validate actor identity and narrow source/destination relationships; routine finalization alone should not produce ransomware evidence.
- [ ] No broad process, extension or directory exemption.
- [ ] Unvalidated actors, unrelated user-file encryption, malicious write-then-swap and independent canary evidence remain protected.
- [ ] Xcode positive/negative regression tests and targeted installed validation pass.

- [ ] Record the confirmed cause and resulting implementation in this document.
- [ ] Run relevant Xcode tests when implementation exists; do not label the planning commit as a tested fix.
- [ ] Review protection and detection impact, including negative cases where applicable.
- [ ] Keep this PR draft until the issue-specific evidence is complete.

No merge, release or additional live workload is requested by this planning checkpoint. Existing evidence and dSYMs remain preserved. Use synthetic fixtures, bounded diagnostics and redacted public evidence; do not post credentials, personal paths or raw private reports.
