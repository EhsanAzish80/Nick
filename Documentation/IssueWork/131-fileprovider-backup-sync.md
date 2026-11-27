# Issue #131: Investigate encrypted-backup sync renames

Related issue: [#131](https://github.com/EhsanAzish80/Nick/issues/131)

## Current status

Draft work plan only. No runtime implementation, reproduction, fix or test pass is claimed by this commit. The original issue remains open. Base checkpoint: `171d1a8b3aea0c59628cae5817bc95d98c4b3951`.

## Problem and scope

[False positive]: File Provider sync of WhatsApp encrypted backup triggers ransomware alert

Trace File Provider staging-to-WhatsApp-backup propagation, preserving distinctions between moving an existing encrypted resource and encrypting unrelated user files.

## Initial code review targets

These are investigation entry points, not established causes:

- `Shared/RansomwareNotePolicy.swift`
- `NickTests/RansomwareAtomicRenameTests.swift`

## Scope boundaries

No blanket exemption for .enc files, iCloud containers or platform processes. Preserve canary and independent ransomware evidence.

This PR owns only issue #131. Keep implementation, tests and validation evidence in this branch. If shared code needs an earlier sibling change, document that dependency and rebase explicitly rather than bundling other issues into this PR.

## Acceptance and validation

The issue remains the source of the full report and acceptance criteria. Initial checklist:

- [ ] Reproduce this File Provider staging-to-container rename pattern with synthetic paths and harmless data.
- [ ] Validated routine propagation does not raise a ransomware alert solely because the destination is an encrypted backup with `.enc` extension.
- [ ] No broad exemption for `.enc`, WhatsApp, iCloud containers or Apple-signed processes.
- [ ] Unvalidated/spoofed staging actors, unrelated user-file encryption and independent canary/strong ransomware evidence remain protected.
- [ ] Xcode positive and negative regressions pass, followed by targeted installed sync validation.

- [ ] Record the confirmed cause and resulting implementation in this document.
- [ ] Run relevant Xcode tests when implementation exists; do not label the planning commit as a tested fix.
- [ ] Review protection and detection impact, including negative cases where applicable.
- [ ] Keep this PR draft until the issue-specific evidence is complete.

No merge, release or additional live workload is requested by this planning checkpoint. Existing evidence and dSYMs remain preserved. Use synthetic fixtures, bounded diagnostics and redacted public evidence; do not post credentials, personal paths or raw private reports.
