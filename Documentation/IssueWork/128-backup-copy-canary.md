# Issue #128: Scope live canaries versus backup copies

Related issue: [#128](https://github.com/EhsanAzish80/Nick/issues/128)

## Current status

Draft work plan only. No runtime implementation, reproduction, fix or test pass is claimed by this commit. The original issue remains open. Base checkpoint: `171d1a8b3aea0c59628cae5817bc95d98c4b3951`.

## Problem and scope

[False positive]: Time Machine backup-copy canary rename triggers ransomware alert

Distinguish a registered live canary from a same-name copy moved between Time Machine backup trees. Preserve independent ransomware evidence.

## Initial code review targets

These are investigation entry points, not established causes:

- `NickExtension/Ransomware/RansomwareDetector.swift`

## Scope boundaries

Do not exempt backupd, Apple-signed processes or all mounted volumes. Keep this separate from #122.

This PR owns only issue #128. Keep implementation, tests and validation evidence in this branch. If shared code needs an earlier sibling change, document that dependency and rebase explicitly rather than bundling other issues into this PR.

## Acceptance and validation

The issue remains the source of the full report and acceptance criteria. Initial checklist:

- [ ] A synthetic Time Machine backup-copy rename matching this report does not produce a ransomware alert solely from the copied canary name.
- [ ] Changes to a live deployed canary, including moving it away from its original location, remain detected.
- [ ] No broad exemption for `backupd`, Apple-signed processes or all `/Volumes` paths is introduced.
- [ ] Additional ransomware evidence in a backup-related event is still evaluated independently of copied-canary classification.
- [ ] Positive and negative regression tests pass in Xcode, followed by a targeted installed-build Time Machine check.
- [ ] The eventual fix PR records its detection/protection impact and validation evidence.

- [ ] Record the confirmed cause and resulting implementation in this document.
- [ ] Run relevant Xcode tests when implementation exists; do not label the planning commit as a tested fix.
- [ ] Review protection and detection impact, including negative cases where applicable.
- [ ] Keep this PR draft until the issue-specific evidence is complete.

No merge, release or additional live workload is requested by this planning checkpoint. Existing evidence and dSYMs remain preserved. Use synthetic fixtures, bounded diagnostics and redacted public evidence; do not post credentials, personal paths or raw private reports.
