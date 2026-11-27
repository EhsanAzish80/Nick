# Issue #128: Scope live canaries versus backup copies

Related issue: [#128](https://github.com/EhsanAzish80/Nick/issues/128)

## Current status

Focused rename-source implementation validated in Xcode; CI and an installed candidate check remain pending. No installed fix is claimed. The original issue remains open. Base checkpoint: `171d1a8b3aea0c59628cae5817bc95d98c4b3951`.

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
- [x] No broad exemption for `backupd`, Apple-signed processes or all `/Volumes` paths is introduced.
- [x] Additional ransomware evidence in a backup-related event is still evaluated independently of copied-canary classification.
- [ ] Positive and negative regression tests pass in Xcode, followed by a targeted installed-build Time Machine check.
- [x] The eventual fix PR records its detection/protection impact and validation evidence.

- [x] Record the confirmed cause and resulting implementation in this document.
- [x] Run relevant Xcode tests when implementation exists; do not label the planning commit as a tested fix.
- [x] Review protection and detection impact, including negative cases where applicable.
- [ ] Keep this PR draft until the issue-specific evidence is complete.

No merge, release or additional live workload is requested by this planning checkpoint. Existing evidence and dSYMs remain preserved. Use synthetic fixtures, bounded diagnostics and redacted public evidence; do not post credentials, personal paths or raw private reports.

## Confirmed classification gap

The reported Time Machine rename moved a canary-named copy between two backup snapshots. `evaluateRename` called `CanaryFileManager.isCanary`, whose fallback recognized a managed filename anywhere, even outside every deployed home location. The same backup copy could therefore contribute the live-canary indicator despite never touching a deployed canary.

## Prepared scope

Rename-source classification now uses registered canary paths or a managed name directly in an actual protected home directory. The directory set, including resolved symlink aliases, is computed once during startup from the same homes and folders used for deployment, before ES clients start; it does not infer trust from a process, signing identity, volume name or a Time Machine-looking path. Startup/legacy adoption remains covered even before the registration set is populated. The real live source still matches when its destination is outside the protected directory.

This is limited to the rename canary indicator. Existing content/write canary checks, known ransomware extensions, burst analysis, confidence and response policy are unchanged. No filesystem or Security-framework calls were added to the event callback.

## Prepared regressions

- Backup `.previous` and `.inprogress` snapshot sources do not qualify merely by filename.
- Live registered sources and startup/legacy names in exact protected directories still qualify.
- Other users, nested/sibling directories and unrelated names do not qualify through the fallback.
- Registered sources and real protected homes on external/network volumes still qualify; there is no blanket `/Volumes` exclusion.
- Lexical normalization preserves the directory boundary without filesystem queries.

Five focused regressions in `RansomwareNotePolicyTests` cover the source boundary and a real disposable symlink fixture. The final Xcode UI full run `Test-Nick-2026.11.27_13-07-05-+0300.xcresult` passed all 1,104 tests, zero failures/skips. It still reports 13 existing main-thread warnings (#51), which this change does not claim to resolve. The earlier run was deliberately stopped when alias coverage was added and is not counted as a pass. Shipping-component CI and installed Time Machine validation remain pending. Do not count policy fixtures as proof of an installed backup run.
