# Issue #134: Correct temporary-payload evidence for workspace diffs

Related issue: [#134](https://github.com/EhsanAzish80/Nick/issues/134)

## Current status

Draft work plan only. No runtime implementation, reproduction, fix or test pass is claimed by this commit. The original issue remains open. Base checkpoint: `171d1a8b3aea0c59628cae5817bc95d98c4b3951`.

## Problem and scope

[False positive]: Codex workspace diff misclassified as executing a temporary payload

Separate benign temporary output/index creation from concrete execution or sourcing of a generated temporary payload.

## Initial code review targets

These are investigation entry points, not established causes:

- `Nick/Core/ProcessMonitor/LOLBinDetector.swift`
- `Shared/LOLBinExecutionPolicy.swift`
- `NickTests/LOLBinExecutionPolicyTests.swift`

## Scope boundaries

Do not exempt Codex, bash, mktemp or ordinary shell syntax wholesale. Keep titles and correlation consistent with demonstrated execution evidence.

This PR owns only issue #134. Keep implementation, tests and validation evidence in this branch. If shared code needs an earlier sibling change, document that dependency and rebase explicitly rather than bundling other issues into this PR.

## Acceptance and validation

The issue remains the source of the full report and acceptance criteria. Initial checklist:

- [ ] Benign temporary output, error files and temporary Git index/object directories do not trigger `mktemp_execute` solely from ordinary shell syntax.
- [ ] Test the minimal command-substitution case and a sanitized multi-function workspace-diff script.
- [ ] Real execution or interpreter sourcing of a generated temporary payload remains detected when supported by concrete command evidence.
- [ ] Do not exempt Codex, bash, Apple-signed utilities or every command using mktemp.
- [ ] Alert title/explanation match the evidence actually available, and aggregation does not imply execution from temp creation alone.
- [ ] Xcode positive/negative detector regressions and targeted installed validation pass.

- [ ] Record the confirmed cause and resulting implementation in this document.
- [ ] Run relevant Xcode tests when implementation exists; do not label the planning commit as a tested fix.
- [ ] Review protection and detection impact, including negative cases where applicable.
- [ ] Keep this PR draft until the issue-specific evidence is complete.

No merge, release or additional live workload is requested by this planning checkpoint. Existing evidence and dSYMs remain preserved. Use synthetic fixtures, bounded diagnostics and redacted public evidence; do not post credentials, personal paths or raw private reports.
