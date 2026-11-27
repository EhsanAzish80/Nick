# Issue #137: Investigate SSH signing and agent alert noise

Related issue: [#137](https://github.com/EhsanAzish80/Nick/issues/137)

## Current status

Draft work plan only. No runtime implementation, reproduction, fix or test pass is claimed by this commit. The original issue remains open. Base checkpoint: `171d1a8b3aea0c59628cae5817bc95d98c4b3951`.

## Problem and scope

[False positive]: Normal Git signing and ssh-add key access fall through to orange credential review

Identify why the exact owned-key Git-signing and ssh-add recognition policies fell through to generic review on the installed build.

## Initial code review targets

These are investigation entry points, not established causes:

- `Shared/LOLBinExecutionPolicy.swift`
- `NickExtension/EventHandler.swift`
- `NickTests/CredentialAccessPolicyTests.swift`
- `NickTests/ProcessTreeBoundsTests.swift`

## Scope boundaries

Do not infer internal argument loss from exported empty argv. Preserve validation, ownership, PID-instance matching and conservative ambiguous-evidence fallback.

This PR owns only issue #137. Keep implementation, tests and validation evidence in this branch. If shared code needs an earlier sibling change, document that dependency and rebase explicitly rather than bundling other issues into this PR.

## Acceptance and validation

The issue remains the source of the full report and acceptance criteria. Initial checklist:

- [ ] Reproduce using disposable synthetic keys only; no real private-key contents in fixtures or diagnostics.
- [ ] Explain which required recognition condition failed for each case with bounded, non-secret diagnostics.
- [ ] Validated exact owned-key Git signing and agent-add workflows reach their intended observed/silent classification.
- [ ] Cover short-lived actors, cold process-tree/cache state, delayed observation and missing argument evidence.
- [ ] Preserve review/protection for spoofed identities, wrong ownership, unsupported commands, unrelated key readers and ambiguous evidence; no broad git, ssh-keygen, ssh-add or coding-app exemption.
- [ ] Positive/negative Xcode regressions and a targeted installed check demonstrate the eventual fix.
- [ ] Keep this separate from historical memory/deadline causality in #122 and unrelated own-container access in #129.

- [ ] Record the confirmed cause and resulting implementation in this document.
- [ ] Run relevant Xcode tests when implementation exists; do not label the planning commit as a tested fix.
- [ ] Review protection and detection impact, including negative cases where applicable.
- [ ] Keep this PR draft until the issue-specific evidence is complete.

No merge, release or additional live workload is requested by this planning checkpoint. Existing evidence and dSYMs remain preserved. Use synthetic fixtures, bounded diagnostics and redacted public evidence; do not post credentials, personal paths or raw private reports.
